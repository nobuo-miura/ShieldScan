// ShieldScan のバックエンドサーバーエントリーポイント。
// セキュリティスキャン用の各種APIエンドポイントを提供します。
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/nobuo-miura/shieldscan/internal/handlers"
)

const (
	// defaultPort はリッスンポートの既定値です。PORT 環境変数で上書きできます。
	defaultPort = "8080"

	// readHeaderTimeout はリクエストヘッダー読み取りのタイムアウトです。
	// 未設定だと Slowloris 攻撃で接続を占有され続けます。
	readHeaderTimeout = 10 * time.Second

	// writeTimeout はスキャン処理（外部への接続を含む）が完了するまでの猶予です。
	// 内部のスキャンタイムアウト（10秒）に余裕を持たせた値にしています。
	writeTimeout = 60 * time.Second

	// idleTimeout はKeep-Alive接続を維持する時間です。
	idleTimeout = 120 * time.Second
)

// main はHTTPサーバーを起動します。
//
// 登録するエンドポイント:
//   - POST /api/analyze  — セキュリティヘッダーの総合スキャン
//   - GET  /api/history  — 過去のスキャン結果一覧
//   - POST /api/cors     — CORSミスコンフィグ診断
//   - POST /api/jwt      — JWTトークンの静的解析
//   - POST /api/ssl      — TLS/SSL証明書チェック
//   - POST /api/cookies  — Cookieセキュリティ監査
//   - GET  /health       — ヘルスチェック（ロードバランサー向け）
func main() {
	mux := http.NewServeMux()

	wrap := func(h http.HandlerFunc) http.HandlerFunc {
		return handlers.CORSMiddleware(handlers.RateLimitMiddleware(h))
	}

	mux.HandleFunc("/api/analyze", wrap(handlers.AnalyzeHandler))
	mux.HandleFunc("/api/history", wrap(handlers.HistoryHandler))
	mux.HandleFunc("/api/cors", wrap(handlers.CORSHandler))
	mux.HandleFunc("/api/jwt", wrap(handlers.JWTHandler))
	mux.HandleFunc("/api/ssl", wrap(handlers.SSLHandler))
	mux.HandleFunc("/api/cookies", wrap(handlers.CookieHandler))
	mux.HandleFunc("/health", healthHandler)

	port := listenPort()

	srv := &http.Server{
		Addr:              ":" + strconv.Itoa(port),
		Handler:           mux,
		ReadHeaderTimeout: readHeaderTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
	}

	log.Printf("ShieldScan server starting on :%d", port)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

// listenPort は PORT 環境変数を読み取り、リッスンするポート番号を返します。
// 未設定・数値でない・範囲外の場合は起動を中断します。
// 設定ミスに気づかないまま既定ポートで動き続けるより、その場で落ちる方が安全です。
func listenPort() int {
	raw := os.Getenv("PORT")
	if raw == "" {
		raw = defaultPort
	}
	port, err := strconv.Atoi(raw)
	if err != nil || port < 1 || port > 65535 {
		log.Fatalf("PORT is not a valid port number (1-65535)")
	}
	return port
}

// healthHandler はロードバランサー・Dockerヘルスチェック向けの応答を返します。
func healthHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{"status": "ok"}); err != nil {
		log.Printf("health check response failed: %v", err)
	}
}
