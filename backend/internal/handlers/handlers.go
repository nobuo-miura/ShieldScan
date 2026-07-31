// Package handlers はShieldScan APIの各HTTPハンドラーとミドルウェアを提供します。
package handlers

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/nobuo-miura/shieldscan/internal/analyzer"
	"github.com/nobuo-miura/shieldscan/internal/models"
	"github.com/nobuo-miura/shieldscan/internal/safehttp"
)

// CORSMiddleware はすべてのAPIリクエストにCORSヘッダーを付与するミドルウェアです。
// フロントエンド（異なるオリジン）からのリクエストを許可し、
// OPTIONSプリフライトリクエストには 204 No Content を返して処理を終了します。
func CORSMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next(w, r)
	}
}

// writeJSON はレスポンスボディをJSONエンコードして書き込むヘルパーです。
//
// エンコードに失敗してもヘッダーは送出済みでステータスを変更できないため、
// ログに残すだけにとどめます（多くはクライアント切断が原因）。
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("failed to encode response: %v", err)
	}
}

// writeError は {"error": msg} 形式のJSONエラーレスポンスを返すヘルパーです。
func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// parseURL はリクエストボディからURLを取得し、正規化・検証して返します。
// スキームが省略されている場合は https:// を自動付与します。
// 不正なURLの場合はエラーを返します。
func parseURL(r *http.Request) (string, error) {
	var body struct {
		URL string `json:"url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		return "", err
	}
	rawURL := strings.TrimSpace(body.URL)
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		rawURL = "https://" + rawURL
	}
	parsed, err := url.ParseRequestURI(rawURL)
	if err != nil {
		return "", err
	}
	// ホストなしのURLでも err は nil になりうるので個別に弾く。
	// ここで err をそのまま返すと nil エラーで空URLが通ってしまう。
	if parsed.Host == "" {
		return "", errors.New("URL has no host")
	}
	return rawURL, nil
}

// AnalyzeHandler は指定URLのセキュリティヘッダーを総合的にスキャンします。
//
// POST /api/analyze
//
// リクエストボディ: {"url": "https://example.com"}
// レスポンス: [analyzer.AnalysisResult] (JSON)
//
// スキャン結果は自動的にスキャン履歴に保存されます。
func AnalyzeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	rawURL, err := parseURL(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid URL")
		return
	}
	if err := safehttp.ValidateURL(r.Context(), rawURL); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	result, err := analyzer.Analyze(r.Context(), rawURL)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	models.Store.Add(result)
	writeJSON(w, http.StatusOK, result)
}

// HistoryHandler は過去のスキャン結果の一覧を返します。
//
// GET /api/history
//
// レスポンス: [models.HistoryEntry] の配列 (JSON)。最新50件を新しい順で返します。
// 各エントリーの詳細フィールド (result) は含まれません。
func HistoryHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "GET only")
		return
	}
	writeJSON(w, http.StatusOK, models.Store.List())
}

// CORSHandler は指定URLに対してCORSミスコンフィグ診断を実行します。
//
// POST /api/cors
//
// リクエストボディ: {"url": "https://example.com"}
// レスポンス: [analyzer.CORSResult] (JSON)
//
// 任意オリジン反射・Nullオリジン・ドメイン前後一致などの脆弱パターンをテストします。
func CORSHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	rawURL, err := parseURL(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid URL")
		return
	}
	if err := safehttp.ValidateURL(r.Context(), rawURL); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	result, err := analyzer.ScanCORS(r.Context(), rawURL)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// JWTHandler はJWTトークンを静的解析し、セキュリティ上の問題を報告します。
//
// POST /api/jwt
//
// リクエストボディ: {"token": "<JWT文字列>"}
// レスポンス: [analyzer.JWTResult] (JSON)
//
// alg:none・kid インジェクション・有効期限・機密情報の混入などをチェックします。
func JWTHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	var body struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.Token) == "" {
		writeError(w, http.StatusBadRequest, "token is required")
		return
	}
	result, err := analyzer.AnalyzeJWT(strings.TrimSpace(body.Token))
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// SSLHandler は指定ホストのTLS/SSL設定を診断します。
//
// POST /api/ssl
//
// リクエストボディ: {"host": "example.com", "port": "443"}
// port は省略可能で、省略時は "443" を使用します。
// レスポンス: [analyzer.SSLResult] (JSON)
//
// TLSバージョン・証明書有効期限・暗号スイート・ホスト名一致などを検査します。
func SSLHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	var body struct {
		Host string `json:"host"`
		Port string `json:"port"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.Host) == "" {
		writeError(w, http.StatusBadRequest, "host is required")
		return
	}
	host := strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(body.Host), "https://"), "http://")
	if idx := strings.Index(host, "/"); idx != -1 {
		host = host[:idx]
	}
	if err := safehttp.ValidateHost(r.Context(), host); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	result, err := analyzer.CheckSSL(r.Context(), host, body.Port)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// CookieHandler は指定URLのCookieセキュリティを監査します。
//
// POST /api/cookies
//
// リクエストボディ: {"url": "https://example.com"}
// レスポンス: [analyzer.CookieAuditResult] (JSON)
//
// Secure・HttpOnly・SameSite フラグの有無、機密Cookieの識別などをチェックします。
func CookieHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	rawURL, err := parseURL(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid URL")
		return
	}
	if err := safehttp.ValidateURL(r.Context(), rawURL); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	result, err := analyzer.AuditCookies(r.Context(), rawURL)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}
