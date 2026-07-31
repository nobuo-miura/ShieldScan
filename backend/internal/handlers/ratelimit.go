package handlers

import (
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	rateLimitRequests = 30          // ウィンドウ内の最大リクエスト数
	rateLimitWindow   = time.Minute // ウィンドウ幅

	// sweepInterval は期限切れエントリを掃除する間隔です。
	// これがないと ipMap はユニークIPの数だけ無限に増え続けます。
	sweepInterval = 5 * time.Minute

	// trustProxyEnv は X-Forwarded-For を信頼するかを指定する環境変数名です。
	// リバースプロキシ配下で動かす場合のみ true にしてください。
	trustProxyEnv = "SHIELDSCAN_TRUST_PROXY"
)

// ipRecord は1つのIPアドレスのリクエスト履歴を保持します。
type ipRecord struct {
	mu         sync.Mutex
	timestamps []time.Time
}

// prune は cutoff より古いタイムスタンプを捨て、残った件数を返します。
// 呼び出し側で mu を保持していること。
func (rec *ipRecord) prune(cutoff time.Time) int {
	valid := rec.timestamps[:0]
	for _, t := range rec.timestamps {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}
	rec.timestamps = valid
	return len(valid)
}

var (
	ipMap sync.Map // map[string]*ipRecord

	// trustProxy はプロセス起動時に一度だけ評価されます。
	trustProxy = parseBoolEnv(trustProxyEnv)

	sweepOnce sync.Once
)

// parseBoolEnv は環境変数を bool として読み、未設定や不正値なら false を返します。
func parseBoolEnv(name string) bool {
	v, err := strconv.ParseBool(os.Getenv(name))
	return err == nil && v
}

// RateLimitMiddleware はIPアドレスごとに1分間30リクエストまでに制限するミドルウェアです。
// 制限を超えた場合は 429 Too Many Requests を返します。
//
// 初回呼び出し時に、期限切れエントリを定期的に削除するバックグラウンド
// ゴルーチンを起動します。
func RateLimitMiddleware(next http.HandlerFunc) http.HandlerFunc {
	sweepOnce.Do(func() { go sweepLoop() })

	return func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)

		val, _ := ipMap.LoadOrStore(ip, &ipRecord{})
		record := val.(*ipRecord)

		record.mu.Lock()
		now := time.Now()
		count := record.prune(now.Add(-rateLimitWindow))

		if count >= rateLimitRequests {
			record.mu.Unlock()
			w.Header().Set("Retry-After", strconv.Itoa(int(rateLimitWindow.Seconds())))
			writeError(w, http.StatusTooManyRequests, "rate limit exceeded, please try again later")
			return
		}

		record.timestamps = append(record.timestamps, now)
		record.mu.Unlock()

		next(w, r)
	}
}

// sweepLoop は sweepInterval ごとに ipMap を走査し、
// ウィンドウ外のエントリを削除してメモリの増加を防ぎます。
func sweepLoop() {
	ticker := time.NewTicker(sweepInterval)
	defer ticker.Stop()
	for range ticker.C {
		sweep(time.Now().Add(-rateLimitWindow))
	}
}

// sweep は cutoff より新しいタイムスタンプを持たないエントリを ipMap から削除します。
// テストから直接呼べるよう sweepLoop とは分離しています。
func sweep(cutoff time.Time) {
	ipMap.Range(func(key, val any) bool {
		record := val.(*ipRecord)
		record.mu.Lock()
		remaining := record.prune(cutoff)
		record.mu.Unlock()
		if remaining == 0 {
			ipMap.Delete(key)
		}
		return true
	})
}

// clientIP はリクエストからクライアントIPアドレスを取得します。
//
// 既定では TCP 接続元 (RemoteAddr) を使います。X-Forwarded-For は
// クライアントが自由に詐称できるヘッダーであり、無条件に信頼すると
// 1リクエストごとに別のIPを名乗るだけでレート制限を回避できてしまうためです。
//
// リバースプロキシ配下で動かす場合のみ SHIELDSCAN_TRUST_PROXY=true を
// 設定してください。その場合は X-Forwarded-For の先頭の値を採用します。
func clientIP(r *http.Request) string {
	if trustProxy {
		if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
			first, _, _ := strings.Cut(forwarded, ",")
			if first = strings.TrimSpace(first); first != "" {
				return first
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
