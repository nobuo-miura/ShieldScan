package handlers

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	rateLimitRequests = 30          // ウィンドウ内の最大リクエスト数
	rateLimitWindow   = time.Minute // ウィンドウ幅
)

// ipRecord は1つのIPアドレスのリクエスト履歴を保持します。
type ipRecord struct {
	mu         sync.Mutex
	timestamps []time.Time
}

var (
	ipMap sync.Map // map[string]*ipRecord
)

// RateLimitMiddleware はIPアドレスごとに1分間30リクエストまでに制限するミドルウェアです。
// 制限を超えた場合は 429 Too Many Requests を返します。
func RateLimitMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)

		val, _ := ipMap.LoadOrStore(ip, &ipRecord{})
		record := val.(*ipRecord)

		record.mu.Lock()
		now := time.Now()
		cutoff := now.Add(-rateLimitWindow)

		// ウィンドウ外の古いタイムスタンプを削除
		valid := record.timestamps[:0]
		for _, t := range record.timestamps {
			if t.After(cutoff) {
				valid = append(valid, t)
			}
		}
		record.timestamps = valid

		if len(record.timestamps) >= rateLimitRequests {
			record.mu.Unlock()
			writeError(w, http.StatusTooManyRequests, "rate limit exceeded, please try again later")
			return
		}

		record.timestamps = append(record.timestamps, now)
		record.mu.Unlock()

		next(w, r)
	}
}

// clientIP はリクエストからクライアントIPアドレスを取得します。
// X-Forwarded-For ヘッダーが存在する場合はその先頭のIPを使用します。
func clientIP(r *http.Request) string {
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		if idx := strings.Index(forwarded, ","); idx != -1 {
			return strings.TrimSpace(forwarded[:idx])
		}
		return strings.TrimSpace(forwarded)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
