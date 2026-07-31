package handlers

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// okHandler は呼ばれた回数を数える最小のハンドラーを返します。
func okHandler(calls *int) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		*calls++
		w.WriteHeader(http.StatusOK)
	}
}

func TestRateLimitBlocksAfterLimit(t *testing.T) {
	t.Cleanup(func() { ipMap.Delete("203.0.113.10") })

	calls := 0
	h := RateLimitMiddleware(okHandler(&calls))

	// 上限ちょうどまでは通る
	for i := range rateLimitRequests {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/history", nil)
		req.RemoteAddr = "203.0.113.10:12345"
		h(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%d 回目で status = %d, want 200", i+1, rec.Code)
		}
	}

	// 1回超過すると 429
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/history", nil)
	req.RemoteAddr = "203.0.113.10:12345"
	h(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("超過時の status = %d, want 429", rec.Code)
	}
	if got := rec.Header().Get("Retry-After"); got == "" {
		t.Error("Retry-After ヘッダーが設定されていません")
	}
	if calls != rateLimitRequests {
		t.Errorf("ハンドラー呼び出し回数 = %d, want %d", calls, rateLimitRequests)
	}
}

// TestRateLimitIsPerIP は、あるIPが上限に達しても別のIPは影響を受けないことを確認します。
func TestRateLimitIsPerIP(t *testing.T) {
	t.Cleanup(func() {
		ipMap.Delete("203.0.113.20")
		ipMap.Delete("203.0.113.21")
	})

	calls := 0
	h := RateLimitMiddleware(okHandler(&calls))

	for range rateLimitRequests + 1 {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/history", nil)
		req.RemoteAddr = "203.0.113.20:1000"
		h(rec, req)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/history", nil)
	req.RemoteAddr = "203.0.113.21:1000"
	h(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("別IPの status = %d, want 200", rec.Code)
	}
}

// TestXForwardedForIgnoredByDefault は、X-Forwarded-For を詐称しても
// レート制限を回避できないことを確認します。既定でこのヘッダーを信頼すると、
// リクエストごとに別のIPを名乗るだけで制限が無効化されてしまいます。
func TestXForwardedForIgnoredByDefault(t *testing.T) {
	if trustProxy {
		t.Skip("SHIELDSCAN_TRUST_PROXY が有効な環境ではスキップ")
	}
	t.Cleanup(func() { ipMap.Delete("203.0.113.30") })

	calls := 0
	h := RateLimitMiddleware(okHandler(&calls))

	// 毎回異なる X-Forwarded-For を名乗るが、接続元は同一
	blocked := false
	for i := range rateLimitRequests + 5 {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/history", nil)
		req.RemoteAddr = "203.0.113.30:1000"
		req.Header.Set("X-Forwarded-For", fmt.Sprintf("198.51.100.%d", i))
		h(rec, req)
		if rec.Code == http.StatusTooManyRequests {
			blocked = true
			break
		}
	}

	if !blocked {
		t.Error("X-Forwarded-For の詐称でレート制限を回避できてしまいました")
	}
}

func TestClientIPUsesXForwardedForWhenTrusted(t *testing.T) {
	original := trustProxy
	trustProxy = true
	t.Cleanup(func() { trustProxy = original })

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:5000"
	req.Header.Set("X-Forwarded-For", "203.0.113.40, 10.0.0.1")

	if got := clientIP(req); got != "203.0.113.40" {
		t.Errorf("clientIP = %q, want %q", got, "203.0.113.40")
	}
}

// TestTrustedProxyTakesFirstEntry は、信頼モードで X-Forwarded-For の
// 「先頭」の値が採用されることを固定します。
//
// これは nginx.conf 側の設定と対になっています。nginx は
//
//	proxy_set_header X-Forwarded-For $remote_addr;   // 上書き
//
// でなければならず、よくある
//
//	proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;  // 追記
//
// に変えると、クライアントが送った偽の値が先頭に残り、この関数がそれを
// 採用してしまってレート制限を回避されます。nginx 側を変更する場合は
// このテストの前提が崩れていないか必ず確認してください。
func TestTrustedProxyTakesFirstEntry(t *testing.T) {
	original := trustProxy
	trustProxy = true
	t.Cleanup(func() { trustProxy = original })

	// 攻撃者が偽の X-Forwarded-For を送り、プロキシがそれに追記した場合の形
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:5000"
	req.Header.Set("X-Forwarded-For", "198.51.100.99, 203.0.113.40")

	if got := clientIP(req); got != "198.51.100.99" {
		t.Fatalf("clientIP = %q — 先頭の値を採用する前提が変わっています。"+
			"nginx が X-Forwarded-For を上書きしているか確認してください", got)
	}
}

func TestClientIPFallsBackToRemoteAddr(t *testing.T) {
	original := trustProxy
	trustProxy = true
	t.Cleanup(func() { trustProxy = original })

	// 空の X-Forwarded-For は無視して RemoteAddr を使う
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.50:5000"
	req.Header.Set("X-Forwarded-For", "   ")

	if got := clientIP(req); got != "203.0.113.50" {
		t.Errorf("clientIP = %q, want %q", got, "203.0.113.50")
	}
}

// TestSweepRemovesExpiredEntries は、ウィンドウを過ぎたIPエントリが
// 削除されメモリが解放されることを確認します。
// これがないと ipMap はユニークIPの数だけ無限に成長します。
func TestSweepRemovesExpiredEntries(t *testing.T) {
	const ip = "203.0.113.60"
	ipMap.Store(ip, &ipRecord{timestamps: []time.Time{time.Now().Add(-2 * rateLimitWindow)}})

	sweep(time.Now().Add(-rateLimitWindow))

	if _, ok := ipMap.Load(ip); ok {
		t.Error("期限切れエントリが削除されていません")
	}
}

// TestSweepKeepsActiveEntries は、まだ有効なエントリを誤って消さないことを確認します。
func TestSweepKeepsActiveEntries(t *testing.T) {
	const ip = "203.0.113.61"
	ipMap.Store(ip, &ipRecord{timestamps: []time.Time{time.Now()}})
	t.Cleanup(func() { ipMap.Delete(ip) })

	sweep(time.Now().Add(-rateLimitWindow))

	if _, ok := ipMap.Load(ip); !ok {
		t.Error("有効なエントリまで削除されました")
	}
}
