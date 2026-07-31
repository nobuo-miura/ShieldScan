package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// postJSON はJSONボディ付きのPOSTリクエストをハンドラーに投げ、結果を返します。
func postJSON(h http.HandlerFunc, path, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	h(rec, req)
	return rec
}

// TestScanHandlersRejectInternalTargets は、内部アドレスを狙ったスキャン要求が
// 実際のリクエストを送る前に 400 で弾かれることを確認します。
// これらのハンドラーはユーザー入力のURLへサーバー側から接続するため、
// SSRF の直接の入口になります。
func TestScanHandlersRejectInternalTargets(t *testing.T) {
	handlers := map[string]http.HandlerFunc{
		"/api/analyze": AnalyzeHandler,
		"/api/cors":    CORSHandler,
		"/api/cookies": CookieHandler,
	}

	targets := []string{
		`{"url":"http://127.0.0.1/"}`,
		`{"url":"http://169.254.169.254/latest/meta-data/"}`,
		`{"url":"http://[::1]/"}`,
		`{"url":"https://10.0.0.1/"}`,
		`{"url":"file:///etc/passwd"}`,
	}

	for path, h := range handlers {
		for _, body := range targets {
			t.Run(path+" "+body, func(t *testing.T) {
				rec := postJSON(h, path, body)
				if rec.Code != http.StatusBadRequest {
					t.Errorf("status = %d, want 400 (body: %s)", rec.Code, rec.Body.String())
				}
			})
		}
	}
}

func TestSSLHandlerRejectsInternalHost(t *testing.T) {
	for _, body := range []string{
		`{"host":"127.0.0.1"}`,
		`{"host":"169.254.169.254"}`,
		`{"host":"https://10.0.0.1/path"}`,
	} {
		rec := postJSON(SSLHandler, "/api/ssl", body)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("body %s: status = %d, want 400", body, rec.Code)
		}
	}
}

func TestHandlersRejectWrongMethod(t *testing.T) {
	post := map[string]http.HandlerFunc{
		"/api/analyze": AnalyzeHandler,
		"/api/cors":    CORSHandler,
		"/api/jwt":     JWTHandler,
		"/api/ssl":     SSLHandler,
		"/api/cookies": CookieHandler,
	}
	for path, h := range post {
		rec := httptest.NewRecorder()
		h(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("GET %s: status = %d, want 405", path, rec.Code)
		}
	}

	rec := httptest.NewRecorder()
	HistoryHandler(rec, httptest.NewRequest(http.MethodPost, "/api/history", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /api/history: status = %d, want 405", rec.Code)
	}
}

func TestJWTHandlerRequiresToken(t *testing.T) {
	for _, body := range []string{`{}`, `{"token":""}`, `{"token":"   "}`, `not json`} {
		rec := postJSON(JWTHandler, "/api/jwt", body)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("body %q: status = %d, want 400", body, rec.Code)
		}
	}
}

// TestJWTHandlerAnalyzesToken は、JWT解析だけは外部通信を伴わないため
// 正常系まで通して確認できます。alg:none のトークンを渡します。
func TestJWTHandlerAnalyzesToken(t *testing.T) {
	// {"alg":"none","typ":"JWT"}.{"sub":"1234567890"}
	const token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0."

	rec := postJSON(JWTHandler, "/api/jwt", `{"token":"`+token+`"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("レスポンスがJSONとして解釈できません: %v", err)
	}
	if _, ok := got["findings"]; !ok {
		t.Errorf("findings フィールドがありません: %v", got)
	}
}

func TestParseURL(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		want    string
		wantErr bool
	}{
		{"スキームなしはhttpsを補う", `{"url":"example.com"}`, "https://example.com", false},
		{"httpはそのまま", `{"url":"http://example.com"}`, "http://example.com", false},
		{"前後の空白を除去", `{"url":"  https://example.com  "}`, "https://example.com", false},
		{"ホストなし", `{"url":"https://"}`, "", true},
		{"空文字", `{"url":""}`, "", true},
		{"不正なJSON", `nope`, "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(tt.body))
			got, err := parseURL(req)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("parseURL = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestParseURLNeverReturnsNilErrorWithEmptyURL は、ホストなしURLで
// nil エラーと空文字列が同時に返る回帰バグを防ぎます。
// 以前の実装では検証をすり抜けた空URLがそのままスキャンに渡っていました。
func TestParseURLNeverReturnsNilErrorWithEmptyURL(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"url":"https://"}`))
	got, err := parseURL(req)
	if err == nil {
		t.Fatalf("parseURL(%q) = %q, nil — エラーを返すべきです", "https://", got)
	}
}

func TestCORSMiddlewarePreflight(t *testing.T) {
	called := false
	h := CORSMiddleware(func(http.ResponseWriter, *http.Request) { called = true })

	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodOptions, "/api/analyze", nil))

	if rec.Code != http.StatusNoContent {
		t.Errorf("status = %d, want 204", rec.Code)
	}
	if called {
		t.Error("プリフライトで後続ハンドラーが呼ばれました")
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("ACAO = %q, want *", got)
	}
}
