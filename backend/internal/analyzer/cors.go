// このファイルはCORSミスコンフィグレーションの診断機能を提供します。
// 実際にHTTPリクエストを送信して、サーバーがどのオリジンを許可するかを検証します。
package analyzer

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/nobuo-miura/shieldscan/internal/msg"
	"github.com/nobuo-miura/shieldscan/internal/safehttp"
)

// CORSTestResult は1つのCORSテストケースの結果を表します。
//
// Reflected が true かつ ACACPresent が true の場合、
// クロスオリジンリクエストで認証情報が漏洩する危険があります。
type CORSTestResult struct {
	TestName    msg.Message  `json:"test_name"`
	Origin      string       `json:"origin"`
	Reflected   bool         `json:"reflected"`    // テスト用オリジンがACAOヘッダーに反射されたか
	ACACPresent bool         `json:"acac_present"` // Access-Control-Allow-Credentials: true か
	Severity    string       `json:"severity"`     // "critical", "high", "info"
	Description msg.Message  `json:"description"`
	Detail      *msg.Message `json:"detail,omitempty"`
}

// CORSResult はCORSミスコンフィグ診断の総合結果を表します。
//
// Vulnerable は「オリジンが反射され、かつ認証情報送信が許可されている」場合に true になります。
type CORSResult struct {
	URL          string           `json:"url"`
	ScannedAt    time.Time        `json:"scanned_at"`
	Vulnerable   bool             `json:"vulnerable"`
	Tests        []CORSTestResult `json:"tests"`
	ResponseTime int64            `json:"response_time_ms"`
}

// ScanCORS は指定URLに対して複数のCORSテストを実行し、脆弱なCORS設定を検出します。
//
// 以下の4パターンをテストします:
//   - 任意オリジン反射: 攻撃者ドメインがACAOに反射されるか
//   - Nullオリジンバイパス: "null"オリジンが許可されるか
//   - プレドメインマッチ: "evil-{ターゲットホスト}" が許可されるか（前方一致の検出）
//   - ポストドメインマッチ: "{ターゲットホスト}.evil.com" が許可されるか（後方一致の検出）
func ScanCORS(ctx context.Context, rawURL string) (*CORSResult, error) {
	start := time.Now()

	type testCase struct {
		nameKey  string
		origin   string
		severity string
		descKey  string
	}

	host := extractHost(rawURL)
	tests := []testCase{
		{
			nameKey:  msg.CORSTestOriginReflectionName,
			origin:   "https://evil-attacker.com",
			severity: "critical",
			descKey:  msg.CORSTestOriginReflectionDesc,
		},
		{
			nameKey:  msg.CORSTestNullOriginName,
			origin:   "null",
			severity: "high",
			descKey:  msg.CORSTestNullOriginDesc,
		},
		{
			nameKey:  msg.CORSTestPreDomainName,
			origin:   fmt.Sprintf("https://evil-%s", host),
			severity: "high",
			descKey:  msg.CORSTestPreDomainDesc,
		},
		{
			nameKey:  msg.CORSTestPostDomainName,
			origin:   fmt.Sprintf("https://%s.evil.com", host),
			severity: "high",
			descKey:  msg.CORSTestPostDomainDesc,
		},
	}

	// リダイレクトを無制限に追跡していた以前の実装は、対象サイトが内部アドレスへ
	// 302 を返すだけで SSRF 保護をすり抜けられた。共通クライアントに寄せて封じる。
	client := safehttp.NewClient(scanTimeout, maxRedirects)
	results := make([]CORSTestResult, 0, len(tests))
	vulnerable := false

	for _, tc := range tests {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Origin", tc.origin)
		req.Header.Set("User-Agent", userAgent)

		resp, err := client.Do(req)
		if err != nil {
			// Go のエラー文字列は翻訳対象外とし、パラメータとしてそのまま埋め込む。
			detail := msg.P(msg.CORSDetailRequestFailed, "error", err.Error())
			results = append(results, CORSTestResult{
				TestName:    msg.M(tc.nameKey),
				Origin:      tc.origin,
				Reflected:   false,
				Severity:    tc.severity,
				Description: msg.M(tc.descKey),
				Detail:      &detail,
			})
			continue
		}
		drainAndClose(resp)

		acao := resp.Header.Get("Access-Control-Allow-Origin")
		acac := strings.ToLower(resp.Header.Get("Access-Control-Allow-Credentials")) == "true"
		reflected := acao == tc.origin || acao == "*"

		if reflected && acac {
			vulnerable = true
		}

		detailKey := msg.CORSDetailACAO
		if acac {
			detailKey = msg.CORSDetailACAOWithACAC
		}
		detail := msg.P(detailKey, "acao", acao)

		results = append(results, CORSTestResult{
			TestName:    msg.M(tc.nameKey),
			Origin:      tc.origin,
			Reflected:   reflected,
			ACACPresent: acac,
			Severity:    tc.severity,
			Description: msg.M(tc.descKey),
			Detail:      &detail,
		})
	}

	return &CORSResult{
		URL:          rawURL,
		ScannedAt:    time.Now(),
		Vulnerable:   vulnerable,
		Tests:        results,
		ResponseTime: time.Since(start).Milliseconds(),
	}, nil
}

// extractHost はURLからホスト名（スキームとパスを除いた部分）を取り出します。
// 例: "https://example.com/path" → "example.com"
func extractHost(rawURL string) string {
	s := strings.TrimPrefix(rawURL, "https://")
	s = strings.TrimPrefix(s, "http://")
	if idx := strings.Index(s, "/"); idx != -1 {
		s = s[:idx]
	}
	return s
}
