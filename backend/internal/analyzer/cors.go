// このファイルはCORSミスコンフィグレーションの診断機能を提供します。
// 実際にHTTPリクエストを送信して、サーバーがどのオリジンを許可するかを検証します。
package analyzer

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

// CORSTestResult は1つのCORSテストケースの結果を表します。
//
// Reflected が true かつ ACACPresent が true の場合、
// クロスオリジンリクエストで認証情報が漏洩する危険があります。
type CORSTestResult struct {
	TestName    string `json:"test_name"`
	Origin      string `json:"origin"`
	Reflected   bool   `json:"reflected"`    // テスト用オリジンがACAOヘッダーに反射されたか
	ACACPresent bool   `json:"acac_present"` // Access-Control-Allow-Credentials: true か
	Severity    string `json:"severity"`     // "critical", "high", "info"
	Description string `json:"description"`
	Detail      string `json:"detail"`
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
func ScanCORS(rawURL string) (*CORSResult, error) {
	start := time.Now()

	type testCase struct {
		name        string
		origin      string
		severity    string
		description string
	}

	host := extractHost(rawURL)
	tests := []testCase{
		{
			name:        "任意オリジン反射",
			origin:      "https://evil-attacker.com",
			severity:    "critical",
			description: "攻撃者のオリジンがACAOヘッダーにそのまま反射される場合、クロスオリジンリクエストで認証情報が盗まれる可能性があります。",
		},
		{
			name:        "Nullオリジンバイパス",
			origin:      "null",
			severity:    "high",
			description: "nullオリジンはsandboxed iframeから送信可能です。nullを信頼する設定は攻撃者に悪用されます。",
		},
		{
			name:        "プレドメインマッチ",
			origin:      fmt.Sprintf("https://evil-%s", host),
			severity:    "high",
			description: "前方一致でオリジン検証している場合、evil-victim.comのような偽ドメインが許可されます。",
		},
		{
			name:        "ポストドメインマッチ",
			origin:      fmt.Sprintf("https://%s.evil.com", host),
			severity:    "high",
			description: "後方一致でオリジン検証している場合、victim.com.evil.comのような偽ドメインが許可されます。",
		},
	}

	client := &http.Client{Timeout: 10 * time.Second}
	results := make([]CORSTestResult, 0, len(tests))
	vulnerable := false

	for _, tc := range tests {
		req, err := http.NewRequest("GET", rawURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Origin", tc.origin)
		req.Header.Set("User-Agent", "ShieldScan/1.0")

		resp, err := client.Do(req)
		if err != nil {
			results = append(results, CORSTestResult{
				TestName:    tc.name,
				Origin:      tc.origin,
				Reflected:   false,
				Severity:    tc.severity,
				Description: tc.description,
				Detail:      "リクエスト失敗: " + err.Error(),
			})
			continue
		}
		resp.Body.Close()

		acao := resp.Header.Get("Access-Control-Allow-Origin")
		acac := strings.ToLower(resp.Header.Get("Access-Control-Allow-Credentials")) == "true"
		reflected := acao == tc.origin || acao == "*"

		if reflected && acac {
			vulnerable = true
		}

		detail := fmt.Sprintf("ACAO: %q", acao)
		if acac {
			detail += "  |  ACAC: true ⚠"
		}

		results = append(results, CORSTestResult{
			TestName:    tc.name,
			Origin:      tc.origin,
			Reflected:   reflected,
			ACACPresent: acac,
			Severity:    tc.severity,
			Description: tc.description,
			Detail:      detail,
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
