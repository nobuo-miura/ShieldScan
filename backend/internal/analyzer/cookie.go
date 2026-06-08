// このファイルはCookieのセキュリティ属性を監査する機能を提供します。
// HTTPレスポンスのSet-CookieヘッダーからSecure・HttpOnly・SameSiteフラグの
// 設定状況を検査し、問題のあるCookieを報告します。
package analyzer

import (
	"net/http"
	"net/http/cookiejar"
	"strings"
	"time"
)

// CookieResult は1つのCookieのセキュリティ監査結果を表します。
//
// Sensitive は Cookie名が [sensitiveNamePatterns] のいずれかを含む場合に true になります。
// Severity はそのCookieで検出された問題の中で最も深刻なレベルを示します。
type CookieResult struct {
	Name      string   `json:"name"`
	Sensitive bool     `json:"sensitive"` // セッション・トークン等の機密Cookieと判定されたか
	Secure    bool     `json:"secure"`
	HttpOnly  bool     `json:"http_only"`
	SameSite  string   `json:"same_site"` // "Strict", "Lax", "None", "未設定"
	Issues    []string `json:"issues"`
	Severity  string   `json:"severity"` // Issues中の最高深刻度: "info", "warning", "high", "critical"
}

// CookieAuditResult はCookieセキュリティ監査の総合結果を表します。
type CookieAuditResult struct {
	URL          string         `json:"url"`
	ScannedAt    time.Time      `json:"scanned_at"`
	Cookies      []CookieResult `json:"cookies"`
	TotalCookies int            `json:"total_cookies"`
	IssueCount   int            `json:"issue_count"` // 1件以上の問題を持つCookieの数
	ResponseTime int64          `json:"response_time_ms"`
}

// sensitiveNamePatterns は機密Cookieを識別するためのキーワード一覧です。
// Cookieの名前にこれらのキーワードが含まれていれば、セキュリティ評価を強化します。
var sensitiveNamePatterns = []string{
	"session", "sess", "token", "auth", "jwt", "id",
	"user", "login", "csrf", "xsrf", "sid",
}

// AuditCookies は指定URLにアクセスしてSet-CookieヘッダーのセキュリティをAuditします。
//
// 各Cookieについて以下を検査します:
//   - Secureフラグ（HTTPS接続時に欠如している場合は high）
//   - HttpOnlyフラグ（JavaScriptからのアクセス可否）
//   - SameSite属性（CSRF攻撃への脆弱性）
//
// 機密Cookieと判定されたものはより厳しい基準で評価されます。
func AuditCookies(rawURL string) (*CookieAuditResult, error) {
	start := time.Now()

	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Timeout: 10 * time.Second,
		Jar:     jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "ShieldScan/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()
	elapsed := time.Since(start).Milliseconds()

	isHTTPS := strings.HasPrefix(rawURL, "https://")
	results := []CookieResult{}
	issueCount := 0

	for _, c := range resp.Cookies() {
		sensitive := isSensitiveCookie(c.Name)
		issues := []string{}
		worstSeverity := "info"

		// Secure flag
		if !c.Secure && isHTTPS {
			issues = append(issues, "Secureフラグなし — HTTP経由で送信される可能性があります")
			worstSeverity = upgradeSeverity(worstSeverity, "high")
		}

		// HttpOnly
		if !c.HttpOnly {
			msg := "HttpOnlyフラグなし — JavaScriptからdocument.cookieでアクセス可能です"
			if sensitive {
				issues = append(issues, msg+" (機密Cookie)")
				worstSeverity = upgradeSeverity(worstSeverity, "high")
			} else {
				issues = append(issues, msg)
				worstSeverity = upgradeSeverity(worstSeverity, "warning")
			}
		}

		// SameSite
		var sameSite string
		switch c.SameSite {
		case http.SameSiteStrictMode:
			sameSite = "Strict"
		case http.SameSiteLaxMode:
			sameSite = "Lax"
		case http.SameSiteNoneMode:
			sameSite = "None"
			if sensitive {
				issues = append(issues, "SameSite=Strict/Laxなし — CSRF攻撃に脆弱な可能性があります (機密Cookie)")
				worstSeverity = upgradeSeverity(worstSeverity, "high")
			} else {
				issues = append(issues, "SameSite=None — クロスサイトリクエストで送信されます")
				worstSeverity = upgradeSeverity(worstSeverity, "warning")
			}
		default:
			sameSite = "未設定"
			if sensitive {
				issues = append(issues, "SameSite属性が未設定 — CSRF攻撃に脆弱な可能性があります (機密Cookie)")
				worstSeverity = upgradeSeverity(worstSeverity, "high")
			} else {
				issues = append(issues, "SameSite属性が未設定 — クロスサイトリクエストで送信されます")
				worstSeverity = upgradeSeverity(worstSeverity, "warning")
			}
		}

		if len(issues) > 0 {
			issueCount++
		}

		results = append(results, CookieResult{
			Name:      c.Name,
			Sensitive: sensitive,
			Secure:    c.Secure,
			HttpOnly:  c.HttpOnly,
			SameSite:  sameSite,
			Issues:    issues,
			Severity:  worstSeverity,
		})
	}

	return &CookieAuditResult{
		URL:          rawURL,
		ScannedAt:    time.Now(),
		Cookies:      results,
		TotalCookies: len(results),
		IssueCount:   issueCount,
		ResponseTime: elapsed,
	}, nil
}

// isSensitiveCookie はCookie名が機密性の高いキーワードを含むかどうかを判定します。
func isSensitiveCookie(name string) bool {
	lower := strings.ToLower(name)
	for _, p := range sensitiveNamePatterns {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

// upgradeSeverity は current と candidate を比較し、より深刻な方を返します。
// 深刻度の順序: info < warning < high < critical
func upgradeSeverity(current, candidate string) string {
	order := map[string]int{"info": 0, "warning": 1, "high": 2, "critical": 3}
	if order[candidate] > order[current] {
		return candidate
	}
	return current
}
