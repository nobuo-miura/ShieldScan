// Package analyzer はWebサイトのセキュリティヘッダー・CORS・JWT・SSL/TLS・Cookieを
// 診断するための各種スキャン機能を提供します。
package analyzer

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// HeaderResult は1つのセキュリティヘッダーの解析結果を表します。
//
// Status フィールドは以下のいずれかの値を取ります:
//   - "good"    — 適切に設定されている
//   - "warning" — 設定はあるが改善の余地がある
//   - "missing" — ヘッダーが存在しない
type HeaderResult struct {
	Name        string `json:"name"`
	Present     bool   `json:"present"`
	Value       string `json:"value"`
	Score       int    `json:"score"`     // 実際の得点（0〜MaxScore）
	MaxScore    int    `json:"max_score"` // このヘッダーの満点
	Status      string `json:"status"`    // "good", "warning", "missing"
	Description string `json:"description"`
	Advice      string `json:"advice"`
}

// AnalysisResult はURL全体のセキュリティヘッダースキャン結果を表します。
// 各ヘッダーの詳細は Headers フィールドに格納され、
// Grade はTotalScore/MaxScore の割合から算出されます（A+〜F）。
type AnalysisResult struct {
	URL          string         `json:"url"`
	FinalURL     string         `json:"final_url"` // リダイレクト後の最終URL
	ScannedAt    time.Time      `json:"scanned_at"`
	TotalScore   int            `json:"total_score"`
	MaxScore     int            `json:"max_score"`
	Grade        string         `json:"grade"` // "A+", "A", "B", "C", "D", "F"
	Headers      []HeaderResult `json:"headers"`
	ResponseTime int64          `json:"response_time_ms"`
	TLSEnabled   bool           `json:"tls_enabled"`
}

// headerRule は1つのセキュリティヘッダーの評価ルールを定義します。
// check 関数にヘッダーの値と存在有無を渡すと、得点・ステータス・改善アドバイスを返します。
type headerRule struct {
	name        string
	maxScore    int
	description string
	check       func(value string, present bool) (score int, status string, advice string)
}

var rules = []headerRule{
	{
		name:        "Strict-Transport-Security",
		maxScore:    20,
		description: "HTTPSの強制を指示します。中間者攻撃（MITM）を防ぐために重要なヘッダーです。",
		check: func(value string, present bool) (int, string, string) {
			if !present {
				return 0, "missing", "HSTSヘッダーを追加し、max-ageを最低31536000（1年）以上に設定してください。"
			}
			lower := strings.ToLower(value)
			if strings.Contains(lower, "max-age=0") {
				return 5, "warning", "max-age=0はHSTSを無効化します。適切な値（例: max-age=31536000）を設定してください。"
			}
			if strings.Contains(lower, "includesubdomains") && strings.Contains(lower, "preload") {
				return 20, "good", ""
			}
			if strings.Contains(lower, "includesubdomains") {
				return 15, "warning", "preloadディレクティブを追加するとより安全です。"
			}
			return 10, "warning", "includeSubDomainsとpreloadディレクティブの追加を検討してください。"
		},
	},
	{
		name:        "Content-Security-Policy",
		maxScore:    25,
		description: "XSS（クロスサイトスクリプティング）やデータインジェクション攻撃を防ぐための強力なヘッダーです。",
		check: func(value string, present bool) (int, string, string) {
			if !present {
				return 0, "missing", "CSPヘッダーを設定してください。最初はContent-Security-Policy: default-src 'self'から始めるのがおすすめです。"
			}
			lower := strings.ToLower(value)
			if strings.Contains(lower, "unsafe-inline") && strings.Contains(lower, "unsafe-eval") {
				return 5, "warning", "unsafe-inlineとunsafe-evalは危険です。nonceやhashベースのCSPへの移行を検討してください。"
			}
			if strings.Contains(lower, "unsafe-inline") || strings.Contains(lower, "unsafe-eval") {
				return 12, "warning", "unsafe-inlineまたはunsafe-evalが含まれています。より厳格なポリシーを検討してください。"
			}
			if strings.Contains(lower, "default-src") {
				return 25, "good", ""
			}
			return 15, "warning", "default-srcディレクティブの追加を検討してください。"
		},
	},
	{
		name:        "X-Frame-Options",
		maxScore:    10,
		description: "クリックジャッキング攻撃を防ぎます。iframeへの埋め込みを制御します。",
		check: func(value string, present bool) (int, string, string) {
			if !present {
				return 0, "missing", "X-Frame-Options: DENYまたはSAMEORIGINを設定してください。"
			}
			upper := strings.ToUpper(value)
			if upper == "DENY" || upper == "SAMEORIGIN" {
				return 10, "good", ""
			}
			return 5, "warning", "DENY（最も安全）またはSAMEORIGINの使用を推奨します。"
		},
	},
	{
		name:        "X-Content-Type-Options",
		maxScore:    10,
		description: "ブラウザがMIMEタイプをスニッフィングするのを防ぎます。",
		check: func(value string, present bool) (int, string, string) {
			if !present {
				return 0, "missing", "X-Content-Type-Options: nosniffを設定してください。"
			}
			if strings.ToLower(value) == "nosniff" {
				return 10, "good", ""
			}
			return 5, "warning", "値はnosniffである必要があります。"
		},
	},
	{
		name:        "Referrer-Policy",
		maxScore:    10,
		description: "リファラー情報の送信範囲を制御し、プライバシーを保護します。",
		check: func(value string, present bool) (int, string, string) {
			if !present {
				return 0, "missing", "Referrer-Policy: strict-origin-when-cross-originの設定を推奨します。"
			}
			safe := []string{"no-referrer", "strict-origin", "strict-origin-when-cross-origin", "same-origin"}
			lower := strings.ToLower(strings.TrimSpace(value))
			for _, s := range safe {
				if lower == s {
					return 10, "good", ""
				}
			}
			return 5, "warning", "strict-origin-when-cross-originなどのより厳格なポリシーを推奨します。"
		},
	},
	{
		name:        "Permissions-Policy",
		maxScore:    10,
		description: "カメラ・マイク・位置情報などのブラウザAPIへのアクセスを制御します。",
		check: func(value string, present bool) (int, string, string) {
			if !present {
				return 0, "missing", "Permissions-Policyを設定し、不要なブラウザ機能へのアクセスを制限してください。"
			}
			return 10, "good", ""
		},
	},
	{
		name:        "X-XSS-Protection",
		maxScore:    5,
		description: "古いブラウザ向けのXSSフィルター設定です。現代のブラウザではCSPで代替されます。",
		check: func(value string, present bool) (int, string, string) {
			if !present {
				return 0, "missing", "X-XSS-Protection: 1; mode=blockを設定してください（レガシー対応）。"
			}
			if strings.Contains(value, "1") {
				return 5, "good", ""
			}
			return 2, "warning", "1; mode=blockの設定を推奨します。"
		},
	},
	{
		name:        "Cache-Control",
		maxScore:    10,
		description: "機密ページのキャッシュを制御し、センシティブな情報の漏洩を防ぎます。",
		check: func(value string, present bool) (int, string, string) {
			if !present {
				return 0, "missing", "機密ページにはCache-Control: no-store, no-cacheを設定してください。"
			}
			lower := strings.ToLower(value)
			if strings.Contains(lower, "no-store") {
				return 10, "good", ""
			}
			if strings.Contains(lower, "no-cache") || strings.Contains(lower, "private") {
				return 7, "warning", "no-storeの追加をお勧めします。"
			}
			return 3, "warning", "機密ページにはno-store, no-cacheの設定を推奨します。"
		},
	},
}

// Analyze は指定URLにGETリクエストを送信し、レスポンスヘッダーのセキュリティ診断を行います。
//
// 内部で定義された rules に基づき各ヘッダーを評価してスコアを算出し、
// 総合グレード（A+〜F）を付与した [AnalysisResult] を返します。
//
// タイムアウトは10秒、リダイレクトは最大5回まで追跡します。
func Analyze(rawURL string) (*AnalysisResult, error) {
	start := time.Now()

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}
	req.Header.Set("User-Agent", "SecurityHeaderAnalyzer/1.0 (+https://github.com/nobuo-miura/shieldscan)")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	elapsed := time.Since(start).Milliseconds()
	tlsEnabled := resp.TLS != nil

	results := make([]HeaderResult, 0, len(rules))
	totalScore := 0
	maxScore := 0

	for _, rule := range rules {
		value := resp.Header.Get(rule.name)
		present := value != ""
		score, status, advice := rule.check(value, present)

		results = append(results, HeaderResult{
			Name:        rule.name,
			Present:     present,
			Value:       value,
			Score:       score,
			MaxScore:    rule.maxScore,
			Status:      status,
			Description: rule.description,
			Advice:      advice,
		})

		totalScore += score
		maxScore += rule.maxScore
	}

	grade := calcGrade(totalScore, maxScore)

	return &AnalysisResult{
		URL:          rawURL,
		FinalURL:     resp.Request.URL.String(),
		ScannedAt:    time.Now(),
		TotalScore:   totalScore,
		MaxScore:     maxScore,
		Grade:        grade,
		Headers:      results,
		ResponseTime: elapsed,
		TLSEnabled:   tlsEnabled,
	}, nil
}

// calcGrade はスコアと満点からグレード文字列を返します。
//
// グレード基準（得点率）:
//   - 90%以上 → A+
//   - 80%以上 → A
//   - 70%以上 → B
//   - 60%以上 → C
//   - 50%以上 → D
//   - 50%未満 → F
func calcGrade(score, max int) string {
	if max == 0 {
		return "F"
	}
	pct := float64(score) / float64(max) * 100
	switch {
	case pct >= 90:
		return "A+"
	case pct >= 80:
		return "A"
	case pct >= 70:
		return "B"
	case pct >= 60:
		return "C"
	case pct >= 50:
		return "D"
	default:
		return "F"
	}
}
