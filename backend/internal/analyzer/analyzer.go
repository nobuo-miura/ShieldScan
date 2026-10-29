// Package analyzer はWebサイトのセキュリティヘッダー・CORS・JWT・SSL/TLS・Cookieを
// 診断するための各種スキャン機能を提供します。
//
// 診断結果に含まれる説明文やアドバイスは [msg.Message]（翻訳キーと差し込みパラメータ）
// として返され、実際の文言はクライアント側の辞書で解決されます。
package analyzer

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/nobuo-miura/shieldscan/internal/msg"
	"github.com/nobuo-miura/shieldscan/internal/safehttp"
)

// drainAndClose はレスポンスボディを読み捨ててから閉じます。
// 本ツールはヘッダーしか見ないためボディは不要ですが、読み切らずに閉じると
// TCP接続が再利用されず、連続スキャン時に接続を張り直す無駄が生じます。
// 読み捨て量は上限を設け、巨大なレスポンスに付き合わないようにしています。
func drainAndClose(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	_ = resp.Body.Close()
}

const (
	// scanTimeout は外部ホストへの1リクエストあたりのタイムアウトです。
	scanTimeout = 10 * time.Second
	// maxRedirects は追跡するリダイレクトの最大回数です。
	maxRedirects = 5
	// userAgent はスキャン時に送出する User-Agent です。
	// 対象サイトの管理者が正体とアクセス理由を特定できるようにしています。
	userAgent = "ShieldScan/1.0 (+https://github.com/nobuo-miura/ShieldScan)"
)

// HeaderResult は1つのセキュリティヘッダーの解析結果を表します。
//
// Status フィールドは以下のいずれかの値を取ります:
//   - "good"    — 適切に設定されている
//   - "warning" — 設定はあるが改善の余地がある
//   - "missing" — ヘッダーが存在しない
type HeaderResult struct {
	Name        string       `json:"name"`
	Present     bool         `json:"present"`
	Value       string       `json:"value"`
	Score       int          `json:"score"`     // 実際の得点（0〜MaxScore）
	MaxScore    int          `json:"max_score"` // このヘッダーの満点
	Status      string       `json:"status"`    // "good", "warning", "missing"
	Description msg.Message  `json:"description"`
	Advice      *msg.Message `json:"advice,omitempty"` // 改善点がない場合は nil
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
// descKey と check が返すメッセージはいずれも翻訳キーであり、訳文は含みません。
// 改善点がない場合、check は空のメッセージ（[msg.Message.IsZero] が true）を返します。
type headerRule struct {
	name     string
	maxScore int
	descKey  string
	check    func(value string, present bool) (score int, status string, advice msg.Message)
}

var rules = []headerRule{
	{
		name:     "Strict-Transport-Security",
		maxScore: 20,
		descKey:  msg.HeaderHSTSDesc,
		check: func(value string, present bool) (int, string, msg.Message) {
			if !present {
				return 0, "missing", msg.M(msg.HeaderHSTSAdviceMissing)
			}
			lower := strings.ToLower(value)
			if strings.Contains(lower, "max-age=0") {
				return 5, "warning", msg.M(msg.HeaderHSTSAdviceMaxAgeZero)
			}
			if strings.Contains(lower, "includesubdomains") && strings.Contains(lower, "preload") {
				return 20, "good", msg.Message{}
			}
			if strings.Contains(lower, "includesubdomains") {
				return 15, "warning", msg.M(msg.HeaderHSTSAdviceNoPreload)
			}
			return 10, "warning", msg.M(msg.HeaderHSTSAdviceNoSubdomains)
		},
	},
	{
		name:     "Content-Security-Policy",
		maxScore: 25,
		descKey:  msg.HeaderCSPDesc,
		check: func(value string, present bool) (int, string, msg.Message) {
			if !present {
				return 0, "missing", msg.M(msg.HeaderCSPAdviceMissing)
			}
			lower := strings.ToLower(value)
			if strings.Contains(lower, "unsafe-inline") && strings.Contains(lower, "unsafe-eval") {
				return 5, "warning", msg.M(msg.HeaderCSPAdviceUnsafeInlineEval)
			}
			if strings.Contains(lower, "unsafe-inline") || strings.Contains(lower, "unsafe-eval") {
				return 12, "warning", msg.M(msg.HeaderCSPAdviceUnsafeEither)
			}
			if strings.Contains(lower, "default-src") {
				return 25, "good", msg.Message{}
			}
			return 15, "warning", msg.M(msg.HeaderCSPAdviceNoDefaultSrc)
		},
	},
	{
		name:     "X-Frame-Options",
		maxScore: 10,
		descKey:  msg.HeaderXFrameOptionsDesc,
		check: func(value string, present bool) (int, string, msg.Message) {
			if !present {
				return 0, "missing", msg.M(msg.HeaderXFrameOptionsAdviceMissing)
			}
			upper := strings.ToUpper(value)
			if upper == "DENY" || upper == "SAMEORIGIN" {
				return 10, "good", msg.Message{}
			}
			return 5, "warning", msg.M(msg.HeaderXFrameOptionsAdviceWeakValue)
		},
	},
	{
		name:     "X-Content-Type-Options",
		maxScore: 10,
		descKey:  msg.HeaderXContentTypeDesc,
		check: func(value string, present bool) (int, string, msg.Message) {
			if !present {
				return 0, "missing", msg.M(msg.HeaderXContentTypeAdviceMissing)
			}
			if strings.ToLower(value) == "nosniff" {
				return 10, "good", msg.Message{}
			}
			return 5, "warning", msg.M(msg.HeaderXContentTypeAdviceNotNosniff)
		},
	},
	{
		name:     "Referrer-Policy",
		maxScore: 10,
		descKey:  msg.HeaderReferrerPolicyDesc,
		check: func(value string, present bool) (int, string, msg.Message) {
			if !present {
				return 0, "missing", msg.M(msg.HeaderReferrerPolicyAdviceMissing)
			}
			safe := []string{"no-referrer", "strict-origin", "strict-origin-when-cross-origin", "same-origin"}
			lower := strings.ToLower(strings.TrimSpace(value))
			for _, s := range safe {
				if lower == s {
					return 10, "good", msg.Message{}
				}
			}
			return 5, "warning", msg.M(msg.HeaderReferrerPolicyAdviceWeakValue)
		},
	},
	{
		name:     "Permissions-Policy",
		maxScore: 10,
		descKey:  msg.HeaderPermissionsPolicyDesc,
		check: func(_ string, present bool) (int, string, msg.Message) {
			if !present {
				return 0, "missing", msg.M(msg.HeaderPermissionsPolicyAdviceMissing)
			}
			return 10, "good", msg.Message{}
		},
	},
	{
		name:     "X-XSS-Protection",
		maxScore: 5,
		descKey:  msg.HeaderXXSSProtectionDesc,
		check: func(value string, present bool) (int, string, msg.Message) {
			if !present {
				return 0, "missing", msg.M(msg.HeaderXXSSProtectionAdviceMissing)
			}
			if strings.Contains(value, "1") {
				return 5, "good", msg.Message{}
			}
			return 2, "warning", msg.M(msg.HeaderXXSSProtectionAdviceWeakValue)
		},
	},
	{
		name:     "Cache-Control",
		maxScore: 10,
		descKey:  msg.HeaderCacheControlDesc,
		check: func(value string, present bool) (int, string, msg.Message) {
			if !present {
				return 0, "missing", msg.M(msg.HeaderCacheControlAdviceMissing)
			}
			lower := strings.ToLower(value)
			if strings.Contains(lower, "no-store") {
				return 10, "good", msg.Message{}
			}
			if strings.Contains(lower, "no-cache") || strings.Contains(lower, "private") {
				return 7, "warning", msg.M(msg.HeaderCacheControlAdviceAddNoStore)
			}
			return 3, "warning", msg.M(msg.HeaderCacheControlAdviceWeakValue)
		},
	},
}

// Analyze は指定URLにGETリクエストを送信し、レスポンスヘッダーのセキュリティ診断を行います。
//
// 内部で定義された rules に基づき各ヘッダーを評価してスコアを算出し、
// 総合グレード（A+〜F）を付与した [AnalysisResult] を返します。
//
// タイムアウトは10秒、リダイレクトは最大5回まで追跡します。
// ctx をキャンセルすると進行中のリクエストも中断されます。
func Analyze(ctx context.Context, rawURL string) (*AnalysisResult, error) {
	start := time.Now()

	// リダイレクト先も含め、接続直前に毎回IPを検査する SSRF 保護付きクライアント。
	client := safehttp.NewClient(scanTimeout, maxRedirects)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer drainAndClose(resp)

	elapsed := time.Since(start).Milliseconds()
	tlsEnabled := resp.TLS != nil

	results := make([]HeaderResult, 0, len(rules))
	totalScore := 0
	maxScore := 0

	for _, rule := range rules {
		value := resp.Header.Get(rule.name)
		present := value != ""
		score, status, advice := rule.check(value, present)

		result := HeaderResult{
			Name:        rule.name,
			Present:     present,
			Value:       value,
			Score:       score,
			MaxScore:    rule.maxScore,
			Status:      status,
			Description: msg.M(rule.descKey),
		}
		if !advice.IsZero() {
			result.Advice = &advice
		}
		results = append(results, result)

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
func calcGrade(score, maxScore int) string {
	if maxScore == 0 {
		return "F"
	}
	pct := float64(score) / float64(maxScore) * 100
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
