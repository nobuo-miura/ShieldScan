// このファイルはJWTトークンの静的セキュリティ解析機能を提供します。
// ネットワーク接続は行わず、トークン文字列だけからヘッダー・ペイロードを解析します。
package analyzer

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	"github.com/nobuo-miura/shieldscan/internal/msg"
)

// JWTFinding はJWT解析で検出された1件のセキュリティ問題を表します。
//
// Severity は以下のいずれかの値を取ります:
//   - "critical" — 即座に悪用可能な重大な問題
//   - "high"     — 高リスクの問題
//   - "warning"  — 注意が必要な問題
//   - "info"     — 情報提供（問題ではない場合も含む）
type JWTFinding struct {
	Severity    string      `json:"severity"`
	Title       msg.Message `json:"title"`
	Description msg.Message `json:"description"`
}

// JWTResult はJWT解析の総合結果を表します。
//
// ParseError が nil でない場合は解析に失敗しており、他のフィールドは信頼できません。
// IssuedAt・ExpiresAt はフロントエンド表示用のフォーマット済み文字列です。
type JWTResult struct {
	Raw        string                 `json:"raw"`
	Header     map[string]interface{} `json:"header"`
	Payload    map[string]interface{} `json:"payload"`
	Findings   []JWTFinding           `json:"findings"`
	ScannedAt  time.Time              `json:"scanned_at"`
	ParseError *msg.Message           `json:"parse_error,omitempty"`
	IssuedAt   string                 `json:"issued_at,omitempty"`  // iat クレームの表示用文字列
	ExpiresAt  string                 `json:"expires_at,omitempty"` // exp クレームの表示用文字列
	Expired    bool                   `json:"expired"`
}

// AnalyzeJWT はJWTトークンを静的解析し、セキュリティ上の問題を検出します。
//
// 以下の項目を検査します:
//   - alg フィールド（none・対称鍵・非対称鍵の識別）
//   - kid フィールドのインジェクション可能文字列
//   - exp クレーム（有効期限切れ・期限が長すぎる）
//   - nbf クレーム（Not Before が未来）
//   - ペイロードへの機密情報の混入
//
// パース失敗時は Findings が空で ParseError にメッセージが格納された結果を返します。
// エラー戻り値は常に nil です（パース失敗はエラーではなく診断結果として扱います）。
func AnalyzeJWT(token string) (*JWTResult, error) {
	token = strings.TrimSpace(token)
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return newJWTParseError(token, msg.M(msg.JWTParseErrorInvalidParts)), nil
	}

	header, err := decodeJWTPart(parts[0])
	if err != nil {
		// Go のエラー文字列は翻訳対象外とし、パラメータとしてそのまま埋め込む。
		return newJWTParseError(token, msg.P(msg.JWTParseErrorHeaderDecode, "error", err.Error())), nil
	}

	payload, err := decodeJWTPart(parts[1])
	if err != nil {
		return newJWTParseError(token, msg.P(msg.JWTParseErrorPayloadDecode, "error", err.Error())), nil
	}

	findings := []JWTFinding{}

	// --- alg checks ---
	alg, _ := header["alg"].(string)
	switch strings.ToLower(alg) {
	case "none", "":
		findings = append(findings, JWTFinding{
			Severity:    "critical",
			Title:       msg.M(msg.JWTAlgNoneTitle),
			Description: msg.M(msg.JWTAlgNoneDesc),
		})
	case "hs256", "hs384", "hs512":
		findings = append(findings, JWTFinding{
			Severity:    "info",
			Title:       msg.P(msg.JWTAlgSymmetricTitle, "alg", alg),
			Description: msg.M(msg.JWTAlgSymmetricDesc),
		})
	case "rs256", "es256", "ps256":
		findings = append(findings, JWTFinding{
			Severity:    "info",
			Title:       msg.P(msg.JWTAlgAsymmetricTitle, "alg", alg),
			Description: msg.M(msg.JWTAlgAsymmetricDesc),
		})
	}

	// --- kid injection ---
	if kid, ok := header["kid"].(string); ok {
		suspicious := []string{"'", "\"", "--", ";", "/", "\\", "../"}
		for _, s := range suspicious {
			if strings.Contains(kid, s) {
				findings = append(findings, JWTFinding{
					Severity:    "critical",
					Title:       msg.M(msg.JWTKidInjectionTitle),
					Description: msg.P(msg.JWTKidInjectionDesc, "kid", kid),
				})
				break
			}
		}
	}

	// --- exp check ---
	now := time.Now().Unix()
	expired := false
	expiresAt := ""
	issuedAt := ""

	if exp, ok := toInt64(payload["exp"]); ok {
		t := time.Unix(exp, 0)
		expiresAt = t.Format("2006-01-02 15:04:05 MST")
		if exp < now {
			expired = true
			findings = append(findings, JWTFinding{
				Severity:    "warning",
				Title:       msg.M(msg.JWTExpiredTitle),
				Description: msg.P(msg.JWTExpiredDesc, "expires_at", expiresAt),
			})
		} else if exp-now > 86400*30 {
			findings = append(findings, JWTFinding{
				Severity:    "warning",
				Title:       msg.M(msg.JWTLongExpiryTitle),
				Description: msg.P(msg.JWTLongExpiryDesc, "expires_at", expiresAt),
			})
		}
	} else {
		findings = append(findings, JWTFinding{
			Severity:    "high",
			Title:       msg.M(msg.JWTNoExpTitle),
			Description: msg.M(msg.JWTNoExpDesc),
		})
	}

	if iat, ok := toInt64(payload["iat"]); ok {
		issuedAt = time.Unix(iat, 0).Format("2006-01-02 15:04:05 MST")
	}

	// --- nbf check ---
	if nbf, ok := toInt64(payload["nbf"]); ok {
		if nbf > now {
			notBefore := time.Unix(nbf, 0).Format("2006-01-02 15:04:05")
			findings = append(findings, JWTFinding{
				Severity:    "warning",
				Title:       msg.M(msg.JWTNbfFutureTitle),
				Description: msg.P(msg.JWTNbfFutureDesc, "not_before", notBefore),
			})
		}
	}

	// --- sensitive fields ---
	sensitiveKeys := []string{"password", "passwd", "secret", "credit_card", "ssn", "token", "api_key"}
	for _, k := range sensitiveKeys {
		for pk := range payload {
			if strings.Contains(strings.ToLower(pk), k) {
				findings = append(findings, JWTFinding{
					Severity:    "high",
					Title:       msg.P(msg.JWTSensitiveClaimTitle, "claim", pk),
					Description: msg.M(msg.JWTSensitiveClaimDesc),
				})
			}
		}
	}

	if len(findings) == 0 {
		findings = append(findings, JWTFinding{
			Severity:    "info",
			Title:       msg.M(msg.JWTNoIssuesTitle),
			Description: msg.M(msg.JWTNoIssuesDesc),
		})
	}

	return &JWTResult{
		Raw:       token,
		Header:    header,
		Payload:   payload,
		Findings:  findings,
		ScannedAt: time.Now(),
		IssuedAt:  issuedAt,
		ExpiresAt: expiresAt,
		Expired:   expired,
	}, nil
}

// newJWTParseError はパース失敗を表す [JWTResult] を組み立てます。
func newJWTParseError(token string, parseError msg.Message) *JWTResult {
	return &JWTResult{
		Raw:        token,
		ParseError: &parseError,
		ScannedAt:  time.Now(),
	}
}

// decodeJWTPart はJWTのヘッダーまたはペイロード部分（Base64URLエンコード）をデコードして
// JSONオブジェクトとして返します。Base64のパディング不足を自動補完します。
func decodeJWTPart(part string) (map[string]interface{}, error) {
	// Base64URLはパディング（=）を省略するため、長さに応じて補完する
	switch len(part) % 4 {
	case 2:
		part += "=="
	case 3:
		part += "="
	}
	b, err := base64.URLEncoding.DecodeString(part)
	if err != nil {
		b, err = base64.StdEncoding.DecodeString(part)
		if err != nil {
			return nil, err
		}
	}
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// toInt64 はJSONの数値型（float64・int64・json.Number）を int64 に変換します。
// JWTクレームの数値フィールド（exp・iat・nbf）を取り出す際に使用します。
func toInt64(v interface{}) (int64, bool) {
	switch n := v.(type) {
	case float64:
		return int64(n), true
	case int64:
		return n, true
	case json.Number:
		i, err := n.Int64()
		return i, err == nil
	}
	return 0, false
}
