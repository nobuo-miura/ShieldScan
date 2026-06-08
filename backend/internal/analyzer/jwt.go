// このファイルはJWTトークンの静的セキュリティ解析機能を提供します。
// ネットワーク接続は行わず、トークン文字列だけからヘッダー・ペイロードを解析します。
package analyzer

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// JWTFinding はJWT解析で検出された1件のセキュリティ問題を表します。
//
// Severity は以下のいずれかの値を取ります:
//   - "critical" — 即座に悪用可能な重大な問題
//   - "high"     — 高リスクの問題
//   - "warning"  — 注意が必要な問題
//   - "info"     — 情報提供（問題ではない場合も含む）
type JWTFinding struct {
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Description string `json:"description"`
}

// JWTResult はJWT解析の総合結果を表します。
//
// ParseError が空でない場合は解析に失敗しており、他のフィールドは信頼できません。
// IssuedAt・ExpiresAt はフロントエンド表示用のフォーマット済み文字列です。
type JWTResult struct {
	Raw        string                 `json:"raw"`
	Header     map[string]interface{} `json:"header"`
	Payload    map[string]interface{} `json:"payload"`
	Findings   []JWTFinding           `json:"findings"`
	ScannedAt  time.Time              `json:"scanned_at"`
	ParseError string                 `json:"parse_error,omitempty"`
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
		return &JWTResult{
			Raw:        token,
			ParseError: "JWTは3つのパート（header.payload.signature）で構成される必要があります",
			ScannedAt:  time.Now(),
		}, nil
	}

	header, err := decodeJWTPart(parts[0])
	if err != nil {
		return &JWTResult{Raw: token, ParseError: "ヘッダーのデコードに失敗: " + err.Error(), ScannedAt: time.Now()}, nil
	}

	payload, err := decodeJWTPart(parts[1])
	if err != nil {
		return &JWTResult{Raw: token, ParseError: "ペイロードのデコードに失敗: " + err.Error(), ScannedAt: time.Now()}, nil
	}

	findings := []JWTFinding{}

	// --- alg checks ---
	alg, _ := header["alg"].(string)
	switch strings.ToLower(alg) {
	case "none", "":
		findings = append(findings, JWTFinding{
			Severity:    "critical",
			Title:       "alg: none — 署名検証なし",
			Description: "alg=noneはJWTの署名検証をスキップします。攻撃者がペイロードを自由に改ざんできます（CVE-2015-9235相当）。",
		})
	case "hs256", "hs384", "hs512":
		findings = append(findings, JWTFinding{
			Severity:    "info",
			Title:       fmt.Sprintf("対称鍵アルゴリズム使用: %s", alg),
			Description: "HMACアルゴリズムは秘密鍵の強度に依存します。弱い鍵はブルートフォース攻撃に脆弱です。RS256/ES256への移行を検討してください。",
		})
	case "rs256", "es256", "ps256":
		findings = append(findings, JWTFinding{
			Severity:    "info",
			Title:       fmt.Sprintf("非対称鍵アルゴリズム使用: %s", alg),
			Description: "公開鍵暗号方式を使用しています。アルゴリズム混同攻撃（RS256→HS256）に注意してください。",
		})
	}

	// --- kid injection ---
	if kid, ok := header["kid"].(string); ok {
		suspicious := []string{"'", "\"", "--", ";", "/", "\\", "../"}
		for _, s := range suspicious {
			if strings.Contains(kid, s) {
				findings = append(findings, JWTFinding{
					Severity:    "critical",
					Title:       "kid インジェクション疑い",
					Description: fmt.Sprintf("kidフィールドに不審な文字列が含まれています: %q。SQLインジェクションやパストラバーサルが可能な場合があります。", kid),
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
				Title:       "トークン期限切れ",
				Description: fmt.Sprintf("expクレームが過去の時刻です（%s）。期限切れトークンが受け入れられている場合、セキュリティリスクがあります。", expiresAt),
			})
		} else if exp-now > 86400*30 {
			findings = append(findings, JWTFinding{
				Severity:    "warning",
				Title:       "有効期限が長すぎる",
				Description: fmt.Sprintf("トークンの有効期限が30日以上です（%s）。短い有効期限を推奨します。", expiresAt),
			})
		}
	} else {
		findings = append(findings, JWTFinding{
			Severity:    "high",
			Title:       "exp クレームなし",
			Description: "有効期限（exp）が設定されていません。トークンが永続的に有効となり、漏洩時のリスクが高まります。",
		})
	}

	if iat, ok := toInt64(payload["iat"]); ok {
		issuedAt = time.Unix(iat, 0).Format("2006-01-02 15:04:05 MST")
	}

	// --- nbf check ---
	if nbf, ok := toInt64(payload["nbf"]); ok {
		if nbf > now {
			findings = append(findings, JWTFinding{
				Severity:    "warning",
				Title:       "nbf が未来の時刻",
				Description: fmt.Sprintf("nbf（Not Before）が未来の時刻（%s）です。このトークンはまだ有効ではありません。", time.Unix(nbf, 0).Format("2006-01-02 15:04:05")),
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
					Title:       fmt.Sprintf("機密情報がペイロードに含まれている可能性: %q", pk),
					Description: "JWTのペイロードはBase64エンコードされているだけで暗号化されていません。機密情報はペイロードに含めないでください。",
				})
			}
		}
	}

	if len(findings) == 0 {
		findings = append(findings, JWTFinding{
			Severity:    "info",
			Title:       "明らかな問題は検出されませんでした",
			Description: "静的解析の範囲では問題が見つかりませんでした。署名の実際の検証はサーバー側で行ってください。",
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
