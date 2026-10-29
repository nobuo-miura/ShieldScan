// このファイルはTLS/SSL接続のセキュリティ診断機能を提供します。
// 実際にTLS接続を確立し、プロトコルバージョン・暗号スイート・証明書の状態を検査します。
package analyzer

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/nobuo-miura/shieldscan/internal/msg"
	"github.com/nobuo-miura/shieldscan/internal/safehttp"
)

// legacyProbeTimeout は TLS 1.0/1.1 受け入れ確認（[checkLegacyTLS]）用の
// 短めのタイムアウトです。2バージョン分を順に試すため本体より短くしています。
const legacyProbeTimeout = 5 * time.Second

// SSLFinding はTLS/SSL診断で検出された1件の問題を表します。
type SSLFinding struct {
	Severity    string      `json:"severity"` // "critical", "high", "warning", "info"
	Title       msg.Message `json:"title"`
	Description msg.Message `json:"description"`
}

// CertInfo はTLS証明書の主要情報をまとめた構造体です。
//
// SelfSigned は Subject と Issuer の CommonName が一致する場合に true になります
// （厳密なCA検証ではなく、簡易判定です）。
type CertInfo struct {
	Subject    string    `json:"subject"`
	Issuer     string    `json:"issuer"`
	NotBefore  time.Time `json:"not_before"`
	NotAfter   time.Time `json:"not_after"`
	DaysLeft   int       `json:"days_left"` // 有効期限まで残り日数（負値は期限切れ）
	SelfSigned bool      `json:"self_signed"`
	SANs       []string  `json:"sans"` // Subject Alternative Names（DNS名・IPアドレス）
}

// SSLResult はTLS/SSL診断の総合結果を表します。
//
// ConnectError が nil でない場合はTLS接続自体に失敗しており、
// TLSVersion・CipherSuite・Cert は空/nil になります。
type SSLResult struct {
	Host         string       `json:"host"`
	Port         string       `json:"port"`
	ScannedAt    time.Time    `json:"scanned_at"`
	TLSVersion   string       `json:"tls_version"`
	CipherSuite  string       `json:"cipher_suite"`
	Cert         *CertInfo    `json:"cert,omitempty"`
	Findings     []SSLFinding `json:"findings"`
	ResponseTime int64        `json:"response_time_ms"`
	ConnectError *msg.Message `json:"connect_error,omitempty"` // TLS接続失敗時のメッセージ
}

// CheckSSL は指定ホストにTLS接続を確立し、セキュリティ診断を行います。
//
// 以下の項目を検査します:
//   - TLSバージョン（1.0/1.1は非推奨、1.3が最良）
//   - 暗号スイート（RC4・DES・3DESなど弱い暗号の検出）
//   - 証明書の有効期限（残り日数に応じてcritical/high/warningを付与）
//   - 自己署名証明書の検出
//   - ホスト名と証明書CN/SANの一致確認
//   - 公開鍵アルゴリズム（RSA/ECDSA）の情報提供
//   - TLS 1.0/1.1 受け入れ有無のベストエフォート確認（[checkLegacyTLS]）
//
// port が空の場合は "443" を使用します。
// TLS接続自体に失敗した場合もエラーは返さず、ConnectError フィールドに格納した結果を返します。
func CheckSSL(ctx context.Context, host, port string) (*SSLResult, error) {
	if port == "" {
		port = "443"
	}
	start := time.Now()
	findings := []SSLFinding{}

	// Try modern TLS first
	dialer := &tls.Dialer{
		NetDialer: safehttp.NewDialer(scanTimeout),
		// 古いTLSしか話せないサーバーの設定を「診断して報告する」のが目的なので、
		// ここで MinVersion を上げて接続を拒否すると、本来検出したい問題が見えなくなる。
		Config: &tls.Config{ //nolint:gosec // G402: 診断対象に接続するための意図的な MinVersion
			ServerName:         host,
			InsecureSkipVerify: false,
			MinVersion:         tls.VersionTLS10,
		},
	}

	rawConn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		// Go のエラー文字列は翻訳対象外とし、パラメータとしてそのまま埋め込む。
		connectError := msg.P(msg.SSLConnectError, "error", err.Error())
		return &SSLResult{
			Host:         host,
			Port:         port,
			ScannedAt:    time.Now(),
			ConnectError: &connectError,
			ResponseTime: time.Since(start).Milliseconds(),
		}, nil
	}
	conn := rawConn.(*tls.Conn)
	defer func() { _ = conn.Close() }()

	state := conn.ConnectionState()
	elapsed := time.Since(start).Milliseconds()

	// TLS version
	tlsVersion := tlsVersionName(state.Version)
	switch state.Version {
	case tls.VersionTLS10, tls.VersionTLS11:
		findings = append(findings, SSLFinding{
			Severity:    "high",
			Title:       msg.P(msg.SSLLegacyTLSTitle, "version", tlsVersion),
			Description: msg.M(msg.SSLLegacyTLSDesc),
		})
	case tls.VersionTLS12:
		findings = append(findings, SSLFinding{
			Severity:    "info",
			Title:       msg.M(msg.SSLTLS12Title),
			Description: msg.M(msg.SSLTLS12Desc),
		})
	case tls.VersionTLS13:
		findings = append(findings, SSLFinding{
			Severity:    "info",
			Title:       msg.M(msg.SSLTLS13Title),
			Description: msg.M(msg.SSLTLS13Desc),
		})
	}

	// Cipher suite
	cipherName := tls.CipherSuiteName(state.CipherSuite)
	if isWeakCipher(cipherName) {
		findings = append(findings, SSLFinding{
			Severity:    "high",
			Title:       msg.P(msg.SSLWeakCipherTitle, "cipher", cipherName),
			Description: msg.M(msg.SSLWeakCipherDesc),
		})
	}

	// Certificate
	var certInfo *CertInfo
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		daysLeft := int(time.Until(cert.NotAfter).Hours() / 24)
		selfSigned := cert.Subject.CommonName == cert.Issuer.CommonName

		sans := cert.DNSNames
		for _, ip := range cert.IPAddresses {
			sans = append(sans, ip.String())
		}

		certInfo = &CertInfo{
			Subject:    cert.Subject.CommonName,
			Issuer:     cert.Issuer.CommonName,
			NotBefore:  cert.NotBefore,
			NotAfter:   cert.NotAfter,
			DaysLeft:   daysLeft,
			SelfSigned: selfSigned,
			SANs:       sans,
		}

		if selfSigned {
			findings = append(findings, SSLFinding{
				Severity:    "high",
				Title:       msg.M(msg.SSLSelfSignedTitle),
				Description: msg.M(msg.SSLSelfSignedDesc),
			})
		}

		switch {
		case daysLeft < 0:
			findings = append(findings, SSLFinding{
				Severity:    "critical",
				Title:       msg.M(msg.SSLCertExpiredTitle),
				Description: msg.P(msg.SSLCertExpiredDesc, "count", -daysLeft),
			})
		case daysLeft < 14:
			findings = append(findings, SSLFinding{
				Severity:    "critical",
				Title:       msg.P(msg.SSLCertExpiringCriticalTitle, "count", daysLeft),
				Description: msg.M(msg.SSLCertExpiringCriticalDesc),
			})
		case daysLeft < 30:
			findings = append(findings, SSLFinding{
				Severity:    "high",
				Title:       msg.P(msg.SSLCertExpiringHighTitle, "count", daysLeft),
				Description: msg.M(msg.SSLCertExpiringHighDesc),
			})
		case daysLeft < 60:
			findings = append(findings, SSLFinding{
				Severity:    "warning",
				Title:       msg.P(msg.SSLCertExpiringWarningTitle, "count", daysLeft),
				Description: msg.M(msg.SSLCertExpiringWarningDesc),
			})
		default:
			findings = append(findings, SSLFinding{
				Severity:    "info",
				Title:       msg.P(msg.SSLCertValidTitle, "count", daysLeft),
				Description: msg.P(msg.SSLCertValidDesc, "date", cert.NotAfter.Format("2006-01-02")),
			})
		}

		// Hostname match
		if err := cert.VerifyHostname(host); err != nil {
			findings = append(findings, SSLFinding{
				Severity:    "critical",
				Title:       msg.M(msg.SSLHostnameMismatchTitle),
				Description: msg.P(msg.SSLHostnameMismatchDesc, "host", host),
			})
		}

		// Weak key
		checkWeakKey(cert, &findings)
	}

	// Check TLS 1.0/1.1 separately (best-effort)
	checkLegacyTLS(ctx, host, port, &findings)

	return &SSLResult{
		Host:         host,
		Port:         port,
		ScannedAt:    time.Now(),
		TLSVersion:   tlsVersion,
		CipherSuite:  cipherName,
		Cert:         certInfo,
		Findings:     findings,
		ResponseTime: elapsed,
	}, nil
}

// tlsVersionName はTLSバージョン定数を人間が読みやすい文字列に変換します。
func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", v)
	}
}

// isWeakCipher は暗号スイート名に既知の弱い暗号アルゴリズムが含まれるかを判定します。
// RC4・DES・3DES・EXPORT・NULL・ANON・MD5 を弱いとみなします。
func isWeakCipher(name string) bool {
	weak := []string{"RC4", "DES", "3DES", "EXPORT", "NULL", "ANON", "MD5"}
	upper := strings.ToUpper(name)
	for _, w := range weak {
		if strings.Contains(upper, w) {
			return true
		}
	}
	return false
}

// checkWeakKey は証明書の公開鍵アルゴリズムを確認し、情報提供レベルの findings を追加します。
// Go の x509 パッケージの制限でRSA鍵長の直接取得が困難なため、現在は一般的な推奨事項を通知します。
func checkWeakKey(cert *x509.Certificate, findings *[]SSLFinding) {
	switch cert.PublicKeyAlgorithm {
	case x509.RSA:
		// x509 doesn't expose key size directly without type assertion
		// We'll flag a general info
		*findings = append(*findings, SSLFinding{
			Severity:    "info",
			Title:       msg.M(msg.SSLRSAKeyTitle),
			Description: msg.M(msg.SSLRSAKeyDesc),
		})
	case x509.ECDSA:
		*findings = append(*findings, SSLFinding{
			Severity:    "info",
			Title:       msg.M(msg.SSLECDSAKeyTitle),
			Description: msg.M(msg.SSLECDSAKeyDesc),
		})
	}
}

// checkLegacyTLS はサーバーが廃止済みのTLS 1.0/1.1を受け入れるかをベストエフォートで確認します。
// 接続成功＝レガシーバージョンを許容しているとみなし、high severity の finding を追加します。
// InsecureSkipVerify を使用しているため、証明書の検証は行いません。
func checkLegacyTLS(ctx context.Context, host, port string, findings *[]SSLFinding) {
	legacy := []struct {
		version uint16
		name    string
	}{
		{tls.VersionTLS10, "TLS 1.0"},
		{tls.VersionTLS11, "TLS 1.1"},
	}

	for _, l := range legacy {
		// 「サーバーが廃止済みプロトコルを受け入れるか」を確かめるのが目的なので、
		// 意図的に古いバージョンを指定し、証明書検証も省略する。
		// ここで見ているのはハンドシェイクの成否だけで、通信内容は一切読まない。
		dialer := &tls.Dialer{
			NetDialer: safehttp.NewDialer(legacyProbeTimeout),
			Config: &tls.Config{
				ServerName: host,
				// ハンドシェイクが成立するかどうかだけを見ており、通信内容は一切読まない。
				InsecureSkipVerify: true,      //nolint:gosec // G402: レガシーTLS受け入れ確認が目的
				MinVersion:         l.version, //nolint:gosec // G402: 同上
				MaxVersion:         l.version,
			},
		}
		conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
		if err == nil {
			_ = conn.Close()
			*findings = append(*findings, SSLFinding{
				Severity:    "high",
				Title:       msg.P(msg.SSLLegacyAcceptedTitle, "protocol", l.name),
				Description: msg.P(msg.SSLLegacyAcceptedDesc, "protocol", l.name),
			})
		}
	}
}
