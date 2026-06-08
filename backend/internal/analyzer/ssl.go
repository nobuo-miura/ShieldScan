// このファイルはTLS/SSL接続のセキュリティ診断機能を提供します。
// 実際にTLS接続を確立し、プロトコルバージョン・暗号スイート・証明書の状態を検査します。
package analyzer

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"
)

// SSLFinding はTLS/SSL診断で検出された1件の問題を表します。
type SSLFinding struct {
	Severity    string `json:"severity"` // "critical", "high", "warning", "info"
	Title       string `json:"title"`
	Description string `json:"description"`
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
// ConnectError が空でない場合はTLS接続自体に失敗しており、
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
	ConnectError string       `json:"connect_error,omitempty"` // TLS接続失敗時のエラーメッセージ
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
func CheckSSL(host, port string) (*SSLResult, error) {
	if port == "" {
		port = "443"
	}
	start := time.Now()
	findings := []SSLFinding{}

	// Try modern TLS first
	conf := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: false,
	}

	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 10 * time.Second},
		"tcp",
		net.JoinHostPort(host, port),
		conf,
	)
	if err != nil {
		return &SSLResult{
			Host:         host,
			Port:         port,
			ScannedAt:    time.Now(),
			ConnectError: err.Error(),
			ResponseTime: time.Since(start).Milliseconds(),
		}, nil
	}
	defer conn.Close()

	state := conn.ConnectionState()
	elapsed := time.Since(start).Milliseconds()

	// TLS version
	tlsVersion := tlsVersionName(state.Version)
	switch state.Version {
	case tls.VersionTLS10, tls.VersionTLS11:
		findings = append(findings, SSLFinding{
			Severity:    "high",
			Title:       fmt.Sprintf("古いTLSバージョン使用中: %s", tlsVersion),
			Description: "TLS 1.0/1.1は2020年にRFC 8996で廃止されました。TLS 1.2以上に移行してください。",
		})
	case tls.VersionTLS12:
		findings = append(findings, SSLFinding{
			Severity:    "info",
			Title:       "TLS 1.2 使用中",
			Description: "TLS 1.2は現在も安全ですが、TLS 1.3への移行でさらにセキュリティとパフォーマンスが向上します。",
		})
	case tls.VersionTLS13:
		findings = append(findings, SSLFinding{
			Severity:    "info",
			Title:       "TLS 1.3 ✓ 最新バージョン使用中",
			Description: "TLS 1.3は最新かつ最も安全なTLSバージョンです。",
		})
	}

	// Cipher suite
	cipherName := tls.CipherSuiteName(state.CipherSuite)
	if isWeakCipher(cipherName) {
		findings = append(findings, SSLFinding{
			Severity:    "high",
			Title:       fmt.Sprintf("脆弱な暗号スイート: %s", cipherName),
			Description: "RC4・DES・3DES・EXPORTなどの弱い暗号スイートは無効化してください。",
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
				Title:       "自己署名証明書",
				Description: "信頼された認証局（CA）が発行した証明書ではありません。本番環境では使用しないでください。",
			})
		}

		switch {
		case daysLeft < 0:
			findings = append(findings, SSLFinding{
				Severity:    "critical",
				Title:       "証明書が期限切れ",
				Description: fmt.Sprintf("証明書は%d日前に期限切れになりました。ブラウザは接続をブロックします。", -daysLeft),
			})
		case daysLeft < 14:
			findings = append(findings, SSLFinding{
				Severity:    "critical",
				Title:       fmt.Sprintf("証明書の期限まで %d日", daysLeft),
				Description: "証明書の更新が急務です。Let's Encryptなどで今すぐ更新してください。",
			})
		case daysLeft < 30:
			findings = append(findings, SSLFinding{
				Severity:    "high",
				Title:       fmt.Sprintf("証明書の期限まで %d日", daysLeft),
				Description: "30日以内に期限切れになります。早めに更新を行ってください。",
			})
		case daysLeft < 60:
			findings = append(findings, SSLFinding{
				Severity:    "warning",
				Title:       fmt.Sprintf("証明書の期限まで %d日", daysLeft),
				Description: "60日以内に期限切れになります。更新の準備を始めてください。",
			})
		default:
			findings = append(findings, SSLFinding{
				Severity:    "info",
				Title:       fmt.Sprintf("証明書有効期間: あと %d日", daysLeft),
				Description: fmt.Sprintf("証明書の有効期限: %s", cert.NotAfter.Format("2006-01-02")),
			})
		}

		// Hostname match
		if err := cert.VerifyHostname(host); err != nil {
			findings = append(findings, SSLFinding{
				Severity:    "critical",
				Title:       "ホスト名不一致",
				Description: fmt.Sprintf("証明書のCN/SANがホスト名 %q と一致しません。フィッシングや設定ミスの可能性があります。", host),
			})
		}

		// Weak key
		checkWeakKey(cert, &findings)
	}

	// Check TLS 1.0/1.1 separately (best-effort)
	checkLegacyTLS(host, port, &findings)

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
			Title:       "RSA公開鍵",
			Description: "RSA鍵は2048bit以上を推奨します。ECDSAへの移行でパフォーマンスも向上します。",
		})
	case x509.ECDSA:
		*findings = append(*findings, SSLFinding{
			Severity:    "info",
			Title:       "ECDSA公開鍵 ✓",
			Description: "ECDSAは効率的で安全な公開鍵アルゴリズムです。",
		})
	}
}

// checkLegacyTLS はサーバーが廃止済みのTLS 1.0/1.1を受け入れるかをベストエフォートで確認します。
// 接続成功＝レガシーバージョンを許容しているとみなし、high severity の finding を追加します。
// InsecureSkipVerify を使用しているため、証明書の検証は行いません。
func checkLegacyTLS(host, port string, findings *[]SSLFinding) {
	legacy := []struct {
		version uint16
		name    string
	}{
		{tls.VersionTLS10, "TLS 1.0"},
		{tls.VersionTLS11, "TLS 1.1"},
	}

	for _, l := range legacy {
		conf := &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: true,
			MinVersion:         l.version,
			MaxVersion:         l.version,
		}
		conn, err := tls.DialWithDialer(
			&net.Dialer{Timeout: 5 * time.Second},
			"tcp",
			net.JoinHostPort(host, port),
			conf,
		)
		if err == nil {
			conn.Close()
			*findings = append(*findings, SSLFinding{
				Severity:    "high",
				Title:       fmt.Sprintf("%s を受け入れています", l.name),
				Description: fmt.Sprintf("%sは廃止済みのプロトコルです。サーバー設定で無効化してください。", l.name),
			})
		}
	}
}
