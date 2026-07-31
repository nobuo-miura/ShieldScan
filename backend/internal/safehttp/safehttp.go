// Package safehttp は外部ホストへスキャンリクエストを送るための、
// SSRF に耐性のある HTTP クライアントとダイヤラーを提供します。
//
// ShieldScan はユーザーが指定した任意のURLへサーバー側からリクエストを送る、
// いわゆる SSRF の温床になりやすい設計です。そのため本パッケージは
// 「事前に名前解決して検査する」だけの防御は採用していません。
// 事前検査は攻撃者が短TTLのDNSレコードを切り替える DNS rebinding で回避できるためです。
//
// 実際の防御は [net.Dialer.Control] フックが担います。Control は TCP 接続を
// 確立する直前に、そのとき実際に接続しようとしている解決済みIPアドレスを
// 受け取ります。ここで拒否すればリダイレクト先だろうと rebinding 後だろうと、
// 内部アドレスへのパケットは1バイトも出ていきません。
//
// [ValidateURL] による事前検査は防御の主体ではなく、
// 利用者に分かりやすいエラーを早く返すための補助です。
package safehttp

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"syscall"
	"time"
)

// ErrBlockedAddress は内部・プライベートアドレスへの接続を拒否したことを表します。
// [errors.Is] で判定できます。
var ErrBlockedAddress = errors.New("requests to private/internal addresses are not allowed")

// allowPrivateEnv はプライベートアドレスへの接続を許可する環境変数名です。
// ローカル開発で localhost をスキャンしたい場合にのみ使用してください。
// 公開インスタンスで有効にすると SSRF 防御が完全に無効になります。
const allowPrivateEnv = "SHIELDSCAN_ALLOW_PRIVATE"

// blockedCIDRs は net.IP の標準判定メソッドでは拾えない特殊用途アドレス範囲です。
// ループバック・プライベート・リンクローカル・未指定アドレスは
// [net.IP] のメソッドで判定するためここには含めません。
var blockedCIDRs = []string{
	"100.64.0.0/10",   // CGNAT (RFC 6598)
	"192.0.0.0/24",    // IETF プロトコル割り当て
	"192.0.2.0/24",    // TEST-NET-1
	"198.18.0.0/15",   // ベンチマーク用 (RFC 2544)
	"198.51.100.0/24", // TEST-NET-2
	"203.0.113.0/24",  // TEST-NET-3
	"240.0.0.0/4",     // 予約済み (クラスE)
	"2001:db8::/32",   // ドキュメント用 IPv6
	"64:ff9b::/96",    // NAT64 well-known prefix (RFC 6052)
	// NAT64 local-use prefix (RFC 8215)。well-known prefix とは別レンジで、
	// net.IP のどの判定メソッドにも掛からない。NAT64 環境ではこの範囲経由で
	// 内部IPv4アドレスに到達できてしまうため /48 全体を拒否する。
	"64:ff9b:1::/48",
}

var blockedNets []*net.IPNet

func init() {
	for _, c := range blockedCIDRs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			// blockedCIDRs はコンパイル時定数なので、ここに来るのはプログラムのバグ。
			panic(fmt.Sprintf("safehttp: invalid CIDR %q: %v", c, err))
		}
		blockedNets = append(blockedNets, n)
	}
}

// allowPrivate は環境変数でプライベートアドレスへの接続が明示的に
// 許可されているかを返します。
func allowPrivate() bool {
	v, err := strconv.ParseBool(os.Getenv(allowPrivateEnv))
	return err == nil && v
}

// IsBlockedIP はそのIPアドレスへの接続を拒否すべきかを返します。
//
// ループバック・プライベート・リンクローカル・マルチキャスト・未指定アドレスに加え、
// CGNAT やドキュメント用など特殊用途に予約された範囲も拒否します。
// nil や解釈不能なアドレスは安全側に倒して拒否します。
func IsBlockedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if allowPrivate() {
		return false
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsInterfaceLocalMulticast() {
		return true
	}
	// IPv4射影アドレス (::ffff:169.254.169.254) を IPv4 として正規化してから照合する。
	// これを怠ると IPv6 表記で内部アドレスに到達できてしまう。
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	for _, n := range blockedNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// control は接続直前に呼ばれ、実際の接続先IPを検査します。
// address は名前解決済みの "IP:port" 形式であることが保証されています。
func control(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("safehttp: cannot parse dial address %q: %w", address, err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("safehttp: unresolvable dial address %q", address)
	}
	if IsBlockedIP(ip) {
		return fmt.Errorf("%w (%s)", ErrBlockedAddress, ip)
	}
	return nil
}

// NewDialer は接続直前にIPアドレスを検査するダイヤラーを返します。
// TLS接続を直接張る場合（[crypto/tls.DialWithDialer] など）はこれを使ってください。
func NewDialer(timeout time.Duration) *net.Dialer {
	return &net.Dialer{
		Timeout: timeout,
		Control: control,
	}
}

// NewClient はSSRF保護付きの [http.Client] を返します。
//
// maxRedirects 回を超えるリダイレクトはエラーになります。リダイレクト先も
// スキーム検査を受け、接続時には改めて [control] によるIP検査が走ります。
//
// プロキシは意図的に無効化しています。プロキシ経由になると実際のTCP接続先が
// プロキシサーバーになり、Control フックがスキャン対象のIPを検査できなくなるためです。
func NewClient(timeout time.Duration, maxRedirects int) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy:                 nil, // 上記の理由により環境変数プロキシを使わない
			DialContext:           NewDialer(timeout).DialContext,
			TLSHandshakeTimeout:   timeout,
			ResponseHeaderTimeout: timeout,
			TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return fmt.Errorf("too many redirects (>%d)", maxRedirects)
			}
			return checkScheme(req.URL)
		},
	}
}

// checkScheme は http/https 以外のスキームを拒否します。
// file:// や gopher:// へのリダイレクトを塞ぐためのものです。
func checkScheme(u *url.URL) error {
	switch u.Scheme {
	case "http", "https":
		return nil
	default:
		return fmt.Errorf("unsupported URL scheme %q", u.Scheme)
	}
}

// ValidateURL はスキャン対象URLを検証します。
//
// スキームが http/https であること、ホストが存在すること、
// 名前解決結果に内部アドレスが含まれないことを確認します。
//
// これは利用者へ早く分かりやすいエラーを返すための事前チェックであり、
// SSRF 防御の主体ではありません（[NewClient] の Control フックが本命です）。
// この検査を通過したURLでも、接続時に内部アドレスに解決されれば拒否されます。
func ValidateURL(ctx context.Context, rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	if err := checkScheme(u); err != nil {
		return err
	}
	if u.Hostname() == "" {
		return errors.New("URL has no host")
	}
	return ValidateHost(ctx, u.Hostname())
}

// ValidateHost はホスト名（またはIPリテラル）を名前解決し、
// 内部アドレスに解決されないことを確認します。
// [ValidateURL] と同じく事前チェック用です。
func ValidateHost(ctx context.Context, host string) error {
	if host == "" {
		return errors.New("host is required")
	}
	if ip := net.ParseIP(host); ip != nil {
		if IsBlockedIP(ip) {
			return fmt.Errorf("%w (%s)", ErrBlockedAddress, ip)
		}
		return nil
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return fmt.Errorf("failed to resolve host: %w", err)
	}
	if len(addrs) == 0 {
		return fmt.Errorf("failed to resolve host: %s", host)
	}
	for _, addr := range addrs {
		if IsBlockedIP(addr.IP) {
			return fmt.Errorf("%w (%s)", ErrBlockedAddress, addr.IP)
		}
	}
	return nil
}
