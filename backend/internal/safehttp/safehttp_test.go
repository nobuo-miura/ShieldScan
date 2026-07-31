package safehttp

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestIsBlockedIP(t *testing.T) {
	tests := []struct {
		ip      string
		blocked bool
	}{
		// ループバック
		{"127.0.0.1", true},
		{"127.255.255.254", true},
		{"::1", true},
		// プライベート
		{"10.0.0.1", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"192.168.1.1", true},
		{"fd00::1", true},
		// リンクローカル（クラウドのメタデータエンドポイント）
		{"169.254.169.254", true},
		{"fe80::1", true},
		// IPv4射影アドレスによる迂回
		{"::ffff:127.0.0.1", true},
		{"::ffff:169.254.169.254", true},
		{"::ffff:10.0.0.1", true},
		// 未指定・マルチキャスト
		{"0.0.0.0", true},
		{"::", true},
		{"224.0.0.1", true},
		// 特殊用途
		{"100.64.0.1", true},  // CGNAT
		{"198.18.0.1", true},  // ベンチマーク
		{"240.0.0.1", true},   // クラスE
		{"2001:db8::1", true}, // ドキュメント用
		// NAT64。well-known prefix (RFC 6052) と local-use prefix (RFC 8215) は
		// 別レンジなので両方を確認する。後者は net.IP のどの判定にも掛からない。
		{"64:ff9b::7f00:1", true},   // 127.0.0.1 を well-known prefix で変換
		{"64:ff9b:1::a00:1", true},  // 10.0.0.1 を local-use prefix で変換
		{"64:ff9b:1:ffff::1", true}, // local-use prefix の /48 末尾側
		{"64:ff9c::1", false},       // 隣接するがNAT64ではない

		{"172.32.0.1", false},     // 172.16/12 の直後、プライベートではない
		{"172.15.255.255", false}, // 172.16/12 の直前
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"2606:4700:4700::1111", false},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("テストデータが不正: %q をIPとして解釈できません", tt.ip)
			}
			if got := IsBlockedIP(ip); got != tt.blocked {
				t.Errorf("IsBlockedIP(%s) = %v, want %v", tt.ip, got, tt.blocked)
			}
		})
	}
}

func TestIsBlockedIPNil(t *testing.T) {
	// 解釈できないアドレスは安全側に倒して拒否する
	if !IsBlockedIP(nil) {
		t.Error("IsBlockedIP(nil) = false, want true")
	}
}

// TestClientBlocksLoopback は Control フックが実際に Transport に組み込まれ、
// 内部アドレスへのTCP接続が成立しないことを確認します。
// httptest サーバーは必ずループバックで待ち受けるため、ここへの接続が
// 失敗すれば防御が効いていることの証明になります。
func TestClientBlocksLoopback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	_, err := NewClient(5*time.Second, 5).Get(srv.URL)
	if err == nil {
		t.Fatal("ループバックへの接続が成功してしまいました。SSRF保護が効いていません")
	}
	if !errors.Is(err, ErrBlockedAddress) {
		t.Errorf("err = %v, ErrBlockedAddress でラップされているべきです", err)
	}
}

// TestClientAllowsPrivateWhenOptedIn は、環境変数による明示的な opt-in で
// ローカル開発向けにプライベートアドレスへ接続できることを確認します。
// 同時に、保護以外の部分（通常のGET）が正しく動くことの確認も兼ねています。
func TestClientAllowsPrivateWhenOptedIn(t *testing.T) {
	t.Setenv(allowPrivateEnv, "true")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	resp, err := NewClient(5*time.Second, 5).Get(srv.URL)
	if err != nil {
		t.Fatalf("opt-in 時にも接続できませんでした: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

// TestClientRejectsRedirectToNonHTTPScheme は file:// などへのリダイレクトを
// 拒否することを確認します。
func TestClientRejectsRedirectToNonHTTPScheme(t *testing.T) {
	t.Setenv(allowPrivateEnv, "true") // httptest はループバックで待ち受けるため

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "file:///etc/passwd", http.StatusFound)
	}))
	defer srv.Close()

	resp, err := NewClient(5*time.Second, 5).Get(srv.URL)
	if err == nil {
		resp.Body.Close()
		t.Fatal("file:// へのリダイレクトが追跡されてしまいました")
	}
}

// TestClientLimitsRedirects はリダイレクトループが無限に追跡されないことを確認します。
func TestClientLimitsRedirects(t *testing.T) {
	t.Setenv(allowPrivateEnv, "true")

	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, srv.URL, http.StatusFound)
	}))
	defer srv.Close()

	resp, err := NewClient(5*time.Second, 3).Get(srv.URL)
	if err == nil {
		resp.Body.Close()
		t.Fatal("リダイレクトループが打ち切られませんでした")
	}
}

func TestValidateURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{"ループバック", "http://127.0.0.1/", true},
		{"IPv6ループバック", "http://[::1]/", true},
		{"メタデータエンドポイント", "http://169.254.169.254/latest/meta-data/", true},
		{"IPv4射影での迂回", "http://[::ffff:127.0.0.1]/", true},
		{"プライベートアドレス", "https://10.1.2.3/", true},
		{"fileスキーム", "file:///etc/passwd", true},
		{"gopherスキーム", "gopher://127.0.0.1:11211/", true},
		{"ホストなし", "https://", true},
		{"公開アドレス", "https://1.1.1.1/", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateURL(t.Context(), tt.url)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateURL(%q) err = %v, wantErr %v", tt.url, err, tt.wantErr)
			}
		})
	}
}

func TestValidateHost(t *testing.T) {
	if err := ValidateHost(t.Context(), ""); err == nil {
		t.Error("空ホストがエラーになりませんでした")
	}
	if err := ValidateHost(t.Context(), "127.0.0.1"); !errors.Is(err, ErrBlockedAddress) {
		t.Errorf("ValidateHost(127.0.0.1) err = %v, ErrBlockedAddress を期待", err)
	}
	if err := ValidateHost(t.Context(), "1.1.1.1"); err != nil {
		t.Errorf("ValidateHost(1.1.1.1) err = %v, want nil", err)
	}
}
