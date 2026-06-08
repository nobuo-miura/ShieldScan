package handlers

import (
	"fmt"
	"net"
	"net/url"
)

// privateRanges はSSRF攻撃を防ぐためにブロックするIPアドレス範囲のリストです。
var privateRanges []*net.IPNet

func init() {
	blocks := []string{
		"127.0.0.0/8",    // loopback
		"10.0.0.0/8",     // private
		"172.16.0.0/12",  // private
		"192.168.0.0/16", // private
		"169.254.0.0/16", // link-local
		"0.0.0.0/8",      // unspecified
		"::1/128",        // IPv6 loopback
		"fc00::/7",       // IPv6 unique local
		"fe80::/10",      // IPv6 link-local
	}
	for _, b := range blocks {
		_, block, _ := net.ParseCIDR(b)
		privateRanges = append(privateRanges, block)
	}
}

// validateNoSSRF はURLのホストを名前解決し、プライベートアドレスや
// ループバックアドレスへのリクエストをブロックします。
// 解決されたIPがすべて安全な場合のみ nil を返します。
func validateNoSSRF(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return err
	}
	host := parsed.Hostname()

	addrs, err := net.LookupHost(host)
	if err != nil {
		return fmt.Errorf("failed to resolve host: %w", err)
	}

	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip == nil {
			continue
		}
		for _, block := range privateRanges {
			if block.Contains(ip) {
				return fmt.Errorf("requests to private/internal addresses are not allowed")
			}
		}
	}
	return nil
}
