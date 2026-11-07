package netwatch

import (
	"fmt"
	"net/netip"
	"testing"
)

func TestParseWinProxy(t *testing.T) {
	resolve := func(host string) []netip.Addr {
		if a, err := netip.ParseAddr(host); err == nil {
			return []netip.Addr{a}
		}
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}
	}
	for _, tc := range []struct {
		server string
		want   []string // схема адрес:порт
	}{
		{"127.0.0.1:7890", []string{"http 127.0.0.1:7890"}},
		{"http=127.0.0.1:7890;https=127.0.0.1:7890", []string{"http 127.0.0.1:7890"}},
		// Смешанный порт — один путь, по HTTP.
		{"socks=127.0.0.1:2080;http=127.0.0.1:2080", []string{"http 127.0.0.1:2080"}},
		{"http=127.0.0.1:7890;socks=127.0.0.1:7891;ftp=127.0.0.1:21", []string{"http 127.0.0.1:7890", "socks5 127.0.0.1:7891"}},
		{"http://localhost:8080", []string{"http localhost:8080"}},
		{"[::1]:7890", []string{"http ::1:7890"}},
		{"", nil},
		{"просто текст;127.0.0.1:0;:80", nil},
	} {
		got := parseWinProxy(tc.server, resolve)
		var list []string
		for _, p := range got {
			list = append(list, fmt.Sprintf("%s %s:%d", p.Scheme, p.Host, p.Port))
			if len(p.Addrs) == 0 {
				t.Errorf("%q: у %s нет адресов", tc.server, p.Host)
			}
		}
		if len(list) != len(tc.want) {
			t.Errorf("%q → %v, ждали %v", tc.server, list, tc.want)
			continue
		}
		for i := range list {
			if list[i] != tc.want[i] {
				t.Errorf("%q → %v, ждали %v", tc.server, list, tc.want)
			}
		}
	}
}
