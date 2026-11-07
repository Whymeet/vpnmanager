package learn

import (
	"net/netip"
	"testing"
)

func TestAcceptable(t *testing.T) {
	for _, tc := range []struct {
		addr string
		port uint16
		want bool
		why  string
	}{
		{"104.18.0.1", 443, true, "обычный адрес сервиса"},
		{"2606:4700::6812:1", 443, true, "обычный IPv6"},
		{"::ffff:104.18.0.1", 443, true, "IPv4 в записи IPv6"},
		{"203.0.113.5", 443, true, "публичный адрес"},
		{"127.0.0.1", 8080, false, "локальный прокси"},
		{"::1", 8080, false, "локальный прокси по IPv6"},
		{"10.8.1.1", 443, false, "частная сеть"},
		{"172.16.5.5", 443, false, "частная сеть"},
		{"192.168.68.1", 443, false, "домашний роутер"},
		{"fd12:3456::1", 443, false, "частная сеть IPv6"},
		{"169.254.10.10", 443, false, "link-local"},
		{"fe80::1", 443, false, "link-local IPv6"},
		{"224.0.0.251", 5353, false, "multicast"},
		{"ff02::fb", 5353, false, "multicast IPv6"},
		{"100.100.100.100", 443, false, "общий NAT провайдера"},
		{"198.18.0.5", 443, false, "фиктивный адрес клиента VPN"},
		{"198.19.255.1", 443, false, "фиктивный адрес клиента VPN"},
		{"255.255.255.255", 443, false, "broadcast"},
		{"0.0.0.0", 443, false, "не адрес"},
		{"104.18.0.1", 53, false, "порт DNS"},
		{"104.18.0.1", 853, false, "порт DNS-over-TLS"},
		{"1.1.1.1", 443, false, "DoH Cloudflare — нужен проверке выхода"},
		{"1.0.0.1", 443, false, "второй адрес Cloudflare"},
		{"8.8.8.8", 443, false, "DoH Google — нужен резолверу"},
		{"77.88.8.8", 443, false, "российский DNS — нужен резолверу"},
		{"2606:4700:4700::1111", 443, false, "Cloudflare по IPv6"},
	} {
		if got := Acceptable(netip.MustParseAddr(tc.addr), tc.port); got != tc.want {
			t.Errorf("%s:%d (%s): %v, ждали %v", tc.addr, tc.port, tc.why, got, tc.want)
		}
	}
	if Acceptable(netip.Addr{}, 443) {
		t.Error("пустой адрес принят")
	}
}
