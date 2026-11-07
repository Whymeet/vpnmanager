package resolver

import (
	"net"
	"net/netip"
	"net/url"
	"time"
)

// Вышестоящие DNS по умолчанию. Шифрованный (DoH) — по адресам, чтобы самому
// DoH не нужен был DNS: ответ программе идёт отсюда. Российский (Яндекс) —
// обычный DNS через физический интерфейс, мимо VPN: он называет узлы сервиса
// внутри России, и их адреса только закрываются. Адреса отсюда нельзя учить
// как адреса сервисов — это проверяет тест в пакете learn.
var (
	primary = []struct{ label, url string }{
		{"Cloudflare", "https://1.1.1.1/dns-query"},
		{"Google", "https://8.8.8.8/dns-query"},
	}
	russian = []struct{ label, addr string }{
		{"Яндекс", "77.88.8.8:53"},
		{"Яндекс", "77.88.8.1:53"},
	}
)

// Defaults — вышестоящие DNS службы. physical называет физический интерфейс
// сейчас — для российского DNS.
func Defaults(physical func() (index int, ok bool)) Upstreams {
	var up Upstreams
	for _, p := range primary {
		up.Primary = append(up.Primary, NewDoH(p.label, p.url, 3*time.Second))
	}
	for _, r := range russian {
		up.Russian = append(up.Russian, &Plain{Label: r.label, Addr: r.addr, Iface: physical, Timeout: time.Second})
	}
	return up
}

// FixedAddrs — адреса, к которым резолвер ходит сам.
func FixedAddrs() []netip.Addr {
	var out []netip.Addr
	for _, p := range primary {
		if u, err := url.Parse(p.url); err == nil {
			if a, err := netip.ParseAddr(u.Hostname()); err == nil {
				out = append(out, a)
			}
		}
	}
	for _, r := range russian {
		if host, _, err := net.SplitHostPort(r.addr); err == nil {
			if a, err := netip.ParseAddr(host); err == nil {
				out = append(out, a)
			}
		}
	}
	return out
}
