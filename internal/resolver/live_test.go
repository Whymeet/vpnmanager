//go:build live && darwin

// Живая проверка источников резолвера: tools/go test -tags live -v ./internal/resolver

package resolver

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"

	"appguard/internal/netwatch"
)

func TestLiveUpstreams(t *testing.T) {
	physical := func() (int, bool) {
		_, index, ok := netwatch.Physical()
		return index, ok
	}
	for _, u := range []Upstream{
		NewDoH("Cloudflare", "https://1.1.1.1/dns-query", 3*time.Second),
		NewDoH("Google", "https://8.8.8.8/dns-query", 3*time.Second),
		&Plain{Label: "Яндекс через физический интерфейс", Addr: "77.88.8.8:53", Iface: physical, Timeout: 2 * time.Second},
	} {
		q := withoutClientSubnet(query("www.notion.so", dns.TypeA))
		start := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		ans, err := u.Exchange(ctx, q)
		cancel()
		if err != nil {
			t.Errorf("%s: %v", u.Name(), err)
			continue
		}
		t.Logf("%s за %v: %v", u.Name(), time.Since(start).Round(time.Millisecond), Addrs(ans))
		if len(Addrs(ans)) == 0 {
			t.Errorf("%s: нет адресов", u.Name())
		}
	}
}
