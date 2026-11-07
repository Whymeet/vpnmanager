package service

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"vpnlock/internal/dnswatch"
)

// Поток ответов с разными именами на один адрес не раздувает кэш: у адреса не
// больше maxAddrNames имён, новое вытесняет самое старое, а старое забывается.
func TestNameCacheIsBounded(t *testing.T) {
	var c nameCache
	addr := netip.MustParseAddr("104.18.0.7")
	start := time.Now()
	for i := range 1000 {
		c.add(dnswatch.Answer{Name: fmt.Sprintf("n%d.example.com", i), Addrs: []netip.Addr{addr}}, start.Add(time.Duration(i)*time.Millisecond))
	}
	now := start.Add(time.Second)
	got := c.of(addr, start)
	if len(got) != maxAddrNames || got[0] != "n984.example.com" {
		t.Fatalf("%d имён: %v", len(got), got)
	}
	c.add(dnswatch.Answer{Name: "fresh.example.com", Addrs: []netip.Addr{netip.MustParseAddr("203.0.113.9")}}, now.Add(nameTTL+time.Second))
	if len(c.by) != 1 {
		t.Fatalf("старое не забылось: %d адресов", len(c.by))
	}
}
