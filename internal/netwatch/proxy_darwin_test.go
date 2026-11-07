package netwatch

import (
	"net/netip"
	"slices"
	"testing"
	"time"

	"vpnlock/internal/core"
)

// Вывод `scutil --proxy` у клиента вроде ClashX: HTTP и HTTPS на одном порту,
// SOCKS — на соседнем; внутри __SCOPED__ — то же по интерфейсам.
const clashX = `<dictionary> {
  ExceptionsList : <array> {
    0 : 127.0.0.1
    1 : localhost
  }
  ExcludeSimpleHostnames : 1
  FTPPassive : 1
  HTTPEnable : 1
  HTTPPort : 7890
  HTTPProxy : 127.0.0.1
  HTTPSEnable : 1
  HTTPSPort : 7890
  HTTPSProxy : 127.0.0.1
  SOCKSEnable : 1
  SOCKSPort : 7891
  SOCKSProxy : 127.0.0.1
  __SCOPED__ : <dictionary> {
    en0 : <dictionary> {
      HTTPEnable : 1
      HTTPPort : 9999
      HTTPProxy : 10.0.0.1
    }
  }
}
`

func TestProxiesFromScutil(t *testing.T) {
	got := parseProxies([]byte(clashX), resolveHost)
	lo := []netip.Addr{netip.MustParseAddr("127.0.0.1")}
	want := []core.Proxy{
		{Scheme: "http", Host: "127.0.0.1", Port: 7890, Addrs: lo},
		{Scheme: "socks5", Host: "127.0.0.1", Port: 7891, Addrs: lo},
	}
	if !slices.EqualFunc(got, want, func(a, b core.Proxy) bool {
		return a.Scheme == b.Scheme && a.Host == b.Host && a.Port == b.Port && slices.Equal(a.Addrs, b.Addrs)
	}) {
		t.Fatalf("%+v", got)
	}
}

// Смешанный порт (Hiddify, Clash Verge): один прокси, с ним говорим по HTTP.
func TestMixedPortIsOneProxy(t *testing.T) {
	out := `<dictionary> {
  HTTPEnable : 1
  HTTPPort : 12334
  HTTPProxy : localhost
  SOCKSEnable : 1
  SOCKSPort : 12334
  SOCKSProxy : localhost
}`
	got := parseProxies([]byte(out), resolveHost)
	if len(got) != 1 || got[0].Scheme != "http" || got[0].Endpoint() != "localhost:12334" ||
		!slices.Equal(got[0].Addrs, []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.IPv6Loopback()}) {
		t.Fatalf("%+v", got)
	}
}

func TestNoProxyWhenDisabled(t *testing.T) {
	out := `<dictionary> {
  FTPPassive : 1
  HTTPEnable : 0
  HTTPPort : 7890
  HTTPProxy : 127.0.0.1
  SOCKSEnable : 1
  SOCKSProxy : 127.0.0.1
}`
	if got := parseProxies([]byte(out), resolveHost); len(got) != 0 {
		t.Fatalf("выключенный прокси или прокси без порта: %+v", got)
	}
}

func TestListenerIsRemembered(t *testing.T) {
	now := time.Unix(0, 0)
	asked := 0
	l := &listeners{look: func(uint16) string { asked++; return "Hiddify" }, now: func() time.Time { return now }}
	l.of(12334)
	l.of(12334)
	if asked != 1 {
		t.Fatalf("lsof спрошен %d раз подряд", asked)
	}
	now = now.Add(listenerTTL)
	if l.of(12334) != "Hiddify" || asked != 2 {
		t.Fatalf("процесс не перепроверен после %v", listenerTTL)
	}
}
