package enforce

import (
	"maps"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

func addrs(s ...string) []netip.Addr {
	out := make([]netip.Addr, len(s))
	for i, a := range s {
		out[i] = netip.MustParseAddr(a)
	}
	return out
}

func TestRulesetClosed(t *testing.T) {
	text := ruleset(Rules{V4: addrs("160.79.104.10", "1.2.3.4"), V6: addrs("2606:4700::1")}, found{})
	for _, want := range []string{
		"delete table inet appguard",
		"elements = { 1.2.3.4, 160.79.104.10 }",
		"elements = { 2606:4700::1 }",
		"meta cgroup 1447840513 jump app",
		"ip daddr @addrs4 drop",
		"ip6 daddr @addrs6 drop",
		"reject with icmpx admin-prohibited",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("нет %q в правилах:\n%s", want, text)
		}
	}
	if strings.Contains(text, "accept\n\t\tip daddr @addrs4") || strings.Contains(text, `oifname {`) {
		t.Errorf("закрытые правила ничего не открывают:\n%s", text)
	}
}

func TestRulesetOpensOnlyVerifiedTunnels(t *testing.T) {
	text := ruleset(Rules{OpenIfaces: []string{"wg0", "tun 0\"; accept #", "mullvad-se1"}, V4: addrs("1.2.3.4")}, found{})
	if got := strings.Count(text, `oifname { "mullvad-se1", "wg0" } accept`); got != 2 {
		t.Errorf("туннель открывается и приложениям, и адресам сервисов, а получилось %d раз:\n%s", got, text)
	}
	if strings.Contains(text, "tun 0") {
		t.Errorf("имя интерфейса с посторонними знаками в правила не попадает:\n%s", text)
	}
}

func TestRulesetVPNServerOnCDN(t *testing.T) {
	text := ruleset(Rules{V4: addrs("1.2.3.4"), V6: addrs("2606:4700::1"), Servers: addrs("1.2.3.4", "2606:4700::1"), Physical: "eth0"}, found{})
	for _, want := range []string{`oifname "eth0" ip daddr { 1.2.3.4 } accept`, `oifname "eth0" ip6 daddr { 2606:4700::1 } accept`} {
		if !strings.Contains(text, want) {
			t.Errorf("нет %q:\n%s", want, text)
		}
	}
	guard, _, _ := strings.Cut(text, "chain app")
	if strings.Index(guard, "accept") > strings.Index(guard, "drop") {
		t.Errorf("разрешение серверу идёт раньше запрета адреса:\n%s", guard)
	}
}

func TestRulesetLocalDNS(t *testing.T) {
	text := ruleset(Rules{}, found{dns: addrs("192.168.1.1", "fd00::1")})
	for _, want := range []string{
		"ip daddr { 192.168.1.1 } meta l4proto { tcp, udp } th dport 53 accept",
		"ip6 daddr { fd00::1 } meta l4proto { tcp, udp } th dport 53 accept",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("нет %q:\n%s", want, text)
		}
	}
}

// WireGuard в ядре сохраняет у внешнего пакета сокет приложения с меткой группы:
// порт туннеля обязан проверяться раньше неё, и пути на это не влияют — иначе туннель
// не поднялся бы и для первой проверки выхода.
func TestRulesetLetsKernelTunnelOutBeforeTheMark(t *testing.T) {
	text := ruleset(Rules{}, found{ports: []uint16{4789, 51820}})
	port, mark := strings.Index(text, "udp sport { 4789, 51820 } accept"), strings.Index(text, "meta cgroup")
	if port < 0 || port > mark {
		t.Errorf("порт туннеля не раньше метки:\n%s", text)
	}
	if strings.Contains(ruleset(Rules{}, found{}), "sport") {
		t.Error("пустой набор портов nft не примет")
	}
}

func TestParseLocalDNS(t *testing.T) {
	got := parseLocalDNS([]byte("# comment\nnameserver 127.0.0.53\nnameserver 192.168.1.1\nnameserver 8.8.8.8\nnameserver fe80::1%eth0\nsearch lan\n"))
	if !slices.Equal(got, addrs("192.168.1.1", "fe80::1")) {
		t.Errorf("%v", got)
	}
}

func TestTallyOwnTextMatchesNftOutput(t *testing.T) {
	r := Rules{OpenIfaces: []string{"wg0"}, V4: addrs("1.2.3.4", "1.2.3.5", "1.2.3.6"), Servers: addrs("1.2.3.4"), Physical: "eth0"}
	// Вывод `nft list table inet appguard` с настоящего ядра: nft разворачивает набор
	// из одного имени и переносит элементы по строкам.
	const listed = `table inet appguard {
	set addrs4 {
		type ipv4_addr
		elements = { 1.2.3.4, 1.2.3.5,
			     1.2.3.6 }
	}

	set addrs6 {
		type ipv6_addr
	}

	chain guard {
		oifname "wg0" accept
		oifname "eth0" ip daddr 1.2.3.4 accept
		ip daddr @addrs4 drop
		ip6 daddr @addrs6 drop
	}

	chain app {
		oifname "lo" accept
		oifname "wg0" accept
		reject with icmpx admin-prohibited
	}

	chain output {
		type filter hook output priority filter - 10; policy accept;
		meta cgroup 1447840513 jump app
		jump guard
	}

	chain forward {
		type filter hook forward priority filter - 10; policy accept;
		jump guard
	}
}
`
	own, got := tally(ruleset(r, found{})), tally(listed)
	if !maps.Equal(own, got) {
		t.Errorf("счёт расходится:\nсвой  %v\nв nft %v", own, got)
	}
	want := map[string]int{"set addrs4": 3, "set addrs6": 0, "chain guard": 4, "chain app": 3, "chain output": 2, "chain forward": 1}
	if !maps.Equal(got, want) {
		t.Errorf("%v, а нужно %v", got, want)
	}
	if got := tally(strings.Replace(listed, "\t\tip daddr @addrs4 drop\n", "", 1)); got["chain guard"] != 3 {
		t.Errorf("снятое правило видно: %v", got)
	}
}

func TestParseNetCls(t *testing.T) {
	const mi = `35 28 0:30 / /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime shared:9 - cgroup2 cgroup2 rw,nsdelegate
60 28 0:50 / /sys/fs/cgroup/net_cls,net_prio rw,nosuid shared:20 - cgroup cgroup rw,net_cls,net_prio
`
	if got := parseNetCls([]byte(mi)); got != "/sys/fs/cgroup/net_cls,net_prio" {
		t.Errorf("%q", got)
	}
	if got := parseNetCls([]byte("35 28 0:30 / /sys/fs/cgroup rw - cgroup2 cgroup2 rw\n")); got != "" {
		t.Errorf("%q", got)
	}
}

func TestMarksFor(t *testing.T) {
	if got := marksFor("/нет/такого"); got != nil {
		t.Errorf("%v", got)
	}
}
