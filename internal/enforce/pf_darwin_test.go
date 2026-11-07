package enforce

import (
	"net/netip"
	"os/exec"
	"strings"
	"testing"
)

var (
	v4 = []netip.Addr{netip.MustParseAddr("104.18.0.1"), netip.MustParseAddr("104.18.0.2")}
	v6 = []netip.Addr{netip.MustParseAddr("2606:4700::6812:1")}
)

// pfParses — pfctl разбирает правила без загрузки: для этого root не нужен.
func pfParses(t *testing.T, rules string) {
	t.Helper()
	cmd := exec.Command(pfctl, "-nf", "-")
	cmd.Stdin = strings.NewReader(rules)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("pf не принял правила: %v\n%s\n%s", err, out, rules)
	}
}

func TestClosedRulesBlockEverywhere(t *testing.T) {
	rules := anchorRules(Rules{V4: v4, V6: v6})
	if strings.Contains(rules, "pass") {
		t.Fatalf("без проверенного туннеля в правилах есть пропуск:\n%s", rules)
	}
	for _, want := range []string{
		"table <vpnlock4> persist",
		"table <vpnlock6> persist",
		"block drop out quick inet from any to <vpnlock4>",
		"block drop out quick inet6 from any to <vpnlock6>",
	} {
		if !strings.Contains(rules, want) {
			t.Fatalf("нет %q:\n%s", want, rules)
		}
	}
	pfParses(t, rules)
}

func TestTableInputListsEveryAddress(t *testing.T) {
	if got := tableInput(v4); got != "104.18.0.1\n104.18.0.2\n" {
		t.Fatalf("%q", got)
	}
	if got := tableInput(nil); got != "" {
		t.Fatalf("пустая таблица: %q", got)
	}
}

func TestOpenRulesPassOnlyVerifiedTunnel(t *testing.T) {
	rules := anchorRules(Rules{OpenIfaces: []string{"utun11"}, V4: v4, V6: v6})
	block := strings.Index(rules, "block drop out quick inet from any to <vpnlock4>")
	for _, pass := range []string{
		"pass out quick on utun11 inet proto tcp from any to <vpnlock4> flags any keep state (if-bound)",
		"pass out quick on utun11 inet from any to <vpnlock4> keep state (if-bound)",
		"pass out quick on utun11 inet6 proto tcp from any to <vpnlock6> flags any keep state (if-bound)",
		"pass out quick on utun11 inet6 from any to <vpnlock6> keep state (if-bound)",
	} {
		i := strings.Index(rules, pass)
		if i < 0 || block < 0 || i > block {
			t.Fatalf("нет пропуска %q раньше запрета:\n%s", pass, rules)
		}
	}
	if strings.Count(rules, "pass out") != 4 || strings.Contains(rules, "S/SA") {
		t.Fatalf("пропуск не только через utun11 или с ограничением по SYN:\n%s", rules)
	}
	// Для TCP правило с flags any стоит раньше общего: иначе общее поймало бы
	// TCP без flags any, и состояние посреди потока не создалось бы.
	if strings.Index(rules, "proto tcp from any to <vpnlock4> flags any") > strings.Index(rules, "inet from any to <vpnlock4> keep state") {
		t.Fatalf("правило для TCP стоит позже общего:\n%s", rules)
	}
	pfParses(t, rules)
}

func TestEmptyTablesAreValid(t *testing.T) {
	pfParses(t, anchorRules(Rules{}))
}

func TestStrangeInterfaceNamesNeverReachRules(t *testing.T) {
	rules := anchorRules(Rules{OpenIfaces: []string{"utun1 inet from any to any", "", "en0;"}, V4: v4})
	if strings.Contains(rules, "pass") {
		t.Fatalf("в правила попало чужое имя интерфейса:\n%s", rules)
	}
	pfParses(t, rules)
}

func TestToken(t *testing.T) {
	if got := parseToken([]byte("No ALTQ support in kernel\npf enabled\nToken : 18446744073709551\n")); got != "18446744073709551" {
		t.Fatalf("токен %q", got)
	}
	if got := parseToken([]byte("pf already enabled\n")); got != "" {
		t.Fatalf("токен из пустого ответа: %q", got)
	}
}

func TestUnverifiedProxyPortIsClosedForAllButRoot(t *testing.T) {
	rules := anchorRules(Rules{
		ClosedProxies: []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:7890"), netip.MustParseAddrPort("[::1]:7890"), {}},
		V4:            v4,
	})
	for _, want := range []string{
		"block drop out quick proto tcp from any to 127.0.0.1 port 7890 user != 0",
		"block drop out quick proto tcp from any to ::1 port 7890 user != 0",
	} {
		if !strings.Contains(rules, want) {
			t.Fatalf("нет %q:\n%s", want, rules)
		}
	}
	if n := strings.Count(rules, "port "); n != 2 {
		t.Fatalf("пустой адрес попал в правила (%d правил для портов):\n%s", n, rules)
	}
	pfParses(t, rules)
}

// Проверенный прокси (или выключенный) — правила для его порта нет.
func TestNoProxyRuleWithoutClosedProxy(t *testing.T) {
	if rules := anchorRules(Rules{OpenIfaces: []string{"utun11"}, V4: v4}); strings.Contains(rules, "user") {
		t.Fatalf("правило для порта без закрытого прокси:\n%s", rules)
	}
}

func TestRulesEqualSeesProxies(t *testing.T) {
	a := Rules{ClosedProxies: []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:7890")}}
	if a.Equal(Rules{}) || !a.Equal(Rules{ClosedProxies: []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:7890")}}) {
		t.Fatal("Equal не различает порты прокси")
	}
}

func TestVPNServerOnProtectedAddressPassesOnlyOnPhysical(t *testing.T) {
	rules := anchorRules(Rules{V4: v4, V6: v6, Servers: []netip.Addr{v4[0], v6[0]}, Physical: "en0"})
	block := strings.Index(rules, "block drop out quick inet from any to <vpnlock4>")
	for _, pass := range []string{
		"pass out quick on en0 inet proto tcp from any to 104.18.0.1 flags any keep state (if-bound)",
		"pass out quick on en0 inet from any to 104.18.0.1 keep state (if-bound)",
		"pass out quick on en0 inet6 proto tcp from any to 2606:4700::6812:1 flags any keep state (if-bound)",
	} {
		if i := strings.Index(rules, pass); i < 0 || i > block {
			t.Fatalf("нет пропуска %q раньше запрета:\n%s", pass, rules)
		}
	}
	pfParses(t, rules)
	// Без физического интерфейса (или с чужим именем) — никаких пропусков.
	for _, phys := range []string{"", "en0 all"} {
		if rules := anchorRules(Rules{V4: v4, Servers: v4, Physical: phys}); strings.Contains(rules, "pass") {
			t.Fatalf("пропуск без физического интерфейса %q:\n%s", phys, rules)
		}
	}
}

// Сторож сверяет число правил в якоре с числом правил в тексте: таблицы не
// правила.
func TestCountRules(t *testing.T) {
	r := Rules{OpenIfaces: []string{"utun11"}, V4: v4, ClosedProxies: []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:7890")}}
	if n := countRules([]byte(anchorRules(r))); n != 7 {
		t.Fatalf("%d правил:\n%s", n, anchorRules(r))
	}
	shown := "block drop out quick proto tcp from any to 127.0.0.1 port = 7890 user != 0\npass out quick on utun11 inet proto tcp from any to <vpnlock4> flags any keep state (if-bound)\n"
	if n := countRules([]byte(shown)); n != 2 {
		t.Fatalf("%d", n)
	}
}
