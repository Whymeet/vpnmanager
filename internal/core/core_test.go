package core

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestJudge(t *testing.T) {
	ip := netip.MustParseAddr("185.1.2.3")
	ans := func(src, country string) Answer { return Answer{Source: src, IP: ip, Country: country} }
	for name, tc := range map[string]struct {
		a, b   Answer
		want   Outcome
		detail string
	}{
		"оба не Россия":            {ans("Cloudflare", "DE"), ans("ipinfo", "DE"), Verified, ""},
		"разные страны, не Россия": {ans("Cloudflare", "DE"), ans("ipinfo", "NL"), Verified, ""},
		"оба Россия":               {ans("Cloudflare", "RU"), ans("ipinfo", "RU"), Russian, ""},
		"расходятся":               {ans("Cloudflare", "RU"), ans("ipinfo", "DE"), Unverified, "Cloudflare — Россия, ipinfo — Германия"},
		"страна неизвестна":        {ans("Cloudflare", "XX"), ans("ipinfo", "DE"), Unverified, "не определил страну"},
		"Tor":                      {ans("Cloudflare", "T1"), ans("ipinfo", "T1"), Unverified, "не определил страну"},
	} {
		t.Run(name, func(t *testing.T) {
			c := Judge(tc.a, tc.b)
			if c.Outcome != tc.want || !strings.Contains(c.Detail, tc.detail) {
				t.Fatalf("%+v", c)
			}
			if c.Outcome == Verified && c.Exit != (Exit{ip, tc.a.Country}) {
				t.Fatalf("выход %+v", c.Exit)
			}
		})
	}
}

func TestPathLifecycle(t *testing.T) {
	now := time.Now()
	utun := Tunnel{Name: "utun11", Index: 30, Addrs: []netip.Addr{netip.MustParseAddr("10.8.1.1")}}
	s := NewState()

	ev := s.Observe(Snapshot{Tunnels: []Tunnel{utun}}, now)
	if len(ev) != 1 || ev[0].Kind != KindTunnelUp || s.Paths()[0].Check.Outcome != Pending {
		t.Fatalf("новый туннель: %+v, %+v", ev, s.Paths())
	}
	gen := s.Paths()[0].Gen
	if ev := s.Observe(Snapshot{Tunnels: []Tunnel{utun}}, now); len(ev) != 0 {
		t.Fatalf("тот же снимок дал события: %+v", ev)
	}

	de := Check{Outcome: Verified, Exit: Exit{netip.MustParseAddr("185.1.2.3"), "DE"}}
	ev = s.Checked("utun11", gen, de, now)
	if len(ev) != 1 || ev[0].Text != "utun11: выход 185.1.2.3, Германия — проверен" {
		t.Fatalf("%+v", ev)
	}
	if ev := s.Checked("utun11", gen, de, now); len(ev) != 0 {
		t.Fatalf("повторная проверка с тем же итогом дала событие: %+v", ev)
	}
	nl := Check{Outcome: Verified, Exit: Exit{netip.MustParseAddr("203.0.113.5"), "NL"}}
	if ev := s.Checked("utun11", gen, nl, now); len(ev) != 1 || !strings.Contains(ev[0].Text, "выход сменился — 203.0.113.5, Нидерланды") {
		t.Fatalf("смена выхода: %+v", ev)
	}

	// Туннель исчез и появился снова: результат прежней проверки к нему не относится.
	s.Observe(Snapshot{}, now)
	s.Observe(Snapshot{Tunnels: []Tunnel{utun}}, now)
	if ev := s.Checked("utun11", gen, de, now); len(ev) != 0 || s.Paths()[0].Check.Outcome != Pending {
		t.Fatal("результат проверки прежнего туннеля применился к новому")
	}

	ev = s.Observe(Snapshot{}, now)
	if len(ev) != 1 || ev[0].Text != "туннель utun11 исчез — VPN нет" || len(s.Paths()) != 0 {
		t.Fatalf("исчезновение: %+v", ev)
	}
}

func TestAddressChangeRestartsVerification(t *testing.T) {
	now := time.Now()
	s := NewState()
	s.Observe(Snapshot{Tunnels: []Tunnel{{Name: "utun5", Index: 7, Addrs: []netip.Addr{netip.MustParseAddr("10.0.0.2")}}}}, now)
	s.Checked("utun5", s.Paths()[0].Gen, Check{Outcome: Verified, Exit: Exit{netip.MustParseAddr("185.1.2.3"), "DE"}}, now)

	s.Observe(Snapshot{Tunnels: []Tunnel{{Name: "utun5", Index: 7, Addrs: []netip.Addr{netip.MustParseAddr("10.0.0.9")}}}}, now)
	if got := s.Paths()[0].Check.Outcome; got != Pending {
		t.Fatalf("туннель с новым адресом остался проверенным: %v", got)
	}
}

func TestPlural(t *testing.T) {
	for n, want := range map[int]string{1: "адрес", 2: "адреса", 4: "адреса", 5: "адресов", 11: "адресов", 12: "адресов", 21: "адрес", 22: "адреса", 111: "адресов"} {
		if got := Plural(n, "адрес", "адреса", "адресов"); got != want {
			t.Errorf("%d: %s, ждали %s", n, got, want)
		}
	}
}

func TestNoClosedReasonBeforeNetworkIsSeen(t *testing.T) {
	s := NewState()
	if p := s.Protect(Policy{}); p.Open || p.Reason != "" {
		t.Fatalf("до первого снимка: %+v", p)
	}
	s.Observe(Snapshot{}, time.Now())
	if p := s.Protect(Policy{}); p.Reason != "VPN выключен" {
		t.Fatalf("после снимка без туннелей: %+v", p)
	}
}

func TestOnlyMyExits(t *testing.T) {
	now := time.Now()
	de := Exit{netip.MustParseAddr("185.1.2.3"), "DE"}
	nl := Exit{netip.MustParseAddr("203.0.113.5"), "NL"}
	s := NewState()
	s.Observe(Snapshot{Tunnels: []Tunnel{{Name: "utun11", Index: 9, Addrs: []netip.Addr{netip.MustParseAddr("10.8.1.1")}}}, DefaultIface: "utun11"}, now)
	s.Checked("utun11", s.Paths()[0].Gen, Check{Outcome: Verified, Exit: nl}, now)

	any := s.Protect(Policy{Rule: RuleAny})
	if !any.Open {
		t.Fatalf("«любой выход не из России»: %+v", any)
	}
	mine := Policy{Rule: RuleMine, Exits: map[netip.Addr]string{de.IP: "Server 1"}}
	if p := s.Protect(mine); p.Open || p.Reason != "выход 203.0.113.5, Нидерланды — не из твоего списка" {
		t.Fatalf("выход не из списка: %+v", p)
	}
	if p := s.Protect(Policy{Rule: RuleMine}); p.Open || !strings.Contains(p.Reason, "в твоём списке пока нет ни одного выхода") {
		t.Fatalf("пустой список: %+v", p)
	}
	s.Checked("utun11", s.Paths()[0].Gen, Check{Outcome: Verified, Exit: de}, now)
	if p := s.Protect(mine); !p.Open || p.Exit != de {
		t.Fatalf("выход из списка: %+v", p)
	}
	// Российский выход закрыт при любом правиле, даже если кто-то занёс его в список.
	ru := Exit{netip.MustParseAddr("95.1.2.3"), "RU"}
	s.Checked("utun11", s.Paths()[0].Gen, Check{Outcome: Russian, Exit: ru}, now)
	if p := s.Protect(Policy{Rule: RuleMine, Exits: map[netip.Addr]string{ru.IP: "свой"}}); p.Open {
		t.Fatalf("российский выход открыт: %+v", p)
	}
}
