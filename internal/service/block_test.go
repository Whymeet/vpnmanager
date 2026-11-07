package service_test

import (
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"vpnlock/internal/enforce"
	"vpnlock/internal/ipc"
	"vpnlock/internal/service/servicetest"
)

// Сценарии таски 03: адреса защищённого сервиса закрыты мимо проверенного
// туннеля. В каждом проверяются итоговое состояние правил и строки журнала.

const domain = "notion.so"

var (
	notion4 = netip.MustParseAddr("104.18.0.1")
	notion6 = netip.MustParseAddr("2606:4700::6812:1")
)

// protected — служба с защищённым notion.so и администратором у клавиатуры.
func protected(t *testing.T) *servicetest.Service {
	t.Helper()
	up := servicetest.NewDNS("Cloudflare")
	up.Maps(domain, notion4.String(), notion6.String())
	s := servicetest.Start(t, "", servicetest.Fakes{Accounts: &servicetest.Accounts{Admin: true}, DNS: up})
	s.Protect(t, domain)
	return s
}

// closed — адреса сервиса в таблицах, и ни одного открытого пути.
func closed(r enforce.Rules) bool {
	return len(r.OpenIfaces) == 0 && slices.Equal(r.V4, []netip.Addr{notion4}) && slices.Equal(r.V6, []netip.Addr{notion6})
}

func openOn(ifaces ...string) func(enforce.Rules) bool {
	return func(r enforce.Rules) bool {
		return slices.Equal(r.OpenIfaces, ifaces) && slices.Equal(r.V4, []netip.Addr{notion4})
	}
}

func waitRules(t *testing.T, s *servicetest.Service, within time.Duration, ok func(enforce.Rules) bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for !ok(s.Enforce.Rules()) {
		if time.Now().After(deadline) {
			t.Fatalf("за %v правила не пришли к нужному: %+v", within, s.Enforce.Rules())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// lineIndex — номер первой строки журнала с want, -1 — нет такой.
func lineIndex(lines []string, want string) int {
	return slices.IndexFunc(lines, func(l string) bool { return strings.Contains(l, want) })
}

func TestVPNOffKeepsServiceClosed(t *testing.T) {
	s := protected(t)
	waitRules(t, s, time.Second, closed)
	hasLine(t, s, "сервисы закрыты: VPN выключен")
}

func TestOpensOnlyAfterVerifiedExit(t *testing.T) {
	s := protected(t)
	s.Web.Set("185.1.2.3", "DE", "DE")
	s.Web.Hold()
	s.Network.Set(utun)
	s.WaitStatus(t, time.Second, onePath("pending"))
	time.Sleep(3 * servicetest.CheckEvery)
	if r := s.Enforce.Rules(); !closed(r) {
		t.Fatalf("пока выход проверяется, сервис открыт: %+v", r)
	}

	s.Web.Release()
	waitRules(t, s, 2*time.Second, openOn("utun11"))
	hasLine(t, s, "сервисы открыты: выход 185.1.2.3, Германия")
	lines := s.Journal(t)
	if verified, opened := lineIndex(lines, "utun11: выход 185.1.2.3, Германия — проверен"), lineIndex(lines, "сервисы открыты"); verified < 0 || opened < verified {
		t.Fatalf("сервисы открылись раньше, чем журнал показал проверенный выход:\n%s", strings.Join(lines, "\n"))
	}
}

func TestSwitchingVPNNeverOpensUncheckedTunnel(t *testing.T) {
	s := protected(t)
	s.Web.Set("185.1.2.3", "DE", "DE")
	s.Network.Set(utun)
	waitRules(t, s, 2*time.Second, openOn("utun11"))

	// Переключение: старый туннель ушёл — закрыто сразу, без промежутка.
	s.Web.Hold()
	s.Network.Set()
	waitRules(t, s, time.Second, closed)
	hasLine(t, s, "сервисы закрыты: VPN выключен")

	// Новый туннель появился, но ещё не проверен — по-прежнему закрыто.
	s.Web.Set("203.0.113.5", "NL", "NL")
	s.Network.Set(servicetest.Tunnel("utun12", "10.9.0.2"))
	s.WaitStatus(t, time.Second, func(st ipc.Status) bool { return len(st.Paths) == 1 && st.Paths[0].Iface == "utun12" })
	time.Sleep(3 * servicetest.CheckEvery)
	if r := s.Enforce.Rules(); !closed(r) {
		t.Fatalf("непроверенный туннель открыт: %+v", r)
	}
	s.Web.Release()
	waitRules(t, s, 2*time.Second, openOn("utun12"))

	// За всё время правила ни разу не открывали путь, кроме проверенных.
	for _, r := range s.Enforce.History() {
		for _, ifn := range r.OpenIfaces {
			if ifn != "utun11" && ifn != "utun12" {
				t.Fatalf("открывался неизвестный путь %s", ifn)
			}
		}
	}
}

func TestRussianExitStaysClosed(t *testing.T) {
	s := protected(t)
	s.Web.Set("95.1.2.3", "RU", "RU")
	s.Network.Set(utun)
	s.WaitStatus(t, 2*time.Second, onePath("russian"))
	waitRules(t, s, time.Second, closed)
	hasLine(t, s, "сервисы закрыты: выход в России (95.1.2.3)")
}

func TestExitTurningRussianClosesServices(t *testing.T) {
	s := protected(t)
	s.Web.Set("185.1.2.3", "DE", "DE")
	s.Network.Set(utun)
	waitRules(t, s, 2*time.Second, openOn("utun11"))

	// Клиент переключился на российский сервер внутри того же подключения.
	s.Web.Set("95.1.2.3", "RU", "RU")
	waitRules(t, s, 5*servicetest.CheckEvery+time.Second, closed)
	hasLine(t, s, "сервисы закрыты: выход в России (95.1.2.3)")
}

func TestUncheckableExitStaysClosed(t *testing.T) {
	for name, tc := range map[string]struct{ cloudflare, second string }{
		"источники расходятся": {"RU", "DE"},
		"источники молчат":     {"", ""},
	} {
		t.Run(name, func(t *testing.T) {
			s := protected(t)
			s.Web.Set("185.1.2.3", tc.cloudflare, tc.second)
			s.Network.Set(utun)
			s.WaitStatus(t, 2*time.Second, onePath("unverified"))
			waitRules(t, s, time.Second, closed)
			hasLine(t, s, "сервисы закрыты: не удалось проверить выход")
		})
	}
}

func TestProtectedAddressesSurviveRestart(t *testing.T) {
	root := t.TempDir()
	up := servicetest.NewDNS("Cloudflare")
	up.Maps(domain, notion4.String(), notion6.String())
	s := servicetest.Start(t, root, servicetest.Fakes{Accounts: &servicetest.Accounts{Admin: true}, DNS: up})
	s.Protect(t, domain)
	s.Stop()

	// После перезапуска таблицы наполнены сразу — до сети и до DNS.
	again := servicetest.Start(t, root, servicetest.Fakes{})
	waitRules(t, again, time.Second, closed)
}

func TestProtectNeedsAdmin(t *testing.T) {
	up := servicetest.NewDNS("Cloudflare")
	up.Maps(domain, notion4.String())
	s := servicetest.Start(t, "", servicetest.Fakes{Accounts: &servicetest.Accounts{Admin: false}, DNS: up})
	resp, err := ipc.Call(s.Layout.Socket, ipc.Request{Cmd: ipc.CmdProtect, Domain: domain})
	if err != nil || resp.OK || resp.Code != ipc.CodeForbidden {
		t.Fatalf("%v %+v", err, resp)
	}
	if r := s.Enforce.Rules(); len(r.V4) != 0 {
		t.Fatalf("адреса попали в таблицы без прав: %+v", r)
	}
}

func TestUnprotectEmptiesTables(t *testing.T) {
	s := protected(t)
	waitRules(t, s, time.Second, closed)
	resp, err := ipc.Call(s.Layout.Socket, ipc.Request{Cmd: ipc.CmdUnprotect, Domain: domain})
	if err != nil || !resp.OK {
		t.Fatalf("%v %+v", err, resp)
	}
	waitRules(t, s, time.Second, func(r enforce.Rules) bool { return len(r.V4) == 0 && len(r.V6) == 0 })
	hasLine(t, s, "защита снята с notion.so")
}

func TestUninstallClearsFirewall(t *testing.T) {
	s := protected(t)
	waitRules(t, s, time.Second, closed)
	if resp := call(t, s, ipc.CmdUninstall); !resp.OK {
		t.Fatalf("%+v", resp)
	}
	if !s.Enforce.Cleared() {
		t.Fatal("удаление не сняло правила файрвола")
	}
}

func TestFirewallFailureIsJournaledAndRetried(t *testing.T) {
	s := protected(t)
	waitRules(t, s, time.Second, closed)
	s.Enforce.Fail(errors.New("pfctl: /dev/pf: Permission denied"))
	s.Web.Set("185.1.2.3", "DE", "DE")
	s.Network.Set(utun)
	hasLine(t, s, "файрвол: не удалось применить правила — pfctl: /dev/pf: Permission denied")

	s.Enforce.Fail(nil)
	waitRules(t, s, 2*time.Second, openOn("utun11"))
	hasLine(t, s, "файрвол: правила снова применены")
}
