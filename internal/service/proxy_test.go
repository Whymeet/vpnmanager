package service_test

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"appguard/internal/core"
	"appguard/internal/enforce"
	"appguard/internal/ipc"
	"appguard/internal/service/servicetest"
)

// Сценарии таски 09: VPN-клиент в режиме системного прокси. Прокси — ещё один
// путь: выход проверяется через сам прокси, а пока он не проверен, порт прокси
// закрыт для всех программ. Адреса защищённых сервисов при этом закрыты на всех
// интерфейсах, как всегда.

var (
	hiddify     = servicetest.Proxy(12334, "Hiddify")
	hiddifyPort = netip.MustParseAddrPort("127.0.0.1:12334")
)

const proxyName = "прокси 127.0.0.1:12334"

// portClosed — порт прокси закрыт, адреса сервиса закрыты везде.
func portClosed(r enforce.Rules) bool {
	return slices.Equal(r.ClosedProxies, []netip.AddrPort{hiddifyPort}) && closed(r)
}

// portOpen — порт прокси открыт, а адреса сервиса по-прежнему закрыты на всех
// интерфейсах: к ним ходит не программа, а клиент VPN по ту сторону прокси.
func portOpen(r enforce.Rules) bool { return len(r.ClosedProxies) == 0 && closed(r) }

func onlyProxy(state string) func(ipc.Status) bool {
	return func(st ipc.Status) bool {
		return len(st.Paths) == 1 && st.Paths[0].Proxy && st.Paths[0].State == state
	}
}

// proxyWithExit — служба с защищённым notion.so и системным прокси, выход
// которого — ip в country; ждёт, пока проверка закончится.
func proxyWithExit(t *testing.T, ip, country string) *servicetest.Service {
	t.Helper()
	s := protected(t)
	s.Web.Set(ip, country, country)
	s.Network.SetProxy(hiddify)
	s.WaitStatus(t, 2*time.Second, func(st ipc.Status) bool { return len(st.Paths) == 1 && st.Paths[0].State != "pending" })
	return s
}

func TestProxyAppearsAndIsVerified(t *testing.T) {
	s := protected(t)
	s.Web.Set("185.1.2.3", "DE", "DE")
	s.Web.Hold()
	s.Network.SetProxy(hiddify)

	// Пока выход проверяется, порт закрыт для всех, и журнал об этом пишет.
	s.WaitStatus(t, time.Second, onlyProxy("pending"))
	waitRules(t, s, time.Second, portClosed)
	hasLine(t, s, proxyName+" включён (порт слушает Hiddify) — проверяю выход; пока он не проверен, "+core.PortClosed)
	time.Sleep(3 * servicetest.CheckEvery)
	if r := s.Enforce.Rules(); !portClosed(r) {
		t.Fatalf("пока выход прокси проверяется, порт открыт: %+v", r)
	}

	s.Web.Release()
	waitRules(t, s, 2*time.Second, portOpen)
	st := s.WaitStatus(t, time.Second, onlyProxy("verified"))
	if p := st.Paths[0]; p.Iface != proxyName || p.Listener != "Hiddify" || p.IP != "185.1.2.3" || p.Country != "DE" ||
		p.Summary != "выход 185.1.2.3, Германия — проверен" {
		t.Fatalf("путь %+v", p)
	}
	hasLine(t, s, proxyName+": порт открыт — выход 185.1.2.3, Германия")
	hasLine(t, s, "сервисы открыты: выход 185.1.2.3, Германия")
	lines := s.Journal(t)
	if verified, opened := lineIndex(lines, proxyName+": выход 185.1.2.3, Германия — проверен"), lineIndex(lines, proxyName+": порт открыт"); verified < 0 || opened < verified {
		t.Fatalf("порт открылся раньше, чем журнал показал проверенный выход:\n%s", strings.Join(lines, "\n"))
	}
}

func TestProxyExitTurningRussianClosesPort(t *testing.T) {
	s := proxyWithExit(t, "185.1.2.3", "DE")
	waitRules(t, s, time.Second, portOpen)

	// Клиент переключился на российский сервер, прокси тот же.
	s.Web.Set("95.1.2.3", "RU", "RU")
	waitRules(t, s, 5*servicetest.CheckEvery+time.Second, portClosed)
	hasLine(t, s, "сервисы закрыты: "+proxyName+" — выход в России (95.1.2.3)")
	hasLine(t, s, proxyName+": выход в России (95.1.2.3) — "+core.PortClosed)
	st := s.WaitStatus(t, time.Second, onlyProxy("russian"))
	if !strings.Contains(st.Paths[0].Summary, core.PortClosed) {
		t.Fatalf("статус не говорит, что порт закрыт: %+v", st.Paths[0])
	}
}

func TestUnverifiedProxyKeepsServicesClosed(t *testing.T) {
	for name, tc := range map[string]struct{ cloudflare, second, why string }{
		"выход российский":     {"RU", "RU", proxyName + " — выход в России (185.1.2.3)"},
		"источники расходятся": {"RU", "DE", proxyName + " — не удалось проверить выход"},
		"источники молчат":     {"", "", proxyName + " — не удалось проверить выход"},
	} {
		t.Run(name, func(t *testing.T) {
			s := protected(t)
			s.Web.Set("185.1.2.3", tc.cloudflare, tc.second)
			s.Network.SetProxy(hiddify)
			waitRules(t, s, 2*time.Second, func(r enforce.Rules) bool {
				return portClosed(r) && s.Status(t).Paths[0].State != "pending"
			})
			hasLine(t, s, "сервисы закрыты: "+tc.why)
			hasLine(t, s, "— "+core.PortClosed)
		})
	}
}

func TestProxyExitNotFromMyListKeepsPortClosed(t *testing.T) {
	// Свой выход запомнен через туннель, правило — «только мои выходы».
	s := withExit(t, "", "185.1.2.3", "DE")
	remember(t, s, "Server 1")
	setRule(t, s, "mine")
	waitRules(t, s, time.Second, openUtun)

	// Туннель выключили, клиент работает прокси с другим выходом.
	s.Web.Set("203.0.113.5", "NL", "NL")
	s.Network.SetProxy(hiddify)
	closedPort := func(r enforce.Rules) bool {
		return slices.Equal(r.ClosedProxies, []netip.AddrPort{hiddifyPort}) && len(r.OpenIfaces) == 0
	}
	waitRules(t, s, 2*time.Second, closedPort)
	hasLine(t, s, "сервисы закрыты: "+proxyName+" — выход 203.0.113.5, Нидерланды — не из твоего списка")
	hasLine(t, s, proxyName+": выход 203.0.113.5, Нидерланды — не из твоего списка — "+core.PortClosed)

	// Тот же прокси с выходом из списка — порт открыт.
	s.Web.Set("185.1.2.3", "DE", "DE")
	waitRules(t, s, 5*servicetest.CheckEvery+time.Second, func(r enforce.Rules) bool { return len(r.ClosedProxies) == 0 })
}

func TestProxyGoneLiftsPortRule(t *testing.T) {
	s := proxyWithExit(t, "95.1.2.3", "RU")
	waitRules(t, s, time.Second, portClosed)

	// В клиенте выключили прокси — правило для порта снято.
	s.Network.Set()
	waitRules(t, s, time.Second, func(r enforce.Rules) bool { return len(r.ClosedProxies) == 0 && closed(r) })
	s.WaitStatus(t, time.Second, func(st ipc.Status) bool { return len(st.Paths) == 0 })
	hasLine(t, s, proxyName+" выключен — правило для его порта снято — VPN нет")
	hasLine(t, s, "сервисы закрыты: VPN выключен")
}

// Порт прокси — отдельно от туннелей: туннель проверен и сервисы открыты через
// него, а прокси с российским выходом закрыт для всех.
func TestRussianProxyIsClosedWhileTunnelIsOpen(t *testing.T) {
	s := protected(t)
	s.Web.Set("185.1.2.3", "DE", "DE")
	s.Web.Via(proxyName, "95.1.2.3", "RU", "RU")
	s.Network.SetProxy(hiddify, utun)
	waitRules(t, s, 2*time.Second, func(r enforce.Rules) bool {
		return slices.Equal(r.OpenIfaces, []string{"utun11"}) && slices.Equal(r.ClosedProxies, []netip.AddrPort{hiddifyPort})
	})
	hasLine(t, s, "сервисы открыты: выход 185.1.2.3, Германия")
	hasLine(t, s, proxyName+": выход в России (95.1.2.3) — "+core.PortClosed)
}

// Служба перезапустилась при включённом прокси: первые же правила закрывают
// его порт, а не открывают до первой проверки; проверка идёт сразу.
func TestProxyPortClosedFromFirstRules(t *testing.T) {
	n := servicetest.NewNetwork()
	n.First = core.Snapshot{Proxies: []core.Proxy{hiddify}, DefaultIface: "en0"}
	web := &servicetest.Web{}
	web.Set("185.1.2.3", "DE", "DE")
	s := servicetest.Start(t, "", servicetest.Fakes{Network: n, Web: web})
	waitRules(t, s, 2*time.Second, func(r enforce.Rules) bool { return len(r.ClosedProxies) == 0 })
	if first := s.Enforce.History()[0]; !slices.Equal(first.ClosedProxies, []netip.AddrPort{hiddifyPort}) {
		t.Fatalf("первые правила не закрыли порт прокси: %+v", first)
	}
}

// Свой выход запоминается и в режиме прокси: текущий выход — выход прокси.
func TestRememberProxyExit(t *testing.T) {
	s := proxyWithExit(t, "185.1.2.3", "DE")
	if resp := remember(t, s, "Server 1"); !resp.OK || resp.Exit.IP != "185.1.2.3" {
		t.Fatalf("запомнить: %+v", resp)
	}
	setRule(t, s, "mine")
	waitRules(t, s, time.Second, portOpen)
}

func TestUninstallLiftsProxyPortRule(t *testing.T) {
	s := proxyWithExit(t, "95.1.2.3", "RU")
	waitRules(t, s, time.Second, portClosed)
	if resp := call(t, s, ipc.CmdUninstall); !resp.OK {
		t.Fatalf("%+v", resp)
	}
	if !s.Enforce.Cleared() || len(s.Enforce.Rules().ClosedProxies) != 0 {
		t.Fatalf("удаление не сняло правило для порта прокси: %+v", s.Enforce.Rules())
	}
}

// «Россия напрямую» замечается и у клиента в режиме прокси: зонд идёт тем же
// путём, что проверка выхода, — через прокси.
func TestRussiaDirectThroughProxy(t *testing.T) {
	s := proxyWithExit(t, "185.1.2.3", "DE")
	s.Web.RussiaDirect(true)
	s.Network.SetProxy(hiddify)
	s.WaitStatus(t, 2*time.Second, direct)
	hasLine(t, s, proxyName+": клиент VPN отправляет российские адреса напрямую")
}
