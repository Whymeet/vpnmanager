package service_test

import (
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"vpnlock/internal/core"
	"vpnlock/internal/enforce"
	"vpnlock/internal/ipc"
	"vpnlock/internal/paths"
	"vpnlock/internal/service/servicetest"
)

// Сценарии таски 10: защита держится, что бы ни происходило с самой службой
// и с правилами файрвола.

func TestRulesResetByAnotherProgramAreRestored(t *testing.T) {
	for _, how := range []string{"pf выключен", "основной набор правил pf сброшен: якоря com.apple не вызываются", "в якоре 0 правил вместо 6"} {
		t.Run(how, func(t *testing.T) {
			s := withExit(t, "", "185.1.2.3", "DE")
			waitRules(t, s, time.Second, openUtun)
			before := s.Enforce.Rules()

			s.Enforce.Reset(how)
			// Сторож замечает и восстанавливает не позже чем через секунду.
			waitRules(t, s, time.Second, func(r enforce.Rules) bool { return r.Equal(before) })
			hasLine(t, s, "правила файрвола сброшены другой программой ("+how+") — восстанавливаю")
			hasLine(t, s, "правила файрвола восстановлены")
		})
	}
}

func TestStoppedServiceLeavesServicesClosed(t *testing.T) {
	root := t.TempDir()
	up := servicetest.NewDNS("Cloudflare")
	up.Maps(domain, notion4.String())
	s := servicetest.Start(t, root, servicetest.Fakes{Accounts: &servicetest.Accounts{Admin: true}, DNS: up})
	s.Protect(t, domain)
	s.Web.Set("185.1.2.3", "DE", "DE")
	s.Network.SetProxy(hiddify, utun)
	waitRules(t, s, 2*time.Second, func(r enforce.Rules) bool {
		return slices.Equal(r.OpenIfaces, []string{"utun11"}) && len(r.ClosedProxies) == 0
	})

	// Без службы выход никто не перепроверяет: остановка закрывает все пути, а
	// таблицы остаются.
	s.Stop()
	if r := s.Enforce.Rules(); len(r.OpenIfaces) != 0 || !slices.Equal(r.ClosedProxies, []netip.AddrPort{hiddifyPort}) || !has(r, notion4.String()) {
		t.Fatalf("после остановки: %+v", r)
	}
	if s.Enforce.Cleared() {
		t.Fatal("остановка сняла правила")
	}
	again := servicetest.Start(t, root, servicetest.Fakes{})
	hasLine(t, again, "служба останавливается — сервисы закрыты до её запуска")
	hasLine(t, again, "служба "+servicetest.Version+" запущена")
}

// Принудительно завершённую службу launchd запускает снова: журнал говорит о
// перезапуске, а первые правила ничего не открывают до проверки выхода.
func TestRestartAfterCrashIsJournaledAndOpensNothing(t *testing.T) {
	root := t.TempDir()
	s := servicetest.Start(t, root, servicetest.Fakes{})
	s.Stop()
	// Метку «работаю» оставляет только оборвавшийся запуск.
	marker := filepath.Join(s.Layout.StateDir, "running")
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("после остановки осталась метка запуска")
	}
	os.WriteFile(marker, nil, 0o600)

	n := servicetest.NewNetwork()
	n.First = core.Snapshot{Tunnels: []core.Tunnel{utun}, DefaultIface: "utun11"}
	web := &servicetest.Web{}
	web.Set("185.1.2.3", "DE", "DE")
	web.Hold()
	again := servicetest.Start(t, root, servicetest.Fakes{Network: n, Web: web})
	hasLine(t, again, "служба "+servicetest.Version+" перезапущена: прошлый запуск оборвался, правила файрвола всё это время оставались в системе")
	time.Sleep(3 * servicetest.CheckEvery)
	for _, r := range again.Enforce.History() {
		if len(r.OpenIfaces) != 0 {
			t.Fatalf("после перезапуска путь открыт до проверки: %+v", r)
		}
	}
	web.Release()
	waitRules(t, again, 2*time.Second, openUtun)
}

// После удаления правил больше нет: ни сторож, ни остановка их не возвращают.
func TestUninstalledServiceNeverPutsRulesBack(t *testing.T) {
	s := withExit(t, "", "185.1.2.3", "DE")
	waitRules(t, s, time.Second, openUtun)
	if resp := call(t, s, ipc.CmdUninstall); !resp.OK {
		t.Fatalf("%+v", resp)
	}
	n := len(s.Enforce.History())
	s.Enforce.Reset("в якоре 0 правил вместо 4")
	s.Network.Set()
	<-s.Done
	if h := s.Enforce.History(); len(h) != n {
		t.Fatalf("после удаления правила ставились снова: %+v", h[n:])
	}
}

// VPN через CDN: сервер VPN на том же адресе, что и защищённый сервис. Пока
// выход проверен, сервер запоминается и на физическом интерфейсе остаётся
// разрешён — и когда VPN переподключается, и после перезапуска службы.
func TestVPNServerOnProtectedAddressStaysAllowed(t *testing.T) {
	root := t.TempDir()
	const cdn = "104.18.0.1" // адрес notion.so — он же адрес сервера VPN
	s := withExit(t, root, "185.1.2.3", "DE")
	s.Apps.VPNServer(cdn)
	allowed := func(r enforce.Rules) bool {
		return slices.Equal(r.Servers, []netip.Addr{netip.MustParseAddr(cdn)}) && r.Physical == servicetest.PhysicalIface.Name && has(r, cdn)
	}
	waitRules(t, s, 2*time.Second, allowed)
	hasLine(t, s, "сервер VPN "+cdn+" — на том же адресе, что и защищённый сервис (VPN через CDN)")

	// VPN переподключается: туннеля нет, а сервер по-прежнему разрешён.
	s.Network.Set()
	waitRules(t, s, time.Second, func(r enforce.Rules) bool { return len(r.OpenIfaces) == 0 && allowed(r) })
	s.Stop()

	again := servicetest.Start(t, root, servicetest.Fakes{})
	waitRules(t, again, time.Second, allowed)
}

// Сервер VPN — только соединение самого клиента VPN. Другие программы, в том
// числе защищённое приложение, привязав сокет к физическому интерфейсу, адрес
// себе не открывают: ни установленным соединением, ни попыткой, которую pf
// отбросил (TCP в SYN_SENT, UDP без обмена). Незавершённая попытка самого
// клиента тоже не в счёт.
func TestOnlyTheVPNClientMakesAServer(t *testing.T) {
	const server, other = "104.18.0.1", "104.18.0.2"
	up := servicetest.NewDNS("Cloudflare")
	up.Maps(domain, server, other)
	s := servicetest.Start(t, "", servicetest.Fakes{Accounts: &servicetest.Accounts{Admin: true}, DNS: up})
	s.Protect(t, domain)
	s.Web.Set("185.1.2.3", "DE", "DE")
	const app, stranger = 501, 777 // процесс защищённого приложения и просто чужая программа
	s.Apps.Bypass(app, "tcp", "SYN_SENT", other)
	s.Apps.Bypass(app, "udp", "", other)
	s.Apps.Bypass(stranger, "tcp", "ESTABLISHED", other)
	s.Apps.Bypass(servicetest.VPNClientPID, "tcp", "SYN_SENT", other)
	s.Apps.VPNServer(server)
	s.Network.Set(utun)
	only := []netip.Addr{netip.MustParseAddr(server)}
	waitRules(t, s, 2*time.Second, func(r enforce.Rules) bool { return slices.Equal(r.Servers, only) })
	time.Sleep(3 * servicetest.ScanEvery)
	if r := s.Enforce.Rules(); !slices.Equal(r.Servers, only) || !has(r, other) {
		t.Fatalf("адрес открыт соединением не клиента VPN: %+v", r)
	}
}

// В режиме системного прокси клиент VPN — процесс, который слушает порт
// прокси: его соединение с адресом защищённого сервиса делает адрес сервером,
// соединение другой программы — нет (с физического адреса там ходят все).
func TestVPNServerLearnedInProxyMode(t *testing.T) {
	const server, other = "104.18.0.1", "104.18.0.2"
	up := servicetest.NewDNS("Cloudflare")
	up.Maps(domain, server, other)
	s := servicetest.Start(t, "", servicetest.Fakes{Accounts: &servicetest.Accounts{Admin: true}, DNS: up})
	s.Protect(t, domain)
	s.Web.Set("185.1.2.3", "DE", "DE")
	s.Apps.Bypass(777, "tcp", "ESTABLISHED", other)
	s.Apps.VPNServer(server)
	s.Network.SetProxy(servicetest.Proxy(12334, "Hiddify"))
	only := []netip.Addr{netip.MustParseAddr(server)}
	waitRules(t, s, 2*time.Second, func(r enforce.Rules) bool { return slices.Equal(r.Servers, only) })
	time.Sleep(3 * servicetest.ScanEvery)
	if r := s.Enforce.Rules(); !slices.Equal(r.Servers, only) || !has(r, other) {
		t.Fatalf("сервер в режиме прокси: %+v", r)
	}
}

// Серверы, записанные прежней версией (ключ vpnServers), не читаются: туда
// попадали соединения любых программ. Адрес закрыт, пока клиент VPN снова к
// нему не подключится.
func TestServersFromOldSettingsAreNotTrusted(t *testing.T) {
	root := t.TempDir()
	L := paths.Under(root)
	os.MkdirAll(L.StateDir, 0o700)
	os.WriteFile(L.ConfigFile, []byte(`{"schema":1,"vpnServers":["`+notion4.String()+`"]}`), 0o600)
	s := withExit(t, root, "185.1.2.3", "DE")
	waitRules(t, s, time.Second, openUtun)
	time.Sleep(3 * servicetest.ScanEvery)
	if r := s.Enforce.Rules(); len(r.Servers) != 0 {
		t.Fatalf("сервер из прежних настроек разрешён: %+v", r)
	}
	s.Apps.VPNServer(notion4.String())
	waitRules(t, s, 2*time.Second, func(r enforce.Rules) bool { return slices.Equal(r.Servers, []netip.Addr{notion4}) })
}

// С «Россией напрямую» мимо туннеля уходят и российские узлы сервисов: тогда
// соединения мимо туннеля за серверы VPN не принимаются.
func TestNoVPNServerLearnedWithRussiaDirect(t *testing.T) {
	up := servicetest.NewDNS("Cloudflare")
	up.Maps(domain, notion4.String())
	s := servicetest.Start(t, "", servicetest.Fakes{Accounts: &servicetest.Accounts{Admin: true}, DNS: up})
	s.Protect(t, domain)
	s.Web.Set("185.1.2.3", "DE", "DE")
	s.Web.RussiaDirect(true)
	s.Apps.VPNServer(notion4.String())
	s.Network.Set(utun)
	s.WaitStatus(t, 2*time.Second, direct)
	time.Sleep(5 * servicetest.ScanEvery)
	if r := s.Enforce.Rules(); len(r.Servers) != 0 {
		t.Fatalf("при «России напрямую» адрес мимо туннеля разрешён: %+v", r)
	}
}
