package service_test

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"appguard/internal/apps"
	"appguard/internal/enforce"
	"appguard/internal/ipc"
	"appguard/internal/service/servicetest"
)

// Сценарии таски 16: приложение Windows — исполняемый файл. Оно защищено сразу,
// без обучения, а сеть у него только с локального адреса проверенного туннеля
// (Rules.Apps и Rules.OpenAddrs, их ставит в фильтры WFP исполнитель Windows).

var (
	wintun     = servicetest.Tunnel("AmneziaVPN", "10.8.1.2")
	wintunAddr = netip.MustParseAddr("10.8.1.2")
)

// readExe узнаёт приложение, как apps.Read на Windows: по exe, а пакет Store —
// по package:<семейство>. Путь в стиле Windows, а тест идёт на маке: имя —
// после последней «\».
func readExe(path string) (apps.App, error) {
	if family, ok := strings.CutPrefix(path, apps.PackagePrefix); ok {
		name, _, _ := strings.Cut(family, "_")
		return apps.App{ID: strings.ToLower(path), Name: name, Path: path, Instant: true}, nil
	}
	file := path[strings.LastIndex(path, `\`)+1:]
	return apps.App{ID: strings.ToLower(path), Name: strings.TrimSuffix(file, ".exe"), Path: path, Instant: true, Exe: file}, nil
}

// exeService — служба, которая узнаёт приложения, как на Windows: по exe.
func exeService(t *testing.T, root string) (*servicetest.Service, string) {
	t.Helper()
	s := servicetest.Start(t, root, servicetest.Fakes{Accounts: &servicetest.Accounts{Admin: true}, ReadApp: readExe})
	return s, `C:\Program Files\Notion\Notion.exe`
}

// appClosed — приложение под фильтрами, и ни одного адреса, с которого ему можно в сеть.
func appClosed(exe string) func(enforce.Rules) bool {
	return func(r enforce.Rules) bool { return slices.Equal(r.Apps, []string{exe}) && len(r.OpenAddrs) == 0 }
}

func appOpenFrom(exe string, addrs ...netip.Addr) func(enforce.Rules) bool {
	return func(r enforce.Rules) bool {
		return slices.Equal(r.Apps, []string{exe}) && slices.Equal(r.OpenAddrs, addrs)
	}
}

func TestExeAppIsProtectedAtOnce(t *testing.T) {
	s, exe := exeService(t, "")
	resp := addApp(t, s, exe)
	if !resp.OK || resp.App == nil || resp.App.Name != "Notion" || !resp.App.Learned {
		t.Fatalf("добавление: %+v", resp)
	}
	if a, ok := app(s.Status(t), strings.ToLower(exe)); !ok || !a.Learned {
		t.Fatalf("статус: %+v", s.Status(t).Apps)
	}
	waitRules(t, s, time.Second, appClosed(exe))
	hasLine(t, s, "Notion защищено: сеть у него только через проверенный VPN")
	if lineIndex(s.Journal(t), "ждёт обучения") >= 0 {
		t.Fatalf("приложение по exe ждёт обучения:\n%s", strings.Join(s.Journal(t), "\n"))
	}
}

func TestExeAppGoesOnlineOnlyThroughVerifiedTunnel(t *testing.T) {
	s, exe := exeService(t, "")
	addApp(t, s, exe)
	waitRules(t, s, time.Second, appClosed(exe))

	// Туннель появился, выход ещё проверяется — сети нет.
	s.Web.Set("185.1.2.3", "DE", "DE")
	s.Web.Hold()
	s.Network.Set(wintun)
	s.WaitStatus(t, time.Second, func(st ipc.Status) bool { return len(st.Paths) == 1 && st.Paths[0].State == "pending" })
	time.Sleep(3 * servicetest.CheckEvery)
	if r := s.Enforce.Rules(); !appClosed(exe)(r) {
		t.Fatalf("пока выход проверяется, приложению открыт адрес: %+v", r)
	}

	// Выход проверен — сеть с адреса туннеля, и не раньше, чем журнал это показал.
	s.Web.Release()
	waitRules(t, s, 2*time.Second, appOpenFrom(exe, wintunAddr))
	lines := s.Journal(t)
	if verified, opened := lineIndex(lines, "AmneziaVPN: выход 185.1.2.3, Германия — проверен"), lineIndex(lines, "сервисы открыты"); verified < 0 || opened < verified {
		t.Fatalf("приложение открыто раньше, чем журнал показал проверенный выход:\n%s", strings.Join(lines, "\n"))
	}

	// Клиент переключился на российский сервер — закрыто.
	s.Web.Set("95.1.2.3", "RU", "RU")
	waitRules(t, s, 5*servicetest.CheckEvery+time.Second, appClosed(exe))
	hasLine(t, s, "сервисы закрыты: выход в России (95.1.2.3)")

	// Снова зарубежный выход, потом VPN выключили — закрыто сразу.
	s.Web.Set("185.1.2.3", "DE", "DE")
	waitRules(t, s, 5*servicetest.CheckEvery+time.Second, appOpenFrom(exe, wintunAddr))
	s.Network.Set()
	waitRules(t, s, time.Second, appClosed(exe))
	hasLine(t, s, "сервисы закрыты: VPN выключен")

	// За всё время приложению открывался только адрес проверенного туннеля.
	for _, r := range s.Enforce.History() {
		for _, a := range r.OpenAddrs {
			if a != wintunAddr {
				t.Fatalf("приложению открывался адрес %s", a)
			}
		}
	}
}

func TestExeAppSurvivesRestartAndIsRemoved(t *testing.T) {
	root := t.TempDir()
	s, exe := exeService(t, root)
	addApp(t, s, exe)
	waitRules(t, s, time.Second, appClosed(exe))
	s.Stop()

	// После перезапуска фильтры на приложение ставятся из настроек.
	s, _ = exeService(t, root)
	waitRules(t, s, time.Second, appClosed(exe))

	resp, err := ipc.Call(s.Layout.Socket, ipc.Request{Cmd: ipc.CmdRemoveApp, AppID: strings.ToLower(exe)})
	if err != nil || !resp.OK {
		t.Fatalf("снятие: %v %+v", err, resp)
	}
	waitRules(t, s, time.Second, func(r enforce.Rules) bool { return len(r.Apps) == 0 })
}

// Имя для людей на Windows — из ярлыка «Пуска»: у Squirrel-приложений exe
// называется Update.exe. Управляющие символы из имени выбрасываются.
func TestExeAppTakesNameFromShortcut(t *testing.T) {
	s, _ := exeService(t, "")
	exe := `C:\Users\u\AppData\Local\Discord\Update.exe`
	resp, err := ipc.Call(s.Layout.Socket, ipc.Request{Cmd: ipc.CmdAddApp, Path: exe, Name: " Disc\x07ord\n"})
	if err != nil || !resp.OK || resp.App.Name != "Discord" {
		t.Fatalf("добавление: %v %+v", err, resp.App)
	}
	hasLine(t, s, "Discord защищено")
}

// Каталог на Windows узнаёт приложение по имени exe или по пакету Store: так у
// него без обучения есть домены и адреса — и сайт сервиса закрыт в браузере.
func TestWindowsAppFromCatalogBringsItsServiceAddresses(t *testing.T) {
	up := servicetest.NewDNS("Cloudflare")
	up.Maps("notion.so", "208.103.161.17")
	up.Maps("spotify.com", "35.186.224.25")
	s := servicetest.Start(t, "", servicetest.Fakes{Accounts: &servicetest.Accounts{Admin: true}, DNS: up, ReadApp: readExe})
	cat := `{"format": 1, "updated": "2026-10-15", "apps": [
		{"name": "Notion", "windows": {"exe": ["notion.exe"]}, "domains": ["notion.so"], "addrs": ["208.103.161.2"]},
		{"name": "Spotify", "windows": {"store": "SpotifyAB.SpotifyMusic_zpdnekdrzrea0"}, "domains": ["spotify.com"]}
	]}`
	if resp := s.LoadCatalog(t, cat); !resp.OK {
		t.Fatalf("каталог: %+v", resp)
	}
	for _, path := range []string{`C:\Users\u\AppData\Local\Programs\Notion\Notion.exe`, "package:SpotifyAB.SpotifyMusic_zpdnekdrzrea0"} {
		if resp := addApp(t, s, path); !resp.OK || !resp.App.Catalog || !resp.App.Learned {
			t.Fatalf("%s: %+v", path, resp.App)
		}
	}
	waitRules(t, s, 2*time.Second, func(r enforce.Rules) bool {
		return len(r.Apps) == 2 && has(r, "208.103.161.2") && has(r, "208.103.161.17") && has(r, "35.186.224.25")
	})
	if got := s.SystemDNS.Domains(); !slices.Equal(got, []string{"notion.so", "spotify.com"}) {
		t.Fatalf("на службу направлены %v", got)
	}
	hasLine(t, s, "Notion защищено по каталогу")
	hasLine(t, s, "Spotify защищено по каталогу")
}
