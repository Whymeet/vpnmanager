package service_test

import (
	"slices"
	"strings"
	"testing"
	"time"

	"vpnlock/internal/enforce"
	"vpnlock/internal/ipc"
	"vpnlock/internal/service/servicetest"
)

// Сценарии таски 06: каталог. Приложение из каталога защищено сразу,
// выгрузка у автора не уносит его VPN и не трогает необученное.

const notionCatalog = `{"format": 1, "updated": "2026-10-15", "apps": [
	{"name": "Notion", "macos": {"id": "notion.id"}, "domains": ["notion.so"], "addrs": ["208.103.161.2"]}
]}`

// withCatalog — служба с администратором, каталогом и пакетом Notion на диске.
func withCatalog(t *testing.T, root string) (*servicetest.Service, string) {
	t.Helper()
	up := servicetest.NewDNS("Cloudflare")
	up.Maps("notion.so", "208.103.161.17")
	s := servicetest.Start(t, root, servicetest.Fakes{Accounts: &servicetest.Accounts{Admin: true}, DNS: up})
	if resp := s.LoadCatalog(t, notionCatalog); !resp.OK {
		t.Fatalf("каталог: %+v", resp)
	}
	return s, servicetest.App(t, t.TempDir(), "Notion", notionID)
}

func TestCatalogAppIsProtectedAtOnce(t *testing.T) {
	s, path := withCatalog(t, "")
	resp := addApp(t, s, path)
	if !resp.OK || !resp.App.Learned || !resp.App.Catalog {
		t.Fatalf("приложение из каталога не защищено сразу: %+v", resp)
	}
	// Без обучения: адрес из каталога и адреса домена из каталога закрыты,
	// домен направлен на резолвер службы, VPN нет — всё закрыто.
	waitRules(t, s, 2*time.Second, func(r enforce.Rules) bool {
		return len(r.OpenIfaces) == 0 && has(r, "208.103.161.2") && has(r, "208.103.161.17")
	})
	if got := s.SystemDNS.Domains(); !slices.Equal(got, []string{"notion.so"}) {
		t.Fatalf("на службу направлены %v", got)
	}
	hasLine(t, s, "Notion защищено по каталогу: 1 домен, 1 адрес")
}

func TestStatusShowsCatalogDate(t *testing.T) {
	s, _ := withCatalog(t, "")
	if st := s.Status(t); st.Catalog != "2026-10-15" || st.CatalogN != 1 {
		t.Fatalf("каталог в статусе: %q, %d", st.Catalog, st.CatalogN)
	}
	plain := servicetest.Start(t, "", servicetest.Fakes{})
	if st := plain.Status(t); st.Catalog != "" {
		t.Fatalf("каталога нет, а статус говорит %q", st.Catalog)
	}
}

func TestNewerCatalogIsNotApplied(t *testing.T) {
	s, _ := withCatalog(t, "")
	resp := s.LoadCatalog(t, `{"format": 2, "updated": "2027-01-01", "apps": []}`)
	if resp.OK || !strings.Contains(resp.Error, "обнови инструмент") {
		t.Fatalf("каталог новее формата принят: %+v", resp)
	}
	hasLine(t, s, "новый каталог не применён: каталог записан более новой версией vpnlock — обнови инструмент")
	if st := s.Status(t); st.Catalog != "2026-10-15" {
		t.Fatalf("прежний каталог не действует: %q", st.Catalog)
	}
}

func TestCatalogUpdateProtectsWaitingApp(t *testing.T) {
	s := servicetest.Start(t, "", servicetest.Fakes{Accounts: &servicetest.Accounts{Admin: true}})
	path := servicetest.App(t, t.TempDir(), "Notion", notionID)
	if resp := addApp(t, s, path); resp.App.Learned {
		t.Fatalf("без каталога приложение сразу защищено: %+v", resp)
	}
	s.LoadCatalog(t, notionCatalog)
	if a, _ := app(s.Status(t), notionID); !a.Learned || !a.Catalog {
		t.Fatalf("после каталога: %+v", a)
	}
	hasLine(t, s, "Notion защищено по каталогу")
}

func TestRemovingCatalogAppKeepsManualDomains(t *testing.T) {
	s, path := withCatalog(t, "")
	s.DNS.Maps("figma.com", "104.16.0.1")
	s.Protect(t, "figma.com")
	addApp(t, s, path)
	resp, err := ipc.Call(s.Layout.Socket, ipc.Request{Cmd: ipc.CmdRemoveApp, AppID: notionID})
	if err != nil || !resp.OK {
		t.Fatalf("%v %+v", err, resp)
	}
	if got := s.SystemDNS.Domains(); !slices.Equal(got, []string{"figma.com"}) {
		t.Fatalf("после снятия приложения направлены %v — домен приложения должен уйти, ручной остаться", got)
	}
	waitRules(t, s, time.Second, func(r enforce.Rules) bool { return !has(r, "208.103.161.2") && has(r, "104.16.0.1") })
}

func TestExportLeavesOutTheAuthorsVPN(t *testing.T) {
	s, path := adminWithApp(t, "")
	s.DNS.Maps("notion.so", "208.103.161.2")
	s.Protect(t, "notion.so")
	addApp(t, s, path)
	s.Web.Set("203.0.113.89", "DE", "DE")
	s.Network.Set(utun)
	s.Apps.VPNServer("185.199.0.10")
	// Приложение ходит к сервису, к адресу, совпавшему с сервером VPN (VPN за CDN),
	// и к адресу своего выхода.
	s.Apps.Run(notionID, "208.103.161.2:443", "185.199.0.10:443", "203.0.113.89:443")
	s.WaitStatus(t, 2*time.Second, func(st ipc.Status) bool { a, _ := app(st, notionID); return a.Learned })

	other := servicetest.App(t, t.TempDir(), "Figma", "com.figma.Desktop")
	addApp(t, s, other) // ждёт обучения — в выгрузку не идёт

	resp, err := ipc.Call(s.Layout.Socket, ipc.Request{Cmd: ipc.CmdExport})
	if err != nil || !resp.OK {
		t.Fatalf("%v %+v", err, resp)
	}
	if len(resp.Learned) != 1 || resp.Learned[0].ID != notionID {
		t.Fatalf("выгружено %+v", resp.Learned)
	}
	l := resp.Learned[0]
	if !slices.Equal(l.Addrs, []string{"208.103.161.2"}) || !slices.Equal(l.Domains, []string{"notion.so"}) {
		t.Fatalf("Notion в выгрузке: %+v", l)
	}
	why := map[string]string{}
	for _, d := range resp.Dropped {
		why[d.Value] = d.Why
	}
	if !strings.Contains(why["185.199.0.10"], "сервер VPN") || !strings.Contains(why["203.0.113.89"], "выхода VPN") {
		t.Fatalf("отброшено: %+v", resp.Dropped)
	}
}

func TestCatalogSurvivesRestart(t *testing.T) {
	root := t.TempDir()
	s, _ := withCatalog(t, root)
	s.Stop()
	again := servicetest.Start(t, root, servicetest.Fakes{})
	if st := again.Status(t); st.Catalog != "2026-10-15" {
		t.Fatalf("после перезапуска каталог %q", st.Catalog)
	}
}
