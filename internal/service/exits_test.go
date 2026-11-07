package service_test

import (
	"strings"
	"testing"
	"time"

	"vpnlock/internal/enforce"
	"vpnlock/internal/ipc"
	"vpnlock/internal/service/servicetest"
)

// Сценарии таски 07: правило «только мои выходы» и «Запомнить текущий выход».

func setRule(t *testing.T, s *servicetest.Service, rule string) {
	t.Helper()
	resp, err := ipc.Call(s.Layout.Socket, ipc.Request{Cmd: ipc.CmdRule, Rule: rule})
	if err != nil || !resp.OK {
		t.Fatalf("правило %s: %v %+v", rule, err, resp)
	}
}

func remember(t *testing.T, s *servicetest.Service, name string) ipc.Response {
	t.Helper()
	resp, err := ipc.Call(s.Layout.Socket, ipc.Request{Cmd: ipc.CmdRemember, Name: name})
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// withExit — служба с защищённым notion.so, VPN проверен с выходом ip в country.
func withExit(t *testing.T, root, ip, country string) *servicetest.Service {
	t.Helper()
	up := servicetest.NewDNS("Cloudflare")
	up.Maps(domain, notion4.String())
	s := servicetest.Start(t, root, servicetest.Fakes{Accounts: &servicetest.Accounts{Admin: true}, DNS: up})
	s.Protect(t, domain)
	s.Web.Set(ip, country, country)
	s.Network.Set(utun)
	s.WaitStatus(t, 2*time.Second, func(st ipc.Status) bool { return len(st.Paths) == 1 && st.Paths[0].State != "pending" })
	return s
}

var openUtun = func(r enforce.Rules) bool { return len(r.OpenIfaces) == 1 && r.OpenIfaces[0] == "utun11" }
var closedAll = func(r enforce.Rules) bool { return len(r.OpenIfaces) == 0 }

func TestExitFromMyListOpens(t *testing.T) {
	s := withExit(t, "", "185.1.2.3", "DE")
	resp := remember(t, s, "Server 1")
	if !resp.OK || resp.Exit.IP != "185.1.2.3" || resp.Exit.Country != "DE" {
		t.Fatalf("запомнить: %+v", resp)
	}
	hasLine(t, s, "запомнен выход «Server 1» — 185.1.2.3, Германия")
	setRule(t, s, "mine")
	waitRules(t, s, time.Second, openUtun)
	if st := s.Status(t); st.Rule != "mine" || len(st.Exits) != 1 || st.Exits[0].Name != "Server 1" {
		t.Fatalf("статус: %+v", st)
	}
}

func TestExitNotFromMyListStaysClosed(t *testing.T) {
	s := withExit(t, "", "185.1.2.3", "DE")
	remember(t, s, "Server 1")
	setRule(t, s, "mine")
	waitRules(t, s, time.Second, openUtun)

	// Клиент перешёл на другой сервер того же подключения — выход не из списка:
	// закрыто не позже чем через 5 секунд (в тесте — несколько проверок).
	s.Web.Set("203.0.113.5", "NL", "NL")
	waitRules(t, s, 5*servicetest.CheckEvery+time.Second, closedAll)
	hasLine(t, s, "сервисы закрыты: выход 203.0.113.5, Нидерланды — не из твоего списка")
}

func TestEmptyListClosesEverything(t *testing.T) {
	s := withExit(t, "", "185.1.2.3", "DE")
	waitRules(t, s, time.Second, openUtun)
	setRule(t, s, "mine")
	waitRules(t, s, time.Second, closedAll)
	hasLine(t, s, "в твоём списке пока нет ни одного выхода")
}

func TestRuleChangesOnTheFly(t *testing.T) {
	s := withExit(t, "", "203.0.113.5", "NL")
	waitRules(t, s, time.Second, openUtun)
	setRule(t, s, "mine")
	waitRules(t, s, time.Second, closedAll)
	hasLine(t, s, "правило: только мои выходы")
	setRule(t, s, "any")
	waitRules(t, s, time.Second, openUtun)
	hasLine(t, s, "правило: любой выход не из России")

	resp, _ := ipc.Call(s.Layout.Socket, ipc.Request{Cmd: ipc.CmdRule, Rule: "pause"})
	if resp.OK {
		t.Fatal("принято несуществующее правило")
	}
}

func TestRussianExitIsNotRemembered(t *testing.T) {
	s := withExit(t, "", "95.1.2.3", "RU")
	resp := remember(t, s, "Работа")
	if resp.OK || !strings.Contains(resp.Error, "российский выход не сохраняется") {
		t.Fatalf("%+v", resp)
	}
	if st := s.Status(t); len(st.Exits) != 0 {
		t.Fatalf("российский выход сохранён: %+v", st.Exits)
	}
}

func TestNothingToRememberWithoutVPN(t *testing.T) {
	s := servicetest.Start(t, "", servicetest.Fakes{Accounts: &servicetest.Accounts{Admin: true}})
	if resp := remember(t, s, "Server 1"); resp.OK || !strings.Contains(resp.Error, "нет проверенного выхода") {
		t.Fatalf("%+v", resp)
	}
	user := servicetest.Start(t, "", servicetest.Fakes{})
	if resp := remember(t, user, "Server 1"); resp.OK || resp.Code != ipc.CodeForbidden {
		t.Fatalf("не администратор запомнил выход: %+v", resp)
	}
}

// Цепочка «сервер в России → выход за границей»: служба видит и запоминает
// адрес выхода (его называют источники проверки), а не адрес сервера, поэтому
// такой выход открывает сервисы.
func TestChainWithRussianServerIsRememberedByItsExit(t *testing.T) {
	s := withExit(t, "", "185.1.2.3", "DE") // выход за границей; сервер — где угодно
	remember(t, s, "Цепочка")
	setRule(t, s, "mine")
	waitRules(t, s, time.Second, openUtun)
}

func TestExitsSurviveRestart(t *testing.T) {
	root := t.TempDir()
	s := withExit(t, root, "185.1.2.3", "DE")
	remember(t, s, "Server 1")
	setRule(t, s, "mine")
	s.Stop()
	again := servicetest.Start(t, root, servicetest.Fakes{})
	if st := again.Status(t); st.Rule != "mine" || len(st.Exits) != 1 || st.Exits[0].IP != "185.1.2.3" {
		t.Fatalf("после перезапуска: %+v", st)
	}
}

func TestExportDropsMyExits(t *testing.T) {
	s, path := adminWithApp(t, "")
	addApp(t, s, path)
	s.Web.Set("185.1.2.3", "DE", "DE")
	s.Network.Set(utun)
	s.WaitStatus(t, 2*time.Second, onePath("verified"))
	remember(t, s, "Server 1")
	s.Web.Set("203.0.113.5", "NL", "NL") // вышли через другой сервер, а старый адрес приложение ещё видит
	s.Apps.Run(notionID, "208.103.161.2:443", "185.1.2.3:443")
	s.WaitStatus(t, 2*time.Second, func(st ipc.Status) bool { a, _ := app(st, notionID); return a.Learned })

	resp, _ := ipc.Call(s.Layout.Socket, ipc.Request{Cmd: ipc.CmdExport})
	if len(resp.Learned) != 1 || len(resp.Learned[0].Addrs) != 1 || resp.Learned[0].Addrs[0] != "208.103.161.2" {
		t.Fatalf("выгружено %+v", resp.Learned)
	}
	found := false
	for _, d := range resp.Dropped {
		found = found || (d.Value == "185.1.2.3" && strings.Contains(d.Why, "твой выход «Server 1»"))
	}
	if !found {
		t.Fatalf("сохранённый выход не отброшен: %+v", resp.Dropped)
	}
}
