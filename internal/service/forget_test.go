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

// Сценарии таски 40: выход по адресу без подключения, «забыть выход» и
// «забыть» выученное приложением по ошибке.

func rememberAt(t *testing.T, s *servicetest.Service, name, ip string) ipc.Response {
	t.Helper()
	resp, err := ipc.Call(s.Layout.Socket, ipc.Request{Cmd: ipc.CmdRemember, Name: name, IP: ip})
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func forgetExit(t *testing.T, s *servicetest.Service, which string) ipc.Response {
	t.Helper()
	resp, err := ipc.Call(s.Layout.Socket, ipc.Request{Cmd: ipc.CmdForgetExit, Name: which})
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func forgetLearned(t *testing.T, s *servicetest.Service, id string, items ...string) ipc.Response {
	t.Helper()
	resp, err := ipc.Call(s.Layout.Socket, ipc.Request{Cmd: ipc.CmdForgetLearned, AppID: id, Addrs: items})
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func detail(t *testing.T, s *servicetest.Service, id string) ipc.AppDetail {
	t.Helper()
	resp, err := ipc.Call(s.Layout.Socket, ipc.Request{Cmd: ipc.CmdApp, AppID: id})
	if err != nil || !resp.OK || resp.Detail == nil {
		t.Fatalf("app: %v %+v", err, resp)
	}
	return *resp.Detail
}

// Выход Сингапура запомнен по адресу, пока VPN — Германия. Сервисы он не
// открывает, пока служба не выйдет через него сама; тогда известна и страна.
func TestRememberExitByAddress(t *testing.T) {
	s := withExit(t, "", "185.1.2.3", "DE")
	if resp := rememberAt(t, s, "Дом", "192.168.1.1"); resp.OK || !strings.Contains(resp.Error, "не адрес выхода") {
		t.Fatalf("частный адрес: %+v", resp)
	}
	resp := rememberAt(t, s, "Сингапур", "203.0.113.7")
	if !resp.OK || resp.Exit.IP != "203.0.113.7" || !resp.Exit.Unverified || resp.Exit.Country != "" {
		t.Fatalf("запомнить по адресу: %+v", resp)
	}
	hasLine(t, s, "запомнен выход «Сингапур» — 203.0.113.7, введён вручную")

	setRule(t, s, "mine")
	waitRules(t, s, time.Second, closedAll) // выход сейчас немецкий — не из списка

	s.Web.Set("203.0.113.7", "SG", "SG")
	waitRules(t, s, 5*servicetest.CheckEvery+time.Second, openUtun)
	st := s.WaitStatus(t, time.Second, func(st ipc.Status) bool { return len(st.Exits) == 1 && !st.Exits[0].Unverified })
	if st.Exits[0].Country != "SG" {
		t.Fatalf("после выхода через него: %+v", st.Exits)
	}
	hasLine(t, s, "выход «Сингапур» подтверждён: служба вышла через него — 203.0.113.7, Сингапур")
}

// Адрес текущего выхода, введённый руками, — это просто текущий выход.
func TestRememberCurrentExitByAddress(t *testing.T) {
	s := withExit(t, "", "185.1.2.3", "DE")
	if resp := rememberAt(t, s, "Германия", "185.1.2.3"); !resp.OK || resp.Exit.Unverified || resp.Exit.Country != "DE" {
		t.Fatalf("%+v", resp)
	}
}

// Российский адрес, введённый руками, сервисы не откроет: выход через него не
// проходит проверку.
func TestManualRussianExitNeverOpens(t *testing.T) {
	s := withExit(t, "", "185.1.2.3", "DE")
	rememberAt(t, s, "Москва", "95.1.2.3")
	setRule(t, s, "mine")
	s.Web.Set("95.1.2.3", "RU", "RU")
	st := s.WaitStatus(t, 5*servicetest.CheckEvery+time.Second, onePath("russian"))
	if r := s.Enforce.Rules(); len(r.OpenIfaces) != 0 {
		t.Fatalf("российский выход из списка открыл сервисы: %+v", r.OpenIfaces)
	}
	if !st.Exits[0].Unverified {
		t.Fatalf("российский выход отмечен проверенным: %+v", st.Exits)
	}
}

func TestForgetExit(t *testing.T) {
	s := withExit(t, "", "185.1.2.3", "DE")
	remember(t, s, "Германия")
	rememberAt(t, s, "Сингапур", "203.0.113.7")
	setRule(t, s, "mine")
	waitRules(t, s, time.Second, openUtun)

	resp := forgetExit(t, s, "германия") // имя — без учёта регистра
	if !resp.OK || len(resp.Exits) != 1 || resp.Exits[0].IP != "185.1.2.3" {
		t.Fatalf("забыть по имени: %+v", resp)
	}
	waitRules(t, s, time.Second, closedAll)
	hasLine(t, s, "забыт выход «Германия» — 185.1.2.3")

	if resp := forgetExit(t, s, "203.0.113.7"); !resp.OK || len(resp.Exits) != 1 || resp.Exits[0].Name != "Сингапур" {
		t.Fatalf("забыть по адресу: %+v", resp)
	}
	if st := s.Status(t); len(st.Exits) != 0 {
		t.Fatalf("выходы остались: %+v", st.Exits)
	}
	if resp := forgetExit(t, s, "Германия"); resp.OK || !strings.Contains(resp.Error, "в списке нет") {
		t.Fatalf("забыть несуществующий: %+v", resp)
	}
	user := servicetest.Start(t, "", servicetest.Fakes{})
	if resp := forgetExit(t, user, "Германия"); resp.OK || resp.Code != ipc.CodeForbidden {
		t.Fatalf("не администратор: %+v", resp)
	}
}

// Адрес, выученный по ошибке, уходит из таблиц, и приложение его больше не
// выучит, даже если продолжит туда ходить.
func TestForgottenAddressIsNotLearnedAgain(t *testing.T) {
	s, path := adminWithApp(t, "")
	addApp(t, s, path)
	s.Web.Set("185.1.2.3", "DE", "DE")
	s.Network.Set(utun)
	s.WaitStatus(t, 2*time.Second, onePath("verified"))
	s.Apps.Run(notionID, "104.18.0.7:443", "203.0.113.50:443")
	s.WaitStatus(t, 2*time.Second, func(st ipc.Status) bool { a, _ := app(st, notionID); return a.Learned && a.Addrs == 2 })

	resp := forgetLearned(t, s, notionID, "203.0.113.50", "198.51.100.1", "example.com")
	if !resp.OK || !slices.Equal(resp.Forgotten, []string{"203.0.113.50"}) || len(resp.Warnings) != 2 ||
		!strings.Contains(resp.Warnings[0], "198.51.100.1 у Notion не выучен") || !strings.Contains(resp.Warnings[1], "домена example.com у Notion нет") {
		t.Fatalf("забыть: %+v", resp)
	}
	waitRules(t, s, time.Second, func(r enforce.Rules) bool { return !has(r, "203.0.113.50") && has(r, "104.18.0.7") })
	hasLine(t, s, "Notion: забыто 203.0.113.50 — приложение их больше не выучит")

	time.Sleep(3 * servicetest.ScanEvery) // соединение с забытым адресом всё ещё открыто
	if has(s.Enforce.Rules(), "203.0.113.50") {
		t.Fatal("забытый адрес выучен снова")
	}
	if d := detail(t, s, notionID); !slices.Equal(d.Addrs, []string{"104.18.0.7"}) || !slices.Equal(d.Forgotten, []string{"203.0.113.50"}) {
		t.Fatalf("приложение: %+v", d)
	}
	if resp := forgetLearned(t, s, "no.such.app", "104.18.0.7"); resp.OK {
		t.Fatalf("забыто у несуществующего приложения: %+v", resp)
	}
}

// Домен, выученный по ошибке (сайт, открытый во время обучения), уходит вместе
// с поддоменами: не направляется на службу и не выучивается снова.
func TestForgottenDomainIsNotLearnedAgain(t *testing.T) {
	s, path := adminWithApp(t, "")
	addApp(t, s, path)
	s.Web.Set("185.1.2.3", "DE", "DE")
	s.Network.Set(utun)
	listening(t, s, "utun11")
	s.Answers.Say("utun11", "blog.example.com", "203.0.113.60")
	s.Apps.Run(notionID, "203.0.113.60:443")
	s.WaitStatus(t, 2*time.Second, func(st ipc.Status) bool { a, _ := app(st, notionID); return a.Domains == 1 })

	resp := forgetLearned(t, s, notionID, "www.blog.example.com", "203.0.113.60", "BLOG.example.com")
	if !resp.OK || !slices.Equal(resp.Forgotten, []string{"203.0.113.60", "blog.example.com"}) ||
		len(resp.Warnings) != 1 || !strings.Contains(resp.Warnings[0], "входит в домен blog.example.com") {
		t.Fatalf("забыть: %+v", resp)
	}
	if got := s.SystemDNS.Domains(); len(got) != 0 {
		t.Fatalf("забытый домен направлен на службу: %v", got)
	}

	// Новое соединение с поддоменом забытого — не учится.
	s.Apps.Run(notionID)
	time.Sleep(2 * servicetest.ScanEvery)
	s.Answers.Say("utun11", "cdn.blog.example.com", "203.0.113.61")
	s.Apps.Run(notionID, "203.0.113.61:443")
	waitRules(t, s, 2*time.Second, func(r enforce.Rules) bool { return has(r, "203.0.113.61") })
	time.Sleep(2 * servicetest.ScanEvery)
	if a, _ := app(s.Status(t), notionID); a.Domains != 0 {
		t.Fatalf("забытый домен выучен снова: %+v", a)
	}
}

// Забытое из каталога обновление каталога не возвращает.
func TestForgottenCatalogEntryIsNotReturned(t *testing.T) {
	s, path := withCatalog(t, "")
	addApp(t, s, path)
	waitRules(t, s, 2*time.Second, func(r enforce.Rules) bool { return has(r, "208.103.161.2") && has(r, "208.103.161.17") })

	if resp := forgetLearned(t, s, notionID, "208.103.161.2", "notion.so"); !resp.OK || len(resp.Forgotten) != 2 {
		t.Fatalf("забыть: %+v", resp)
	}
	waitRules(t, s, time.Second, func(r enforce.Rules) bool { return !has(r, "208.103.161.2") && !has(r, "208.103.161.17") })

	s.LoadCatalog(t, notionCatalog)
	time.Sleep(3 * servicetest.ScanEvery)
	if r := s.Enforce.Rules(); has(r, "208.103.161.2") || has(r, "208.103.161.17") {
		t.Fatal("каталог вернул забытое")
	}
	if got := s.SystemDNS.Domains(); len(got) != 0 {
		t.Fatalf("на службу направлены %v", got)
	}
}
