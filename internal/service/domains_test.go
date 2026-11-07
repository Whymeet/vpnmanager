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

// Сценарии таски 25: обучение записывает домены — имена, которые стоят за
// адресами приложения в ответах DNS на проверенном туннеле.

func listening(t *testing.T, s *servicetest.Service, want ...string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !slices.Equal(s.Answers.Listening(), want) {
		if time.Now().After(deadline) {
			t.Fatalf("ответы DNS слушаются на %v, а нужно %v", s.Answers.Listening(), want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestLearningTakesDomainsFromTunnelDNS(t *testing.T) {
	s, path := adminWithApp(t, "")
	// Когда служба сама разрешит выученный домен, у сервиса окажется и новый
	// адрес CDN.
	s.DNS.Maps("api.notion.com", "104.18.0.7", "104.18.0.99")
	addApp(t, s, path)
	listening(t, s) // без проверенного туннеля служба не слушает
	s.Web.Set("185.1.2.3", "DE", "DE")
	s.Network.Set(utun)
	s.WaitStatus(t, 2*time.Second, onePath("verified"))
	listening(t, s, "utun11")

	// Через туннель пришли ответы; приложение соединилось с адресом из первого.
	s.Answers.Say("utun11", "api.notion.com", "104.18.0.7")
	s.Answers.Say("utun11", "ipv4-internet.yandex.net", "104.18.0.7") // зонд «Россия напрямую» — служебное имя
	s.Answers.Say("utun11", "printer.local", "104.18.0.7")
	s.Answers.Say("utun11", "other.example.com", "203.0.113.50") // туда приложение не ходило
	s.Apps.Run(notionID, "104.18.0.7:443")

	// Домен защищён: система спрашивает его у службы, а новый адрес сервиса
	// закрыт вне туннеля для всех программ, в том числе для браузера (К13).
	waitRules(t, s, 2*time.Second, func(r enforce.Rules) bool { return has(r, "104.18.0.7") && has(r, "104.18.0.99") })
	if got := s.SystemDNS.Domains(); !slices.Equal(got, []string{"api.notion.com"}) {
		t.Fatalf("на резолвер службы направлены %v", got)
	}
	st := s.WaitStatus(t, 2*time.Second, func(st ipc.Status) bool { a, _ := app(st, notionID); return a.Learned })
	if a, _ := app(st, notionID); a.Addrs != 1 || a.Domains != 1 {
		t.Fatalf("обученное приложение: %+v", a)
	}
	hasLine(t, s, "Notion защищено: обучение закончено, 1 адрес, 1 домен")

	// Выгрузка в каталог несёт выученный домен (К28).
	resp, err := ipc.Call(s.Layout.Socket, ipc.Request{Cmd: ipc.CmdExport})
	if err != nil || !resp.OK || len(resp.Learned) != 1 || !slices.Contains(resp.Learned[0].Domains, "api.notion.com") {
		t.Fatalf("выгрузка: %v %+v", err, resp)
	}

	// VPN выключен — ответы DNS больше не слушаются.
	s.Network.Set()
	listening(t, s)
}

// Имя — приложению, только если ответ пришёл перед его новым соединением.
// Сайт, открытый в браузере на том же адресе CDN, когда соединение приложения
// уже было, приложению не приписывается: иначе он ушёл бы и в выгрузку.
func TestNameAnsweredAfterTheConnectionIsNotTheApps(t *testing.T) {
	s, path := adminWithApp(t, "")
	addApp(t, s, path)
	s.Web.Set("185.1.2.3", "DE", "DE")
	s.Network.Set(utun)
	listening(t, s, "utun11")
	s.Apps.Run(notionID, "104.18.0.7:443")
	waitRules(t, s, 2*time.Second, func(r enforce.Rules) bool { return has(r, "104.18.0.7") })
	s.Answers.Say("utun11", "author-blog.example.com", "104.18.0.7")
	time.Sleep(3 * servicetest.ScanEvery)
	if a, _ := app(s.Status(t), notionID); a.Domains != 0 {
		t.Fatalf("приложению приписан чужой сайт: %+v", a)
	}
	if got := s.SystemDNS.Domains(); len(got) != 0 {
		t.Fatalf("на резолвер направлены %v", got)
	}
}

// Приложение снято — его выученные домены уходят вместе с ним.
func TestRemovedAppTakesItsLearnedDomains(t *testing.T) {
	s, path := adminWithApp(t, "")
	s.DNS.Maps("api.notion.com", "104.18.0.7")
	addApp(t, s, path)
	s.Web.Set("185.1.2.3", "DE", "DE")
	s.Network.Set(utun)
	listening(t, s, "utun11")
	s.Answers.Say("utun11", "api.notion.com", "104.18.0.7")
	s.Apps.Run(notionID, "104.18.0.7:443")
	s.WaitStatus(t, 2*time.Second, func(st ipc.Status) bool { a, _ := app(st, notionID); return a.Domains == 1 })

	resp, err := ipc.Call(s.Layout.Socket, ipc.Request{Cmd: ipc.CmdRemoveApp, AppID: notionID})
	if err != nil || !resp.OK {
		t.Fatalf("%v %+v", err, resp)
	}
	if got := s.SystemDNS.Domains(); len(got) != 0 {
		t.Fatalf("после снятия приложения направлены %v", got)
	}
}

// Сценарий таски 26: приложение Windows защищено по своим программам сразу, а
// адреса и домены его сервиса учатся фоном, пока путь проверен, — и
// закрываются для всех программ, в том числе для браузера (К13).
func TestExeAppLearnsServiceAddressesInTheBackground(t *testing.T) {
	s, exe := exeService(t, "")
	s.DNS.Maps("api.notion.com", "104.18.0.7", "104.18.0.99")
	if resp := addApp(t, s, exe); !resp.OK || !resp.App.Learned {
		t.Fatalf("добавление: %+v", resp)
	}
	id := strings.ToLower(exe)
	s.Web.Set("185.1.2.3", "DE", "DE")
	s.Network.Set(wintun)
	listening(t, s, "AmneziaVPN")
	s.Answers.Say("AmneziaVPN", "api.notion.com", "104.18.0.7")
	s.Apps.Run(id, "104.18.0.7:443", "1.1.1.1:443")
	waitRules(t, s, 2*time.Second, func(r enforce.Rules) bool { return has(r, "104.18.0.7") && has(r, "104.18.0.99") })
	if has(s.Enforce.Rules(), "1.1.1.1") {
		t.Fatal("служебный адрес выучен")
	}
	if a, _ := app(s.Status(t), id); !a.Learned || a.Addrs != 1 || a.Domains != 1 {
		t.Fatalf("приложение: %+v", a)
	}
}
