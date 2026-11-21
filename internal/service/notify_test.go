package service_test

import (
	"context"
	"slices"
	"sync"
	"testing"
	"time"

	"vpnlock/internal/core"
	"vpnlock/internal/ipc"
	"vpnlock/internal/service/servicetest"
)

// Сценарии таски 11, К26 и таски 45: при каждом закрытии сервисов — одно
// системное уведомление с причиной, при открытии и смене выхода — одно с адресом
// и страной выхода; о коротком обрыве — ни одного; выключаются одной командой
// (и из меню значка, без прав администратора), журнал пишется всегда.

const (
	offline  = "Защищённые приложения без сети: VPN выключен"
	onlineDE = "Защищённые приложения в сети: выход 185.1.2.3, Германия"
)

func waitNotes(t *testing.T, s *servicetest.Service, want ...string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !slices.Equal(s.Notify.Texts(), want) {
		if time.Now().After(deadline) {
			t.Fatalf("уведомления %q, а нужны %q", s.Notify.Texts(), want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func setNotify(t *testing.T, s *servicetest.Service, on bool) {
	t.Helper()
	resp, err := ipc.Call(s.Layout.Socket, ipc.Request{Cmd: ipc.CmdNotify, Notify: on})
	if err != nil || !resp.OK {
		t.Fatalf("уведомления %v: %v %+v", on, err, resp)
	}
}

func TestEachClosingNotifiesOnceWithTheReason(t *testing.T) {
	s := protected(t)
	waitNotes(t, s, offline)

	s.Web.Set("185.1.2.3", "DE", "DE")
	s.Network.Set(utun)
	waitRules(t, s, 2*time.Second, openOn("utun11"))

	// Клиент перешёл на российский сервер: новое закрытие — новое уведомление.
	s.Web.Set("95.1.2.3", "RU", "RU")
	waitRules(t, s, 2*time.Second, closed)
	waitNotes(t, s, offline, onlineDE, "Защищённые приложения без сети: выход в России (95.1.2.3)")

	// Проверки идут дальше — это то же закрытие.
	time.Sleep(5 * servicetest.CheckEvery)
	if n := len(s.Notify.Texts()); n != 3 {
		t.Fatalf("повторные проверки дали уведомления: %q", s.Notify.Texts())
	}
}

// Человек видит, что приложения в сети и через какой выход: уведомление при
// открытии, ещё одно — когда выход сменился, а сервисы остались открыты.
func TestOpeningNotifiesOnceWithTheExit(t *testing.T) {
	s := protected(t)
	waitNotes(t, s, offline)

	s.Web.Set("185.1.2.3", "DE", "DE")
	s.Network.Set(utun)
	waitRules(t, s, 2*time.Second, openOn("utun11"))
	waitNotes(t, s, offline, onlineDE)
	hasLine(t, s, "сервисы открыты: выход 185.1.2.3, Германия")

	// Проверки идут дальше с тем же выходом — это то же открытие.
	time.Sleep(5 * servicetest.CheckEvery)
	waitNotes(t, s, offline, onlineDE)

	// Клиент внутри подключения перешёл на сервер в другой стране: сервисы
	// открыты, но выход другой — человеку стоит это знать.
	s.Web.Set("45.1.2.3", "NL", "NL")
	waitNotes(t, s, offline, onlineDE, "Защищённые приложения в сети: выход 45.1.2.3, Нидерланды")
	waitRules(t, s, time.Second, openOn("utun11"))

	// VPN выключили и включили снова — снова закрытие и открытие.
	s.Network.Set()
	waitRules(t, s, time.Second, closed)
	s.Network.Set(utun)
	waitRules(t, s, 2*time.Second, openOn("utun11"))
	waitNotes(t, s, offline, onlineDE, "Защищённые приложения в сети: выход 45.1.2.3, Нидерланды",
		offline, "Защищённые приложения в сети: выход 45.1.2.3, Нидерланды")
}

func TestBlocksWithinOneClosingDoNotNotify(t *testing.T) {
	s := protected(t)
	waitNotes(t, s, offline)
	// Сеть шевелится, правила пересчитываются, а VPN всё так же нет.
	for range 3 {
		s.Network.Set()
	}
	s.Protect(t, domain)
	time.Sleep(5 * servicetest.CheckEvery)
	waitNotes(t, s, offline)
}

func TestNotificationsOffJournalStays(t *testing.T) {
	s := withExit(t, "", "185.1.2.3", "DE")
	waitRules(t, s, time.Second, openUtun)
	// До VPN служба уже уведомила: «VPN выключен», затем — об открытии.
	waitNotes(t, s, offline, onlineDE)
	setNotify(t, s, false)
	hasLine(t, s, "уведомления выключены — журнал пишется, как прежде")
	if st := s.Status(t); !st.NotifyOff {
		t.Fatalf("статус: %+v", st)
	}

	s.Network.Set()
	hasLine(t, s, "сервисы закрыты: VPN выключен")
	time.Sleep(3 * servicetest.CheckEvery)
	if n := s.Notify.Texts(); len(n) != 2 {
		t.Fatalf("уведомления выключены, а пришли: %q", n)
	}

	// Включили посреди закрытия — о нём уже не напоминаем; следующие открытие
	// и закрытие снова с уведомлениями.
	setNotify(t, s, true)
	time.Sleep(3 * servicetest.CheckEvery)
	waitNotes(t, s, offline, onlineDE)
	s.Network.Set(utun)
	waitRules(t, s, 2*time.Second, openUtun)
	s.Network.Set()
	waitNotes(t, s, offline, onlineDE, onlineDE, offline)
}

// Уведомления выключает и значок у часов, а он работает от имени человека, без
// прав администратора: защиту они не меняют.
func TestNotificationsSettingSurvivesRestartAndNeedsNoAdmin(t *testing.T) {
	root := t.TempDir()
	s := servicetest.Start(t, root, servicetest.Fakes{Accounts: &servicetest.Accounts{Admin: true}})
	setNotify(t, s, false)
	s.Stop()

	again := servicetest.Start(t, root, servicetest.Fakes{Accounts: &servicetest.Accounts{Admin: false}})
	if st := again.Status(t); !st.NotifyOff {
		t.Fatalf("после перезапуска уведомления снова включены: %+v", st)
	}
	setNotify(t, again, true)
	if st := again.Status(t); st.NotifyOff {
		t.Fatalf("без прав администратора уведомления не включились: %+v", st)
	}
	resp, err := ipc.Call(again.Layout.Socket, ipc.Request{Cmd: ipc.CmdRule, Rule: core.RuleMine})
	if err != nil || resp.OK || resp.Code != ipc.CodeForbidden {
		t.Fatalf("правило без прав: %v %+v", err, resp)
	}
}

// protectedAfter — защищённый домен и уведомление о закрытии через after.
func protectedAfter(t *testing.T, after time.Duration) *servicetest.Service {
	t.Helper()
	up := servicetest.NewDNS("Cloudflare")
	up.Maps(domain, notion4.String(), notion6.String())
	s := servicetest.Start(t, "", servicetest.Fakes{Accounts: &servicetest.Accounts{Admin: true}, DNS: up, NotifyAfter: after})
	s.Protect(t, domain)
	return s
}

// VPN переподключается — сервисы закрыты сразу, а человека это не дёргает: о
// закрытии короче NotifyAfter уведомления нет, открытие тем же выходом — то же
// событие, что и до обрыва. Обрыв дольше — оба уведомления.
func TestShortDropsDoNotNotify(t *testing.T) {
	const after = time.Second
	s := protectedAfter(t, after)
	// Служба стартовала без VPN, закрытие длится — уведомление приходит.
	waitNotes(t, s, offline)
	s.Web.Set("185.1.2.3", "DE", "DE")
	s.Network.Set(utun)
	waitRules(t, s, 2*time.Second, openOn("utun11"))
	waitNotes(t, s, offline, onlineDE)

	s.Network.Set()
	waitRules(t, s, time.Second, closed)
	s.Network.Set(utun)
	waitRules(t, s, 2*time.Second, openOn("utun11"))
	time.Sleep(after + 5*servicetest.CheckEvery)
	if got := s.Notify.Texts(); !slices.Equal(got, []string{offline, onlineDE}) {
		t.Fatalf("короткий обрыв дал уведомления: %q", got)
	}

	s.Network.Set()
	waitRules(t, s, time.Second, closed)
	time.Sleep(after / 2)
	if got := s.Notify.Texts(); len(got) != 2 {
		t.Fatalf("о закрытии уведомили раньше срока: %q", got)
	}
	waitNotes(t, s, offline, onlineDE, offline)
	s.Network.Set(utun)
	waitNotes(t, s, offline, onlineDE, offline, onlineDE)
}

// waitProtection ждёт, пока служба не скажет значку want.
func waitProtection(t *testing.T, s *servicetest.Service, want ipc.Protection) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		resp, err := ipc.Call(s.Layout.Socket, ipc.Request{Cmd: ipc.CmdProtection})
		if err == nil && resp.OK && resp.Protection != nil && *resp.Protection == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("значку: %v %+v, а нужно %+v", err, resp.Protection, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Значок у часов показывает защиту сейчас: открыта ли, выход или причина, и
// включены ли уведомления. Спросить может любой: в ответе то же, что в журнале.
func TestProtectionForTheTrayIcon(t *testing.T) {
	up := servicetest.NewDNS("Cloudflare")
	up.Maps(domain, notion4.String(), notion6.String())
	s := servicetest.Start(t, "", servicetest.Fakes{Accounts: &servicetest.Accounts{Admin: false}, DNS: up})
	waitProtection(t, s, ipc.Protection{Reason: "VPN выключен"})

	s.Web.Set("185.1.2.3", "DE", "DE")
	s.Network.Set(utun)
	waitProtection(t, s, ipc.Protection{Open: true, IP: "185.1.2.3", Country: "DE"})

	setNotify(t, s, false)
	waitProtection(t, s, ipc.Protection{Open: true, IP: "185.1.2.3", Country: "DE", NotifyOff: true})

	s.Web.Set("95.1.2.3", "RU", "RU")
	waitProtection(t, s, ipc.Protection{Reason: "выход в России (95.1.2.3)", NotifyOff: true})
}

// subscribe — уведомления, которые служба раздаёт по каналу (их показывает
// задача в сеансе пользователя на Windows): вид события и текст.
func subscribe(t *testing.T, s *servicetest.Service) func() []string {
	t.Helper()
	var mu sync.Mutex
	var got []string
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go ipc.StreamContext(ctx, s.Layout.Socket, ipc.Request{Cmd: ipc.CmdNotifications}, func(r ipc.Response) error {
		if r.OK && r.Event != nil {
			mu.Lock()
			got = append(got, r.Event.Kind+" "+r.Event.Text)
			mu.Unlock()
		}
		return nil
	})
	// Подписка встаёт, когда служба приняла запрос: даём ей мгновение.
	time.Sleep(100 * time.Millisecond)
	return func() []string {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(got)
	}
}

func TestNotificationsReachSubscribedClients(t *testing.T) {
	s := protected(t)
	waitNotes(t, s, offline)
	notes := subscribe(t, s)

	s.Web.Set("185.1.2.3", "DE", "DE")
	s.Network.Set(utun)
	waitRules(t, s, 2*time.Second, openOn("utun11"))
	s.Network.Set()
	waitRules(t, s, time.Second, closed)
	want := []string{core.KindOpen + " " + onlineDE, core.KindClosed + " " + offline}
	deadline := time.Now().Add(2 * time.Second)
	for !slices.Equal(notes(), want) {
		if time.Now().After(deadline) {
			t.Fatalf("подписчик получил %q", notes())
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Выключены — и подписчикам ничего, хотя журнал пишется.
	setNotify(t, s, false)
	s.Network.Set(utun)
	waitRules(t, s, 2*time.Second, openOn("utun11"))
	s.Network.Set()
	waitRules(t, s, time.Second, closed)
	time.Sleep(3 * servicetest.CheckEvery)
	if n := len(notes()); n != 2 {
		t.Fatalf("уведомления выключены, а подписчику пришло: %q", notes())
	}
}
