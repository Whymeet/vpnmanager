package service_test

import (
	"context"
	"slices"
	"sync"
	"testing"
	"time"

	"vpnlock/internal/ipc"
	"vpnlock/internal/service/servicetest"
)

// Сценарии таски 11: при каждом закрытии сервисов — одно системное
// уведомление с причиной; выключаются одной командой, журнал пишется всегда.

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
	waitNotes(t, s, "Защищённые приложения без сети: VPN выключен")

	s.Web.Set("185.1.2.3", "DE", "DE")
	s.Network.Set(utun)
	waitRules(t, s, 2*time.Second, openOn("utun11"))

	// Клиент перешёл на российский сервер: новое закрытие — новое уведомление.
	s.Web.Set("95.1.2.3", "RU", "RU")
	waitRules(t, s, 2*time.Second, closed)
	waitNotes(t, s, "Защищённые приложения без сети: VPN выключен", "Защищённые приложения без сети: выход в России (95.1.2.3)")

	// Проверки идут дальше — это то же закрытие.
	time.Sleep(5 * servicetest.CheckEvery)
	if n := len(s.Notify.Texts()); n != 2 {
		t.Fatalf("повторные проверки дали уведомления: %q", s.Notify.Texts())
	}
}

func TestBlocksWithinOneClosingDoNotNotify(t *testing.T) {
	s := protected(t)
	waitNotes(t, s, "Защищённые приложения без сети: VPN выключен")
	// Сеть шевелится, правила пересчитываются, а VPN всё так же нет.
	for range 3 {
		s.Network.Set()
	}
	s.Protect(t, domain)
	time.Sleep(5 * servicetest.CheckEvery)
	waitNotes(t, s, "Защищённые приложения без сети: VPN выключен")
}

func TestNotificationsOffJournalStays(t *testing.T) {
	s := withExit(t, "", "185.1.2.3", "DE")
	waitRules(t, s, time.Second, openUtun)
	// До VPN служба уже уведомила: «VPN выключен».
	waitNotes(t, s, "Защищённые приложения без сети: VPN выключен")
	setNotify(t, s, false)
	hasLine(t, s, "уведомления выключены — журнал пишется, как прежде")
	if st := s.Status(t); !st.NotifyOff {
		t.Fatalf("статус: %+v", st)
	}

	s.Network.Set()
	hasLine(t, s, "сервисы закрыты: VPN выключен")
	time.Sleep(3 * servicetest.CheckEvery)
	if n := s.Notify.Texts(); len(n) != 1 {
		t.Fatalf("уведомления выключены, а пришли: %q", n)
	}

	// Включили — следующее закрытие снова с уведомлением.
	setNotify(t, s, true)
	s.Network.Set(utun)
	waitRules(t, s, 2*time.Second, openUtun)
	s.Network.Set()
	waitNotes(t, s, "Защищённые приложения без сети: VPN выключен", "Защищённые приложения без сети: VPN выключен")
}

func TestNotificationsSettingSurvivesRestartAndNeedsAdmin(t *testing.T) {
	root := t.TempDir()
	s := servicetest.Start(t, root, servicetest.Fakes{Accounts: &servicetest.Accounts{Admin: true}})
	setNotify(t, s, false)
	s.Stop()

	again := servicetest.Start(t, root, servicetest.Fakes{Accounts: &servicetest.Accounts{Admin: false}})
	if st := again.Status(t); !st.NotifyOff {
		t.Fatalf("после перезапуска уведомления снова включены: %+v", st)
	}
	resp, err := ipc.Call(again.Layout.Socket, ipc.Request{Cmd: ipc.CmdNotify, Notify: true})
	if err != nil || resp.OK || resp.Code != ipc.CodeForbidden {
		t.Fatalf("без прав: %v %+v", err, resp)
	}
}

// subscribe — уведомления, которые служба раздаёт по каналу (их показывает
// задача в сеансе пользователя на Windows).
func subscribe(t *testing.T, s *servicetest.Service) func() []string {
	t.Helper()
	var mu sync.Mutex
	var got []string
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go ipc.StreamContext(ctx, s.Layout.Socket, ipc.Request{Cmd: ipc.CmdNotifications}, func(r ipc.Response) error {
		if r.OK && r.Event != nil {
			mu.Lock()
			got = append(got, r.Event.Text)
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
	waitNotes(t, s, "Защищённые приложения без сети: VPN выключен")
	notes := subscribe(t, s)

	s.Web.Set("185.1.2.3", "DE", "DE")
	s.Network.Set(utun)
	waitRules(t, s, 2*time.Second, openOn("utun11"))
	s.Network.Set()
	waitRules(t, s, time.Second, closed)
	deadline := time.Now().Add(2 * time.Second)
	for !slices.Equal(notes(), []string{"Защищённые приложения без сети: VPN выключен"}) {
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
	if n := len(notes()); n != 1 {
		t.Fatalf("уведомления выключены, а подписчику пришло: %q", notes())
	}
}
