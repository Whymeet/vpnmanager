package service_test

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"vpnlock/internal/enforce"
	"vpnlock/internal/ipc"
	"vpnlock/internal/service/servicetest"
)

// Сценарии таски 05: приложения и обучение. Сокеты процессов приложения
// подменены сканером; проверяются статус, правила и журнал.

const notionID = "notion.id"

// adminWithApp — служба с администратором и пакетом Notion на диске.
func adminWithApp(t *testing.T, root string) (*servicetest.Service, string) {
	t.Helper()
	s := servicetest.Start(t, root, servicetest.Fakes{Accounts: &servicetest.Accounts{Admin: true}})
	return s, servicetest.App(t, t.TempDir(), "Notion", notionID)
}

func addApp(t *testing.T, s *servicetest.Service, path string) ipc.Response {
	t.Helper()
	resp, err := ipc.Call(s.Layout.Socket, ipc.Request{Cmd: ipc.CmdAddApp, Path: path})
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func app(st ipc.Status, id string) (ipc.AppStatus, bool) {
	for _, a := range st.Apps {
		if a.ID == id {
			return a, true
		}
	}
	return ipc.AppStatus{}, false
}

func has(r enforce.Rules, addr string) bool {
	a := netip.MustParseAddr(addr)
	return slices.Contains(r.V4, a) || slices.Contains(r.V6, a)
}

func TestAppIsAddedLearnedAndRemoved(t *testing.T) {
	s, path := adminWithApp(t, "")

	// Добавлено — ждёт обучения.
	resp := addApp(t, s, path)
	if !resp.OK || resp.App == nil || resp.App.Name != "Notion" || resp.App.Learned {
		t.Fatalf("добавление: %+v", resp)
	}
	if a, ok := app(s.Status(t), notionID); !ok || a.Learned {
		t.Fatalf("статус после добавления: %+v", s.Status(t).Apps)
	}
	hasLine(t, s, "Notion добавлено и ждёт обучения: включи VPN и поработай в нём пару минут")

	// VPN проверен, приложение работает: его адреса запоминаются и закрываются.
	// Локальные, частные и фиктивные адреса — нет.
	s.Web.Set("185.1.2.3", "DE", "DE")
	s.Network.Set(utun)
	s.WaitStatus(t, 2*time.Second, onePath("verified"))
	s.Apps.Run(notionID, "104.18.0.7:443", "[2606:4700::7]:443", "127.0.0.1:54339", "192.168.68.1:80", "198.18.0.9:443", "1.1.1.1:443")
	waitRules(t, s, 2*time.Second, func(r enforce.Rules) bool { return has(r, "104.18.0.7") && has(r, "2606:4700::7") })
	for _, local := range []string{"127.0.0.1", "192.168.68.1", "198.18.0.9", "1.1.1.1"} {
		if has(s.Enforce.Rules(), local) {
			t.Fatalf("в таблицы попал %s", local)
		}
	}

	// Через две минуты работы (в тесте — LearnFor) — защищено, и в журнале строка.
	st := s.WaitStatus(t, 2*time.Second, func(st ipc.Status) bool { a, _ := app(st, notionID); return a.Learned })
	if a, _ := app(st, notionID); a.Addrs != 2 || !a.Running {
		t.Fatalf("обученное приложение: %+v", a)
	}
	hasLine(t, s, "Notion защищено: обучение закончено, 2 адреса")

	// VPN выключен: адреса приложения закрыты, журнал — с причиной.
	s.Network.Set()
	waitRules(t, s, time.Second, func(r enforce.Rules) bool { return len(r.OpenIfaces) == 0 && has(r, "104.18.0.7") })
	hasLine(t, s, "сервисы закрыты: VPN выключен")

	// Убрано: адреса уходят из таблиц.
	resp, err := ipc.Call(s.Layout.Socket, ipc.Request{Cmd: ipc.CmdRemoveApp, AppID: notionID})
	if err != nil || !resp.OK {
		t.Fatalf("%v %+v", err, resp)
	}
	waitRules(t, s, time.Second, func(r enforce.Rules) bool { return !has(r, "104.18.0.7") && !has(r, "2606:4700::7") })
	if _, ok := app(s.Status(t), notionID); ok {
		t.Fatal("убранное приложение осталось в статусе")
	}
	hasLine(t, s, "Notion: защита снята")
}

func TestNoLearningWithoutVerifiedExit(t *testing.T) {
	s, path := adminWithApp(t, "")
	addApp(t, s, path)
	s.Apps.Run(notionID, "104.18.0.7:443")

	// VPN нет: приложение работает, но учиться нельзя — адреса не запоминаются,
	// время не идёт, журнал напоминает.
	hasLine(t, s, "Notion ещё не защищено — включи VPN и открой его")
	time.Sleep(2 * servicetest.LearnFor)
	a, _ := app(s.Status(t), notionID)
	if a.Learned || a.WorkSecs != 0 || a.Addrs != 0 || has(s.Enforce.Rules(), "104.18.0.7") {
		t.Fatalf("приложение училось без проверенного выхода: %+v", a)
	}

	// Российский выход — тоже не учимся.
	s.Web.Set("95.1.2.3", "RU", "RU")
	s.Network.Set(utun)
	s.WaitStatus(t, 2*time.Second, onePath("russian"))
	time.Sleep(2 * servicetest.LearnFor)
	if a, _ := app(s.Status(t), notionID); a.Learned || a.Addrs != 0 {
		t.Fatalf("приложение училось при российском выходе: %+v", a)
	}
}

func TestLearningNeedsTheAppToGoOnline(t *testing.T) {
	s, path := adminWithApp(t, "")
	addApp(t, s, path)
	s.Web.Set("185.1.2.3", "DE", "DE")
	s.Network.Set(utun)
	s.WaitStatus(t, 2*time.Second, onePath("verified"))

	// Запущено, но в сеть не выходило: защищать нечего — по-прежнему учится.
	s.Apps.Run(notionID)
	time.Sleep(3 * servicetest.LearnFor)
	if a, _ := app(s.Status(t), notionID); a.Learned {
		t.Fatalf("приложение без единого соединения стало «защищено»: %+v", a)
	}
	// Закрыто — время не идёт.
	s.Apps.Quit(notionID)
	a1, _ := app(s.Status(t), notionID)
	time.Sleep(3 * servicetest.ScanEvery)
	if a2, _ := app(s.Status(t), notionID); a2.WorkSecs != a1.WorkSecs || a2.Running {
		t.Fatalf("время шло у закрытого приложения: %+v → %+v", a1, a2)
	}
	// Вышло в сеть — доучилось.
	s.Apps.Run(notionID, "104.18.0.7:443")
	s.WaitStatus(t, 2*time.Second, func(st ipc.Status) bool { a, _ := app(st, notionID); return a.Learned })
}

func TestLearnedAppSurvivesRestart(t *testing.T) {
	root := t.TempDir()
	s, path := adminWithApp(t, root)
	addApp(t, s, path)
	s.Web.Set("185.1.2.3", "DE", "DE")
	s.Network.Set(utun)
	s.Apps.Run(notionID, "104.18.0.7:443")
	s.WaitStatus(t, 2*time.Second, func(st ipc.Status) bool { a, _ := app(st, notionID); return a.Learned })
	s.Stop()

	// После перезапуска (и после обновления приложения — путь и идентификатор те
	// же) оно защищено, а его адреса в таблицах сразу, без сети.
	again := servicetest.Start(t, root, servicetest.Fakes{})
	if a, ok := app(again.Status(t), notionID); !ok || !a.Learned {
		t.Fatalf("после перезапуска: %+v", again.Status(t).Apps)
	}
	waitRules(t, again, time.Second, func(r enforce.Rules) bool { return len(r.OpenIfaces) == 0 && has(r, "104.18.0.7") })
}

func TestAddAppRefusals(t *testing.T) {
	s, path := adminWithApp(t, "")
	if resp := addApp(t, s, path); !resp.OK {
		t.Fatalf("%+v", resp)
	}
	for name, tc := range map[string]struct{ path, want string }{
		"уже в списке":       {path, "уже в списке (ждёт обучения)"},
		"не приложение":      {"/etc/passwd", "не программа"},
		"нет такого":         {"/Applications/Нет такого.app", "нет"},
		"относительный путь": {"Notion.app", "не путь к приложению"},
	} {
		t.Run(name, func(t *testing.T) {
			resp := addApp(t, s, tc.path)
			if resp.OK || !strings.Contains(resp.Error, tc.want) {
				t.Fatalf("%+v", resp)
			}
		})
	}
	if n := len(s.Status(t).Apps); n != 1 {
		t.Fatalf("приложений %d", n)
	}

	user := servicetest.Start(t, "", servicetest.Fakes{Accounts: &servicetest.Accounts{Admin: false}})
	if resp := addApp(t, user, path); resp.OK || resp.Code != ipc.CodeForbidden {
		t.Fatalf("не администратор добавил приложение: %+v", resp)
	}
}

func TestScannerFailureIsJournaledOnce(t *testing.T) {
	s, path := adminWithApp(t, "")
	addApp(t, s, path)
	s.Apps.Fail(errFake("lsof завис"))
	hasLine(t, s, "не удалось посмотреть соединения приложений: lsof завис")
	time.Sleep(5 * servicetest.ScanEvery)
	n := 0
	for _, l := range s.Journal(t) {
		if strings.Contains(l, "lsof завис") {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("одна и та же ошибка в журнале %d раз", n)
	}
}

type errFake string

func (e errFake) Error() string { return string(e) }
