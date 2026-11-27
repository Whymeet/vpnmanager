package service_test

import (
	"errors"
	"testing"
	"time"

	"appguard/internal/ipc"
	"appguard/internal/service/servicetest"
)

// Сценарии таски 12: «Проверка» по пунктам. Соединение мимо VPN на шве
// отвечает так, как ответил бы pf с текущими правилами.

func runCheck(t *testing.T, s *servicetest.Service) map[string]ipc.CheckItem {
	t.Helper()
	resp, err := ipc.Call(s.Layout.Socket, ipc.Request{Cmd: ipc.CmdCheck})
	if err != nil || !resp.OK {
		t.Fatalf("проверка: %v %+v", err, resp)
	}
	out := map[string]ipc.CheckItem{}
	for _, it := range resp.Check {
		out[it.Name] = it
	}
	return out
}

func failed(items map[string]ipc.CheckItem) []string {
	var out []string
	for name, it := range items {
		if it.Result == ipc.CheckFail {
			out = append(out, name)
		}
	}
	return out
}

func TestCheckPassesWhenProtectionHolds(t *testing.T) {
	s := withExit(t, "", "185.1.2.3", "DE")
	waitRules(t, s, time.Second, openUtun)
	time.Sleep(3 * servicetest.CheckEvery) // зонд «Россия напрямую» успевает пройти
	items := runCheck(t, s)
	for name, want := range map[string]string{
		"Правила файрвола":    "на месте: в таблицах 1 адрес",
		"Выход":               "185.1.2.3, Германия — проверен, сервисы открыты",
		"«Россия напрямую»":   "российские адреса идут через туннель",
		"Мимо VPN: notion.so": "не достучаться через en0 (1 адрес)",
	} {
		if it := items[name]; it.Result != ipc.CheckOK || it.Detail != want {
			t.Fatalf("%s: %+v", name, it)
		}
	}
	if it := items["Резолвер"]; it.Result != ipc.CheckOK || it.Detail != "отвечает на "+s.DNSAddr {
		t.Fatalf("резолвер: %+v", it)
	}
}

// Правила сброшены и не возвращаются: провалены ровно правила и сервис,
// который стал достижим мимо VPN.
func TestCheckNamesTheBrokenItems(t *testing.T) {
	s := withExit(t, "", "185.1.2.3", "DE")
	waitRules(t, s, time.Second, openUtun)
	s.Enforce.Fail(errors.New("pfctl: /dev/pf: Operation not permitted"))
	s.Enforce.Reset("в якоре 0 правил вместо 6")
	hasLine(t, s, "файрвол: не удалось восстановить правила")

	items := runCheck(t, s)
	if got := failed(items); len(got) != 2 || items["Правила файрвола"].Result != ipc.CheckFail || items["Мимо VPN: notion.so"].Result != ipc.CheckFail {
		t.Fatalf("провалены %v: %+v", got, items)
	}
	if it := items["Мимо VPN: notion.so"]; it.Detail != "достижим через en0: 104.18.0.1" || it.Hint == "" {
		t.Fatalf("%+v", it)
	}
}

func TestCheckWithoutVPNAndWithRussiaDirect(t *testing.T) {
	s := protected(t)
	items := runCheck(t, s)
	if it := items["Выход"]; it.Result != ipc.CheckWarn || it.Detail != "VPN выключен — защищённые сервисы закрыты, пока его нет" {
		t.Fatalf("без VPN: %+v", it)
	}
	if got := failed(items); len(got) != 0 {
		t.Fatalf("без VPN защита держится, а провалено %v", got)
	}

	s.Web.Set("185.1.2.3", "DE", "DE")
	s.Web.RussiaDirect(true)
	s.Network.Set(utun)
	s.WaitStatus(t, 2*time.Second, direct)
	if it := runCheck(t, s)["«Россия напрямую»"]; it.Result != ipc.CheckFail || it.Hint == "" {
		t.Fatalf("«Россия напрямую»: %+v", it)
	}
}

// VPN через CDN: адрес сервиса, совпавший с сервером VPN, на физическом
// интерфейсе разрешён — проверка его не пробует и не считает провалом.
func TestCheckSkipsAllowedVPNServer(t *testing.T) {
	s := withExit(t, "", "185.1.2.3", "DE")
	s.Apps.VPNServer(notion4.String())
	s.WaitStatus(t, 2*time.Second, func(ipc.Status) bool { return len(s.Enforce.Rules().Servers) == 1 })
	if it := runCheck(t, s)["Мимо VPN: notion.so"]; it.Result != ipc.CheckWarn {
		t.Fatalf("%+v", it)
	}
}
