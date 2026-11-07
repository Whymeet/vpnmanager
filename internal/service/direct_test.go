package service_test

import (
	"slices"
	"strings"
	"testing"
	"time"

	"vpnlock/internal/ipc"
	"vpnlock/internal/service/servicetest"
)

// Сценарии таски 08: «Россия напрямую». Российский сервис спрашивается через
// туннель; если он видит домашний адрес, клиент VPN отправил запрос мимо
// туннеля. Зонд сервисы не открывает и не закрывает.

func direct(st ipc.Status) bool { return len(st.Paths) == 1 && st.Paths[0].Direct }

func journalCount(t *testing.T, s *servicetest.Service, want string) int {
	t.Helper()
	n := 0
	for _, l := range s.Journal(t) {
		if strings.Contains(l, want) {
			n++
		}
	}
	return n
}

func TestRussiaDirectIsReportedWithAHint(t *testing.T) {
	s := withExit(t, "", "185.1.2.3", "DE")
	waitRules(t, s, time.Second, openUtun)
	s.Web.RussiaDirect(true)
	s.Network.Set(utun) // событие сети — зонд идёт сразу

	st := s.WaitStatus(t, 2*time.Second, direct)
	if !strings.Contains(st.Paths[0].Summary, "выключи в нём правило «Россия напрямую»") {
		t.Fatalf("статус без подсказки: %+v", st.Paths[0])
	}
	hasLine(t, s, "клиент VPN отправляет российские адреса напрямую («Россия напрямую»)")
	hasLine(t, s, "Выключи это правило в клиенте")
	// Сервисы по-прежнему открыты через туннель, а их адреса закрыты везде
	// ещё — прямые соединения клиента к ним упираются в файрвол.
	if r := s.Enforce.Rules(); !slices.Equal(r.OpenIfaces, []string{"utun11"}) || !has(r, notion4.String()) {
		t.Fatalf("зонд поменял правила: %+v", r)
	}
	// Повторные зонды с тем же итогом журнал не засоряют.
	time.Sleep(5 * servicetest.CheckEvery)
	if n := journalCount(t, s, "отправляет российские адреса напрямую"); n != 1 {
		t.Fatalf("одна и та же тревога в журнале %d раз", n)
	}
}

func TestNoFalseAlarmWithoutTheRule(t *testing.T) {
	s := withExit(t, "", "185.1.2.3", "DE")
	time.Sleep(6 * servicetest.CheckEvery)
	if st := s.Status(t); direct(st) {
		t.Fatalf("ложная тревога: %+v", st.Paths)
	}
	if n := journalCount(t, s, "Россия напрямую"); n != 0 {
		t.Fatalf("в журнале о «России напрямую» без правила: %d", n)
	}
}

func TestSilentRussianServiceChangesNothing(t *testing.T) {
	s := withExit(t, "", "185.1.2.3", "DE")
	waitRules(t, s, time.Second, openUtun)
	s.Web.RussianDown(true)
	s.Network.Set(utun)
	hasLine(t, s, "российский сервис проверки не ответил — «Россию напрямую» проверить не удалось")
	if st := s.Status(t); direct(st) || st.Paths[0].State != "verified" {
		t.Fatalf("статус: %+v", st.Paths)
	}
	if r := s.Enforce.Rules(); !slices.Equal(r.OpenIfaces, []string{"utun11"}) {
		t.Fatalf("недоступность зонда закрыла сервисы: %+v", r)
	}
}

func TestRussiaDirectTurnedOffInTheClient(t *testing.T) {
	s := withExit(t, "", "185.1.2.3", "DE")
	s.Web.RussiaDirect(true)
	s.Network.Set(utun)
	s.WaitStatus(t, 2*time.Second, direct)
	s.Web.RussiaDirect(false)
	s.WaitStatus(t, 2*time.Second, func(st ipc.Status) bool { return !direct(st) })
	hasLine(t, s, "«Россия напрямую» больше не замечено")
}
