package service_test

import (
	"slices"
	"strings"
	"testing"
	"time"

	"vpnlock/internal/ipc"
	"vpnlock/internal/service/servicetest"
)

// Сценарии таски 02: служба видит туннели и проверяет выход. Сеть и внешние
// источники подменены; проверяются статус и строки журнала.

var utun = servicetest.Tunnel("utun11", "10.8.1.1")

func onePath(state string) func(ipc.Status) bool {
	return func(st ipc.Status) bool { return len(st.Paths) == 1 && st.Paths[0].State == state }
}

func hasLine(t *testing.T, s *servicetest.Service, want string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		lines := s.Journal(t)
		if slices.ContainsFunc(lines, func(l string) bool { return strings.Contains(l, want) }) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("в журнале нет %q:\n%s", want, strings.Join(lines, "\n"))
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestTunnelAppearsAndIsVerified(t *testing.T) {
	s := servicetest.Start(t, "", servicetest.Fakes{})
	if st := s.Status(t); len(st.Paths) != 0 {
		t.Fatalf("без туннелей статус показывает пути: %+v", st.Paths)
	}
	s.Web.Set("185.1.2.3", "DE", "DE")

	s.Network.Set(utun)
	st := s.WaitStatus(t, 2*time.Second, onePath("verified"))
	p := st.Paths[0]
	if p.Iface != "utun11" || p.IP != "185.1.2.3" || p.Country != "DE" || p.Summary != "выход 185.1.2.3, Германия — проверен" {
		t.Fatalf("путь %+v", p)
	}
	hasLine(t, s, "туннель utun11 появился (10.8.1.1) — проверяю выход")
	hasLine(t, s, "utun11: выход 185.1.2.3, Германия — проверен")
}

func TestTunnelGoneMeansNoVPN(t *testing.T) {
	s := servicetest.Start(t, "", servicetest.Fakes{})
	s.Web.Set("185.1.2.3", "DE", "DE")
	s.Network.Set(utun)
	s.WaitStatus(t, 2*time.Second, onePath("verified"))

	s.Network.Set()
	s.WaitStatus(t, 2*time.Second, func(st ipc.Status) bool { return len(st.Paths) == 0 })
	hasLine(t, s, "туннель utun11 исчез — VPN нет")
}

func TestSourcesDisagree(t *testing.T) {
	s := servicetest.Start(t, "", servicetest.Fakes{})
	s.Web.Set("185.1.2.3", "RU", "DE")
	s.Network.Set(utun)

	st := s.WaitStatus(t, 2*time.Second, onePath("unverified"))
	if !strings.Contains(st.Paths[0].Summary, "не удалось проверить выход") || st.Paths[0].IP != "" {
		t.Fatalf("путь %+v", st.Paths[0])
	}
	hasLine(t, s, "utun11: не удалось проверить выход — источники расходятся: Cloudflare — Россия, ipinfo — Германия")
}

func TestSourcesUnavailable(t *testing.T) {
	for name, tc := range map[string]struct{ cloudflare, second, why string }{
		"оба молчат": {"", "", "Cloudflare не ответил"},
		"молчит второй и все запасные": {"DE", "", "второй источник не ответил"},
	} {
		t.Run(name, func(t *testing.T) {
			s := servicetest.Start(t, "", servicetest.Fakes{})
			s.Web.Set("185.1.2.3", tc.cloudflare, tc.second)
			s.Network.Set(utun)

			s.WaitStatus(t, 2*time.Second, onePath("unverified"))
			hasLine(t, s, "utun11: не удалось проверить выход — "+tc.why)
		})
	}
}

func TestExitChangesWithinConnection(t *testing.T) {
	s := servicetest.Start(t, "", servicetest.Fakes{})
	s.Web.Set("185.1.2.3", "DE", "DE")
	s.Network.Set(utun)
	s.WaitStatus(t, 2*time.Second, onePath("verified"))

	// Клиент сменил сервер, не трогая туннель: сеть не менялась, выход — да.
	s.Web.Set("203.0.113.5", "NL", "NL")
	st := s.WaitStatus(t, 5*servicetest.CheckEvery+time.Second, func(st ipc.Status) bool {
		return len(st.Paths) == 1 && st.Paths[0].IP == "203.0.113.5"
	})
	if st.Paths[0].State != "verified" || st.Paths[0].Country != "NL" {
		t.Fatalf("путь %+v", st.Paths[0])
	}
	hasLine(t, s, "utun11: выход сменился — 203.0.113.5, Нидерланды, проверен")
}

func TestRussianExit(t *testing.T) {
	s := servicetest.Start(t, "", servicetest.Fakes{})
	s.Web.Set("95.1.2.3", "RU", "RU")
	s.Network.Set(utun)

	st := s.WaitStatus(t, 2*time.Second, onePath("russian"))
	if st.Paths[0].Summary != "выход в России (95.1.2.3)" {
		t.Fatalf("путь %+v", st.Paths[0])
	}
	hasLine(t, s, "utun11: выход в России (95.1.2.3)")
}

// Второй источник спрашивается, когда меняется адрес выхода, а не на каждой
// проверке: у бесплатных сервисов лимиты, а проверка идёт раз в несколько секунд.
func TestSecondSourceIsAskedOncePerExit(t *testing.T) {
	s := servicetest.Start(t, "", servicetest.Fakes{})
	s.Web.Set("185.1.2.3", "DE", "DE")
	s.Network.Set(utun)
	s.WaitStatus(t, 2*time.Second, onePath("verified"))

	time.Sleep(10 * servicetest.CheckEvery)
	if hits := s.Web.SecondHits(); hits != 1 {
		t.Fatalf("второй источник спрошен %d раз за десять проверок одного выхода", hits)
	}
}

func TestServiceStartIsJournaled(t *testing.T) {
	s := servicetest.Start(t, "", servicetest.Fakes{})
	hasLine(t, s, "служба "+servicetest.Version+" запущена")
}
