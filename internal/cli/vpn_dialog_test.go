//go:build !windows

package cli

import (
	"strings"
	"testing"

	"appguard/internal/core"
	"appguard/internal/ipc"
)

// fakeUI отвечает по очереди заготовленными ответами и запоминает вопросы.
type fakeUI struct {
	t       *testing.T
	choices []string // подпись пункта; "" — кнопка «Готово/Отмена»
	asks    []string // "\x00" — отмена
	confirm []bool
	prompts []string
	alerts  []string
}

func (f *fakeUI) Choose(prompt string, items []string, ok, cancel string) (int, bool) {
	f.prompts = append(f.prompts, prompt)
	if len(f.choices) == 0 {
		f.t.Fatalf("лишний выбор: %q", items)
	}
	want := f.choices[0]
	f.choices = f.choices[1:]
	if want == "" {
		return 0, false
	}
	for i, it := range items {
		if strings.HasPrefix(it, want) {
			return i, true
		}
	}
	f.t.Fatalf("нет пункта %q среди %q", want, items)
	return 0, false
}

func (f *fakeUI) Ask(prompt, def string) (string, bool) {
	if len(f.asks) == 0 {
		return def, true
	}
	a := f.asks[0]
	f.asks = f.asks[1:]
	return a, a != "\x00"
}

func (f *fakeUI) Confirm(string, string) bool {
	if len(f.confirm) == 0 {
		return true
	}
	c := f.confirm[0]
	f.confirm = f.confirm[1:]
	return c
}

func (f *fakeUI) Alert(text string) { f.alerts = append(f.alerts, text) }

// fakeService — служба в памяти: выходы, правило, текущий путь.
type fakeService struct {
	st ipc.Status
}

func (s *fakeService) ops() vpnOps {
	return vpnOps{
		Status: func() (*ipc.Status, error) {
			c := s.st
			c.Exits = append([]ipc.ExitStatus(nil), s.st.Exits...)
			return &c, nil
		},
		Remember: func(name, ip string) error {
			x := ipc.ExitStatus{Name: name, IP: ip, Unverified: true}
			if ip == "" {
				p := s.st.Paths[0]
				x = ipc.ExitStatus{Name: name, IP: p.IP, Country: p.Country}
			}
			s.st.Exits = append(s.st.Exits, x)
			return nil
		},
		Forget: func(ip string) error {
			for i, x := range s.st.Exits {
				if x.IP == ip {
					s.st.Exits = append(s.st.Exits[:i], s.st.Exits[i+1:]...)
				}
			}
			return nil
		},
		RuleMine: func() error { s.st.Rule = core.RuleMine; return nil },
	}
}

func connected() *fakeService {
	return &fakeService{st: ipc.Status{Rule: core.RuleAny, Paths: []ipc.PathStatus{{Iface: "utun4", State: "verified", IP: "203.0.113.10", Country: "DE", Default: true}}}}
}

func TestVPNDialogAddsCurrentExitAndSetsRuleMine(t *testing.T) {
	s := connected()
	ui := &fakeUI{t: t, choices: []string{vpnAddNow, ""}, asks: []string{"VPS"}}
	if code := vpnDialog(ui, s.ops()); code != 0 {
		t.Fatalf("код %d", code)
	}
	if len(s.st.Exits) != 1 || s.st.Exits[0].IP != "203.0.113.10" || s.st.Exits[0].Name != "VPS" {
		t.Fatalf("выходы: %+v", s.st.Exits)
	}
	if s.st.Rule != core.RuleMine {
		t.Fatal("правило не mine")
	}
	if last := ui.prompts[len(ui.prompts)-1]; !strings.Contains(last, "Claude открыт") {
		t.Fatalf("после добавления: %q", last)
	}
}

func TestVPNDialogAddByAddressRejectsGarbage(t *testing.T) {
	s := connected()
	ui := &fakeUI{t: t, choices: []string{vpnAddAddr, ""}, asks: []string{"не адрес", "192.168.1.1", "203.0.113.5", "Запасной"}}
	vpnDialog(ui, s.ops())
	if len(ui.alerts) != 2 {
		t.Fatalf("ожидались 2 отказа, а было: %q", ui.alerts)
	}
	if len(s.st.Exits) != 1 || s.st.Exits[0].IP != "203.0.113.5" || s.st.Exits[0].Name != "Запасной" {
		t.Fatalf("выходы: %+v", s.st.Exits)
	}
}

func TestVPNDialogDelete(t *testing.T) {
	s := connected()
	s.st.Rule = core.RuleMine
	s.st.Exits = []ipc.ExitStatus{{Name: "A", IP: "203.0.113.1", Country: "NL"}, {Name: "B", IP: "203.0.113.2", Country: "DE"}}
	ui := &fakeUI{t: t, choices: []string{vpnDelete, "B", ""}}
	vpnDialog(ui, s.ops())
	if len(s.st.Exits) != 1 || s.st.Exits[0].Name != "A" {
		t.Fatalf("выходы: %+v", s.st.Exits)
	}
}

// Пустой список: «Готово» сначала предупреждает; «Отмена» возвращает в окно.
func TestVPNDialogWarnsOnEmptyList(t *testing.T) {
	s := &fakeService{st: ipc.Status{Rule: core.RuleMine}}
	ui := &fakeUI{t: t, choices: []string{"", ""}, confirm: []bool{false, true}}
	if code := vpnDialog(ui, s.ops()); code != 0 {
		t.Fatalf("код %d", code)
	}
	if len(ui.prompts) != 2 || !strings.Contains(ui.prompts[0], "пусто") || !strings.Contains(ui.prompts[0], "Claude закрыт") {
		t.Fatalf("вопросы: %q", ui.prompts)
	}
}

func TestFreeExitName(t *testing.T) {
	st := &ipc.Status{Exits: []ipc.ExitStatus{{Name: "VPN"}, {Name: "vpn 2"}}}
	if got := freeExitName(st, "VPN"); got != "VPN 3" {
		t.Fatal(got)
	}
}
