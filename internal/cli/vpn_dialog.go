//go:build !windows

package cli

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"appguard/internal/core"
	"appguard/internal/ipc"
)

// vpnUI — диалоги окна «Мои VPN» на macOS (osascript). Шов для тестов.
type vpnUI interface {
	// Choose — выбор из списка; false — нажата кнопка cancel.
	Choose(prompt string, items []string, ok, cancel string) (int, bool)
	// Ask — строка ввода; false — отмена.
	Ask(prompt, def string) (string, bool)
	// Confirm — «да/нет», yes — надпись кнопки согласия.
	Confirm(text, yes string) bool
	Alert(text string)
}

// vpnOps — что окно делает со службой.
type vpnOps struct {
	Status   func() (*ipc.Status, error)
	Remember func(name, ip string) error // ip пустой — текущий проверенный выход
	Forget   func(ip string) error
	RuleMine func() error
}

const (
	vpnAddNow  = "Добавить текущий VPN"
	vpnAddAddr = "Добавить VPN по адресу…"
	vpnDelete  = "Удалить VPN…"
	vpnRefresh = "Обновить"
)

// vpnDialog — цикл окна «Мои VPN»: показать состояние и список, выполнить
// выбранное, снова показать. Закрыть с пустым списком — только после
// предупреждения: Claude тогда закрыт при любом VPN.
func vpnDialog(ui vpnUI, ops vpnOps) int {
	for {
		st, err := ops.Status()
		if err != nil {
			ui.Alert("Служба appguard не отвечает: " + err.Error())
			return 1
		}
		cur, haveCur := verifiedExit(st)
		known := haveCur && slices.ContainsFunc(st.Exits, func(x ipc.ExitStatus) bool { return x.IP == cur.IP })
		var labels []string
		if haveCur && !known {
			labels = append(labels, fmt.Sprintf("%s (%s, %s)", vpnAddNow, cur.IP, core.CountryName(cur.Country)))
		}
		labels = append(labels, vpnAddAddr)
		if len(st.Exits) > 0 {
			labels = append(labels, vpnDelete)
		}
		labels = append(labels, vpnRefresh)

		i, ok := ui.Choose(vpnSummary(st, cur, haveCur, known), labels, "Выбрать", "Готово")
		if !ok {
			if len(st.Exits) == 0 && !ui.Confirm("В списке нет ни одного VPN — Claude будет закрыт всегда.\n\nДобавить VPN потом: щит в строке меню → «Мои VPN…».\n\nЗакрыть окно?", "Закрыть") {
				continue
			}
			return 0
		}
		var opErr error
		switch label := labels[i]; {
		case strings.HasPrefix(label, vpnAddNow):
			name, ok := ui.Ask("Название этого VPN:", freeExitName(st, "VPN"))
			if !ok {
				continue
			}
			opErr = addExit(ops, st, name, "")
		case label == vpnAddAddr:
			opErr = addByAddress(ui, ops, st)
		case label == vpnDelete:
			opErr = deleteExit(ui, ops, st)
		}
		if opErr != nil {
			ui.Alert(opErr.Error())
		}
	}
}

func addByAddress(ui vpnUI, ops vpnOps, st *ipc.Status) error {
	text := ""
	for {
		var ok bool
		text, ok = ui.Ask("IP выхода VPN — адрес, который видят сайты (не адрес сервера).\nУзнать: включи VPN и открой 1.1.1.1/cdn-cgi/trace — строка ip=", text)
		if !ok {
			return nil
		}
		text = strings.TrimSpace(text)
		if a, err := netip.ParseAddr(text); err == nil && !a.IsPrivate() && !a.IsLoopback() && !a.IsUnspecified() {
			text = a.Unmap().String()
			break
		}
		ui.Alert(fmt.Sprintf("«%s» — не внешний IP-адрес. Пример: 203.0.113.5", text))
	}
	name, ok := ui.Ask("Название этого VPN:", freeExitName(st, "VPN"))
	if !ok {
		return nil
	}
	return addExit(ops, st, name, text)
}

func addExit(ops vpnOps, st *ipc.Status, name, ip string) error {
	if name = strings.TrimSpace(name); name == "" {
		name = freeExitName(st, "VPN")
	}
	if err := ops.Remember(name, ip); err != nil {
		return err
	}
	if st.Rule != core.RuleMine {
		return ops.RuleMine()
	}
	return nil
}

func deleteExit(ui vpnUI, ops vpnOps, st *ipc.Status) error {
	items := make([]string, len(st.Exits))
	for i, x := range st.Exits {
		items[i] = exitText(x)
	}
	i, ok := ui.Choose("Какой VPN удалить?", items, "Удалить", "Отмена")
	if !ok {
		return nil
	}
	msg := fmt.Sprintf("Удалить VPN «%s» (%s)?", st.Exits[i].Name, st.Exits[i].IP)
	if len(st.Exits) == 1 {
		msg += "\n\nЭто последний VPN в списке — Claude будет закрыт при любом VPN, пока не добавишь новый."
	}
	if !ui.Confirm(msg, "Удалить") {
		return nil
	}
	return ops.Forget(st.Exits[i].IP)
}

// verifiedExit — текущий проверенный выход (не российский): маршрут по
// умолчанию, иначе единственный проверенный путь.
func verifiedExit(st *ipc.Status) (ipc.ExitStatus, bool) {
	var found []ipc.PathStatus
	for _, p := range st.Paths {
		if p.State != "verified" {
			continue
		}
		if p.Default {
			return ipc.ExitStatus{IP: p.IP, Country: p.Country}, true
		}
		found = append(found, p)
	}
	if len(found) == 1 {
		return ipc.ExitStatus{IP: found[0].IP, Country: found[0].Country}, true
	}
	return ipc.ExitStatus{}, false
}

func vpnSummary(st *ipc.Status, cur ipc.ExitStatus, haveCur, known bool) string {
	var b strings.Builder
	b.WriteString("Claude (приложение, Claude Code и сайт в браузере) работает только через VPN из этого списка.\n\n")
	switch {
	case haveCur && known:
		fmt.Fprintf(&b, "Сейчас: VPN %s, %s — Claude открыт ✓\n", cur.IP, core.CountryName(cur.Country))
	case haveCur:
		fmt.Fprintf(&b, "Сейчас: VPN %s, %s — его нет в списке, Claude закрыт\n", cur.IP, core.CountryName(cur.Country))
	default:
		b.WriteString("Сейчас: VPN не подключён или ещё проверяется — Claude закрыт\n")
	}
	b.WriteString("\nМои VPN:\n")
	if len(st.Exits) == 0 {
		b.WriteString("  — пусто —\n")
	}
	for _, x := range st.Exits {
		fmt.Fprintf(&b, "  • %s\n", exitText(x))
	}
	return b.String()
}

func freeExitName(st *ipc.Status, base string) string {
	taken := func(n string) bool {
		return slices.ContainsFunc(st.Exits, func(x ipc.ExitStatus) bool { return strings.EqualFold(x.Name, n) })
	}
	if !taken(base) {
		return base
	}
	for i := 2; ; i++ {
		if n := fmt.Sprintf("%s %d", base, i); !taken(n) {
			return n
		}
	}
}

// serviceVPNOps — vpnOps через канал службы.
func serviceVPNOps(env Env) vpnOps {
	call := func(req ipc.Request) (ipc.Response, error) {
		resp, err := ipc.Call(env.Layout.Socket, req)
		if err == nil && !resp.OK {
			err = errors.New(resp.Error)
		}
		return resp, err
	}
	return vpnOps{
		Status: func() (*ipc.Status, error) {
			resp, err := call(ipc.Request{Cmd: ipc.CmdStatus})
			if err == nil && resp.Status == nil {
				err = errors.New("служба не прислала состояние")
			}
			return resp.Status, err
		},
		Remember: func(name, ip string) error {
			_, err := call(ipc.Request{Cmd: ipc.CmdRemember, Name: name, IP: ip})
			return err
		},
		Forget: func(ip string) error {
			_, err := call(ipc.Request{Cmd: ipc.CmdForgetExit, Name: ip})
			return err
		},
		RuleMine: func() error {
			_, err := call(ipc.Request{Cmd: ipc.CmdRule, Rule: core.RuleMine})
			return err
		},
	}
}
