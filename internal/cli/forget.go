package cli

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"vpnlock/internal/core"
	"vpnlock/internal/ipc"
	"vpnlock/internal/tui"
)

// forget — «Забыть»: выход из моих, по имени или адресу (vpnlock forget
// Германия), или адреса и домены, которые приложение выучило по ошибке
// (vpnlock forget claude 34.149.66.165). Без аргумента в терминале — выбор
// выхода из списка.
func forget(env Env, args []string) int {
	st, ok := currentStatus(env)
	if !ok {
		return 1
	}
	if len(args) == 0 {
		if !env.Interactive {
			fmt.Fprintln(env.Err, forgetUsage)
			return 2
		}
		if len(st.Exits) == 0 {
			fmt.Fprintln(env.Out, "Запомненных выходов нет — забывать нечего.")
			return 0
		}
		items := make([]string, len(st.Exits))
		for i, x := range st.Exits {
			items[i] = exitText(x)
		}
		i, ok := choose(env, items, tui.Options{Title: "Какой выход забыть?"})
		if !ok {
			return 1
		}
		return forgetExit(env, st, st.Exits[i].IP)
	}
	if which := strings.Join(args, " "); hasExit(st.Exits, which) {
		return forgetExit(env, st, which)
	}
	if len(args) == 1 {
		fmt.Fprintf(env.Err, "Выхода «%s» в списке нет.\n", args[0])
		printExits(env, st.Exits)
		fmt.Fprintln(env.Err, forgetUsage)
		return 1
	}
	a, ok := findApp(st.Apps, args[0])
	if !ok {
		fmt.Fprintf(env.Err, "«%s» — нет ни выхода с таким именем, ни приложения в списке защищённых.\n%s\n", strings.Join(args, " "), forgetUsage)
		return 1
	}
	return forgetLearned(env, a, args[1:])
}

const forgetUsage = `Забыть выход: vpnlock forget Германия (или его адрес).
Убрать у приложения адрес или домен, выученный по ошибке: vpnlock forget claude 34.149.66.165 example.com — что оно выучило, покажет vpnlock status claude.`

func hasExit(exits []ipc.ExitStatus, which string) bool {
	ip, err := netip.ParseAddr(which)
	return slices.ContainsFunc(exits, func(x ipc.ExitStatus) bool {
		return strings.EqualFold(x.Name, which) || (err == nil && x.IP == ip.Unmap().String())
	})
}

func forgetExit(env Env, st *ipc.Status, which string) int {
	resp, err := ipc.Call(env.Layout.Socket, ipc.Request{Cmd: ipc.CmdForgetExit, Name: which})
	if err != nil {
		return silent(env, err)
	}
	if !resp.OK {
		fmt.Fprintln(env.Err, resp.Error)
		return 1
	}
	for _, x := range resp.Exits {
		fmt.Fprintf(env.Out, "Забыт выход: %s.\n", exitText(x))
	}
	left := len(st.Exits) - len(resp.Exits)
	if st.Rule == core.RuleMine && left <= 0 {
		fmt.Fprintln(env.Out, "В списке больше нет ни одного выхода, а правило — «только мои выходы»: защищённые сервисы закрыты при любом VPN. Запомни свой выход или верни правило: vpnlock rule any")
	}
	return 0
}

func forgetLearned(env Env, a ipc.AppStatus, items []string) int {
	resp, err := ipc.Call(env.Layout.Socket, ipc.Request{Cmd: ipc.CmdForgetLearned, AppID: a.ID, Addrs: items})
	if err != nil {
		return silent(env, err)
	}
	if !resp.OK {
		fmt.Fprintln(env.Err, resp.Error)
		return 1
	}
	if len(resp.Forgotten) > 0 {
		fmt.Fprintf(env.Out, "У %s забыто: %s. Без VPN это больше не закрыто — ни для него, ни для других программ; само оно это больше не выучит.\n",
			a.Name, strings.Join(resp.Forgotten, ", "))
	}
	for _, w := range resp.Warnings {
		fmt.Fprintf(env.Out, "  %s\n", w)
	}
	if len(resp.Forgotten) == 0 {
		return 1
	}
	return 0
}

// appDetail — vpnlock status <приложение>: что оно выучило и что из этого убрано.
func appDetail(env Env, name string) int {
	st, ok := currentStatus(env)
	if !ok {
		return 1
	}
	a, ok := findApp(st.Apps, name)
	if !ok {
		fmt.Fprintf(env.Err, "«%s» нет в списке защищённых приложений.\n", name)
		return 1
	}
	resp, err := ipc.Call(env.Layout.Socket, ipc.Request{Cmd: ipc.CmdApp, AppID: a.ID})
	if err != nil {
		return silent(env, err)
	}
	if !resp.OK || resp.App == nil || resp.Detail == nil {
		fmt.Fprintln(env.Err, resp.Error)
		return 1
	}
	d := resp.Detail
	fmt.Fprintln(env.Out, appLine(*resp.App))
	printList(env, "Адреса", d.Addrs)
	printList(env, "Домены (вместе с поддоменами)", d.Domains)
	if len(d.Forgotten) > 0 {
		fmt.Fprintf(env.Out, "Забыто: %s\n", strings.Join(d.Forgotten, ", "))
	}
	if len(d.Addrs)+len(d.Domains) > 0 {
		fmt.Fprintf(env.Out, "Убрать выученное по ошибке: vpnlock forget %s <адрес или домен>\n", quoted(resp.App.Name))
	}
	return 0
}

func printList(env Env, title string, list []string) {
	if len(list) == 0 {
		fmt.Fprintf(env.Out, "%s: нет\n", title)
		return
	}
	fmt.Fprintf(env.Out, "%s — %d:\n", title, len(list))
	for _, s := range list {
		fmt.Fprintf(env.Out, "  %s\n", s)
	}
}

// quoted — имя для команды в терминале: с пробелами — в кавычках.
func quoted(name string) string {
	if strings.ContainsAny(name, " \t") {
		return `"` + name + `"`
	}
	return name
}

// findApp — приложение из списка по имени, идентификатору или пути. Сначала —
// точное имя: Claude — приложение, claude — Claude Code; без учёта регистра
// имя подходит, только если такое приложение одно.
func findApp(list []ipc.AppStatus, name string) (ipc.AppStatus, bool) {
	for _, a := range list {
		if a.Name == name || a.ID == name || a.Path == name {
			return a, true
		}
	}
	var found []ipc.AppStatus
	for _, a := range list {
		if strings.EqualFold(a.Name, name) {
			found = append(found, a)
		}
	}
	if len(found) == 1 {
		return found[0], true
	}
	return ipc.AppStatus{}, false
}
