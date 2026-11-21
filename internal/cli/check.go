package cli

import (
	"fmt"
	"strings"

	"appguard/internal/browsers"
	"appguard/internal/ipc"
)

// check — «Проверка»: служба проверяет правила, выход, «Россию напрямую» и
// каждый защищённый сервис мимо VPN, клиент — «безопасный DNS» браузеров.
// Итог по пунктам; проваленный пункт назван, общего «всё в порядке» нет.
func check(env Env) int {
	resp, err := ipc.Call(env.Layout.Socket, ipc.Request{Cmd: ipc.CmdCheck})
	if err != nil {
		return silent(env, err)
	}
	if !resp.OK {
		fmt.Fprintln(env.Err, resp.Error)
		return 1
	}
	items := append(resp.Check, browserItems(env.Home)...)
	items = append(items, movedItems(env)...)
	fmt.Fprintln(env.Out, "Проверка:")
	var failed []string
	warns := 0
	for _, it := range items {
		mark := "✓"
		switch it.Result {
		case ipc.CheckFail:
			mark = "✗"
			failed = append(failed, it.Name)
		case ipc.CheckWarn:
			mark = "!"
			warns++
		}
		fmt.Fprintf(env.Out, "  %s %s — %s\n", mark, it.Name, it.Detail)
		if it.Hint != "" && it.Result != ipc.CheckOK {
			fmt.Fprintf(env.Out, "      → %s\n", it.Hint)
		}
	}
	if len(failed) > 0 {
		fmt.Fprintf(env.Out, "Итог: не в порядке — %s.\n", strings.Join(failed, "; "))
		return 1
	}
	fmt.Fprint(env.Out, "Итог: всё в порядке.")
	if warns > 0 {
		fmt.Fprint(env.Out, " Пункты с «!» — не поломка, а то, что стоит знать.")
	}
	fmt.Fprintln(env.Out)
	return 0
}

// movedItems — программы, которые после обновления лежат не там, где их защищали.
func movedItems(env Env) []ipc.CheckItem {
	if env.Moved == nil {
		return nil
	}
	st, err := ipc.Call(env.Layout.Socket, ipc.Request{Cmd: ipc.CmdStatus})
	if err != nil || st.Status == nil {
		return nil
	}
	var out []ipc.CheckItem
	for _, a := range st.Status.Apps {
		if env.Moved(a.Name, a.ID) {
			out = append(out, ipc.CheckItem{Name: a.Name, Result: ipc.CheckFail,
				Detail: "программа переехала: новая версия не защищена",
				Hint:   "защити её заново: appguard remove " + a.Name + " и appguard add " + a.Name})
		}
	}
	return out
}

// browserItems — «безопасный DNS» установленных браузеров.
func browserItems(home string) []ipc.CheckItem {
	if home == "" {
		return nil
	}
	var out []ipc.CheckItem
	for _, b := range browsers.Check(home) {
		it := ipc.CheckItem{Name: b.Browser + ": безопасный DNS", Result: ipc.CheckOK, Detail: "свой не включён — имена идут через appguard"}
		if b.On {
			it.Result = ipc.CheckFail
			it.Detail = "включён свой"
			if b.Provider != "" {
				it.Detail += " (" + b.Provider + ")"
			}
			it.Detail += ": браузер узнаёт адреса сервисов мимо appguard, и сайт может открыться без VPN"
			it.Hint = b.Hint
		}
		out = append(out, it)
	}
	return out
}
