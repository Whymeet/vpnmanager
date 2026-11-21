package cli

import (
	"fmt"
	"strings"

	"vpnlock/internal/ipc"
	"vpnlock/internal/tui"
)

// notifications — `vpnlock notifications [on|off]`: без аргумента в меню —
// выбор, в команде — что сейчас.
func notifications(env Env, args []string) int {
	st, ok := currentStatus(env)
	if !ok {
		return 1
	}
	on := !st.NotifyOff
	var want bool
	switch {
	case len(args) == 1:
		switch strings.ToLower(args[0]) {
		case "on":
			want = true
		case "off":
			want = false
		default:
			fmt.Fprintf(env.Err, "Нет такого: vpnlock notifications on — включить, vpnlock notifications off — выключить.\n")
			return 2
		}
	case len(args) > 1:
		fmt.Fprintln(env.Err, "Укажи одно: вкл или выкл.")
		return 2
	case env.Interactive:
		items := []string{"Включены", "Выключены"}
		if on {
			items[0] += " — сейчас"
		} else {
			items[1] += " — сейчас"
		}
		i, ok := choose(env, items, tui.Options{Title: "Уведомления об открытии и закрытии сервисов (журнал пишется всегда):"})
		if !ok {
			return 1
		}
		want = i == 0
	default:
		fmt.Fprintf(env.Out, "Уведомления: %s.\n", notifyText(on))
		return 0
	}
	if want != on {
		resp, err := ipc.Call(env.Layout.Socket, ipc.Request{Cmd: ipc.CmdNotify, Notify: want})
		if err != nil {
			return silent(env, err)
		}
		if !resp.OK {
			fmt.Fprintln(env.Err, resp.Error)
			return 1
		}
	}
	fmt.Fprintf(env.Out, "Уведомления: %s.", notifyText(want))
	if !want {
		fmt.Fprint(env.Out, " Журнал пишется, как прежде: vpnlock log.")
	}
	fmt.Fprintln(env.Out)
	return 0
}

func notifyText(on bool) string {
	if on {
		return "включены"
	}
	return "выключены"
}
