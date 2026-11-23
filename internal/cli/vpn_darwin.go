package cli

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
)

// Диалоги окна «Мои VPN» на macOS — системный osascript, ничего ставить не надо.
// Тексты идут аргументами (on run argv), а не внутрь скрипта: кавычки и
// переводы строк в них ничего не ломают.

const vpnTitle = "Мои VPN — Claude только через VPN"

const chooseScript = `on run argv
	activate
	set r to choose from list (items 5 thru -1 of argv) with title (item 1 of argv) with prompt (item 2 of argv) OK button name (item 3 of argv) cancel button name (item 4 of argv)
	if r is false then return ""
	return item 1 of r
end run`

const askScript = `on run argv
	activate
	try
		set r to display dialog (item 2 of argv) default answer (item 3 of argv) with title (item 1 of argv) buttons {"Отмена", "OK"} default button 2 cancel button 1
		return "ok:" & text returned of r
	on error number -128
		return "cancel"
	end try
end run`

const confirmScript = `on run argv
	activate
	try
		display dialog (item 2 of argv) with title (item 1 of argv) buttons {"Отмена", item 3 of argv} default button 2 cancel button 1 with icon caution
		return "ok"
	on error number -128
		return "cancel"
	end try
end run`

const alertScript = `on run argv
	activate
	display dialog (item 2 of argv) with title (item 1 of argv) buttons {"OK"} default button 1 with icon caution
end run`

type osaUI struct{}

func osa(script string, args ...string) (string, error) {
	out, err := exec.Command("/usr/bin/osascript", append([]string{"-e", script}, args...)...).Output()
	return strings.TrimRight(string(out), "\n"), err
}

func (osaUI) Choose(prompt string, items []string, ok, cancel string) (int, bool) {
	out, err := osa(chooseScript, append([]string{vpnTitle, prompt, ok, cancel}, items...)...)
	if err != nil {
		return 0, false
	}
	for i, it := range items {
		if it == out {
			return i, true
		}
	}
	return 0, false
}

func (osaUI) Ask(prompt, def string) (string, bool) {
	out, err := osa(askScript, vpnTitle, prompt, def)
	if err != nil || !strings.HasPrefix(out, "ok:") {
		return "", false
	}
	return strings.TrimPrefix(out, "ok:"), true
}

func (osaUI) Confirm(text, yes string) bool {
	out, err := osa(confirmScript, vpnTitle, text, yes)
	return err == nil && out == "ok"
}

func (osaUI) Alert(text string) { osa(alertScript, vpnTitle, text) }

// vpnWindow — `appguard vpn`: окно «Мои VPN». Права не нужны: менять выходы
// служба разрешает группе admin, а под sudo окно было бы не в сеансе человека.
func vpnWindow(env Env) int {
	if os.Geteuid() == 0 {
		fmt.Fprintln(env.Err, "Запусти без sudo: appguard vpn")
		return 2
	}
	return vpnDialog(osaUI{}, serviceVPNOps(env))
}

// vpnOpener — пункт «Мои VPN…» в меню значка: тот же appguard с командой vpn,
// отдельным процессом — значок не ждёт окна. Второе окно поверх первого не
// открывается.
func vpnOpener(env Env) func() {
	var open atomic.Bool
	return func() {
		if !open.CompareAndSwap(false, true) {
			return
		}
		self, err := os.Executable()
		if err != nil {
			open.Store(false)
			return
		}
		cmd := exec.Command(self, "vpn")
		if err := cmd.Start(); err != nil {
			fmt.Fprintf(env.Err, "окно «Мои VPN»: %v\n", err)
			open.Store(false)
			return
		}
		go func() { cmd.Wait(); open.Store(false) }()
	}
}
