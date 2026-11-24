package cli

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"golang.org/x/sys/windows"
)

// vpnCommand — PowerShell с окном «Мои VPN» из папки программы. Окно само
// попросит права администратора (UAC), если их нет: список выходов меняет
// только администратор, а файл окна лежит там, куда пишет только он.
func vpnCommand(env Env) (*exec.Cmd, error) {
	if _, err := os.Stat(env.Layout.ExitsUI); err != nil {
		return nil, fmt.Errorf("нет окна «Мои VPN» (%s) — переустанови appguard: install-windows.cmd в папке проекта", env.Layout.ExitsUI)
	}
	cmd := exec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", env.Layout.ExitsUI)
	// Консоли у PowerShell нет (CREATE_NO_WINDOW), но и SW_HIDE в STARTUPINFO
	// (HideWindow, как у quiet) нельзя: первый ShowWindow процесса берёт режим
	// оттуда, и форма окна осталась бы невидимой, а ShowDialog ждал бы вечно.
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NO_WINDOW}
	return cmd, nil
}

// vpnWindow — `appguard vpn`: открыть окно и дождаться, пока его закроют.
func vpnWindow(env Env) int {
	cmd, err := vpnCommand(env)
	if err != nil {
		fmt.Fprintln(env.Err, err)
		return 1
	}
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(env.Err, "окно «Мои VPN»: %v\n", err)
		return 1
	}
	return 0
}

// vpnOpener — пункт «Мои VPN…» в меню значка: открыть окно и не ждать.
func vpnOpener(env Env) func() {
	return func() {
		cmd, err := vpnCommand(env)
		if err != nil {
			fmt.Fprintln(env.Err, err)
			return
		}
		if err := cmd.Start(); err != nil {
			fmt.Fprintf(env.Err, "окно «Мои VPN»: %v\n", err)
			return
		}
		go cmd.Wait()
	}
}
