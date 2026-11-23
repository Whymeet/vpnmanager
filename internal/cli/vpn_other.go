//go:build !windows && !darwin

package cli

import "fmt"

// vpnWindow — окно «Мои VPN» есть только на Windows; здесь те же действия командами.
func vpnWindow(env Env) int {
	fmt.Fprintln(env.Err, "Окно «Мои VPN» есть только на Windows. Здесь: appguard remember <имя> [адрес], appguard forget <выход>, appguard rule mine.")
	return 2
}

// vpnOpener — пункт «Мои VPN…» в меню значка: только на Windows.
func vpnOpener(Env) func() { return nil }
