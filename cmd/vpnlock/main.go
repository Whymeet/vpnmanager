// Команда vpnlock: клиент (меню и команды) и служба в одном исполняемом файле.
package main

import (
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"vpnlock/internal/apps"
	"vpnlock/internal/cli"
	"vpnlock/internal/core"
	"vpnlock/internal/netwatch"
	"vpnlock/internal/paths"
	"vpnlock/internal/resolver"
	"vpnlock/internal/tray"
	"vpnlock/internal/tui"
	"vpnlock/internal/version"
)

// checkEvery — как часто служба перепроверяет выход: так смена выхода внутри
// подключения видна не позже чем через 5 секунд, вместе с самой проверкой.
const checkEvery = 4 * time.Second

// Обучение: соединения приложений просматриваются раз в scanEvery, обученным
// приложение считается после learnFor работы при проверенном выходе.
const (
	scanEvery = 2 * time.Second
	learnFor  = 2 * time.Minute
)

func main() {
	L := paths.System()
	if len(os.Args) > 1 && os.Args[1] == "daemon" {
		os.Exit(daemon(L))
	}
	env := cli.Env{
		Layout:      L,
		Version:     version.Version,
		In:          os.Stdin,
		Out:         os.Stdout,
		Err:         os.Stderr,
		Interactive: isTerminal(os.Stdin),
		Raw:         func() (func() error, error) { return tui.Raw(int(os.Stdin.Fd())) },
		Installed:   func() []apps.App { return apps.Scan(apps.Dirs()) },
		Tray:        tray.System,
	}
	platform(&env)
	os.Exit(cli.Run(os.Args[1:], env))
}

// self — путь к этому исполняемому файлу: установка ставит его службой.
func self() (string, error) {
	p, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(p)
}

func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// physicalTunnel — физический интерфейс в виде пути: зонд «Россия напрямую»
// спрашивает через него российский сервис и узнаёт домашний адрес.
func physicalTunnel() (core.Tunnel, bool) {
	name, index, ok := netwatch.Physical()
	if !ok {
		return core.Tunnel{}, false
	}
	addr, ok := physicalAddr()
	if !ok {
		return core.Tunnel{}, false
	}
	return core.Tunnel{Name: name, Index: index, Addrs: []netip.Addr{addr}}, true
}

// physicalAddr — IPv4-адрес физического интерфейса: через него ходит клиент
// VPN, а по его соединениям выгрузка каталога узнаёт адреса серверов VPN.
func physicalAddr() (netip.Addr, bool) {
	_, index, ok := netwatch.Physical()
	if !ok {
		return netip.Addr{}, false
	}
	ifi, err := net.InterfaceByIndex(index)
	if err != nil {
		return netip.Addr{}, false
	}
	addrs, _ := ifi.Addrs()
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(ipn.IP); ok && ip.Unmap().Is4() {
				return ip.Unmap(), true
			}
		}
	}
	return netip.Addr{}, false
}

// upstreams — откуда резолвер службы берёт ответы; российский DNS спрашивается
// через физический интерфейс, мимо VPN.
func upstreams() resolver.Upstreams {
	return resolver.Defaults(func() (int, bool) {
		_, index, ok := netwatch.Physical()
		return index, ok
	})
}
