// Package bind привязывает сокеты к интерфейсу. IP_BOUND_IF не даёт ядру увести
// соединение в другой интерфейс: если через этот маршрута нет, запрос просто не
// проходит.
package bind

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
)

// Control — для net.Dialer.Control: сокет уходит только через интерфейс index.
func Control(index int) func(network, address string, c syscall.RawConn) error {
	return func(network, _ string, c syscall.RawConn) error {
		var serr error
		err := c.Control(func(fd uintptr) {
			switch network {
			case "tcp4", "udp4":
				serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF, index)
			case "tcp6", "udp6":
				serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, index)
			default:
				serr = fmt.Errorf("неожиданная сеть %s", network)
			}
		})
		if err != nil {
			return err
		}
		return serr
	}
}
