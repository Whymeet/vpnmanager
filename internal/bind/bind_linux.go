// Package bind привязывает сокеты к интерфейсу. SO_BINDTOIFINDEX не даёт ядру
// увести соединение в другой интерфейс: если через этот маршрута нет, запрос
// просто не проходит. Правила маршрутизации wg-quick такой сокет тоже не уводят:
// маршрут через другой интерфейс ему не подходит.
package bind

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// Control — для net.Dialer.Control: сокет уходит только через интерфейс index.
func Control(index int) func(network, address string, c syscall.RawConn) error {
	return func(_, _ string, c syscall.RawConn) error {
		var serr error
		err := c.Control(func(fd uintptr) {
			serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_BINDTOIFINDEX, index)
		})
		if err != nil {
			return err
		}
		return serr
	}
}
