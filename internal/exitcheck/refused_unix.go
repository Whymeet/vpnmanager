//go:build unix

package exitcheck

import (
	"errors"
	"net"
	"syscall"
)

// refused — узел ответил отказом в соединении.
func refused(err error) bool { return errors.Is(err, syscall.ECONNREFUSED) }

// connected — у сокета есть собеседник: ядро знает адрес другого конца.
func connected(c net.Conn) bool {
	sc, ok := c.(syscall.Conn)
	if !ok {
		return true
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		return true
	}
	var perr error
	if err := rc.Control(func(fd uintptr) { _, perr = syscall.Getpeername(int(fd)) }); err != nil {
		return true
	}
	return !errors.Is(perr, syscall.ENOTCONN)
}
