package exitcheck

import (
	"errors"
	"net"

	"golang.org/x/sys/windows"
)

// refused — узел ответил отказом в соединении. На Windows это WSAECONNREFUSED,
// а не syscall.ECONNREFUSED.
func refused(err error) bool { return errors.Is(err, windows.WSAECONNREFUSED) }

// connected — на Windows WFP отбрасывает молча, и соединение без собеседника
// не возвращается: соединилось — значит, соединилось.
func connected(net.Conn) bool { return true }
