package ipc

import (
	"errors"
	"net"

	"golang.org/x/sys/unix"
)

// peerOf спрашивает у ядра учётную запись процесса, который подключился к сокету.
func peerOf(conn net.Conn) (Peer, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return Peer{}, errors.New("соединение не через unix-сокет")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return Peer{}, err
	}
	var (
		cred *unix.Ucred
		serr error
	)
	err = raw.Control(func(fd uintptr) {
		cred, serr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	})
	if err == nil {
		err = serr
	}
	if err != nil {
		return Peer{}, err
	}
	return Peer{UID: int(cred.Uid), PID: int(cred.Pid)}, nil
}
