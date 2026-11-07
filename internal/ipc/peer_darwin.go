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
		cred *unix.Xucred
		pid  int
		serr error
	)
	err = raw.Control(func(fd uintptr) {
		cred, serr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if serr == nil {
			pid, serr = unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID)
		}
	})
	if err == nil {
		err = serr
	}
	if err != nil {
		return Peer{}, err
	}
	return Peer{UID: int(cred.Uid), PID: pid}, nil
}
