//go:build unix

package service

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// lock не даёт запустить вторую службу: она отобрала бы канал у первой.
// Блокировку снимает ядро, когда процесс завершается, даже аварийно.
func lock(path string) (unlock func(), err error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, errors.New("служба уже работает")
		}
		return nil, err
	}
	return func() { f.Close() }, nil
}
