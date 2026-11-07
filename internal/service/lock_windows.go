package service

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

// lock не даёт запустить вторую службу: она отобрала бы канал у первой.
// Блокировку снимает ядро, когда процесс завершается, даже аварийно.
func lock(path string) (unlock func(), err error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	const flags = windows.LOCKFILE_EXCLUSIVE_LOCK | windows.LOCKFILE_FAIL_IMMEDIATELY
	if err := windows.LockFileEx(windows.Handle(f.Fd()), flags, 0, 1, 0, new(windows.Overlapped)); err != nil {
		f.Close()
		if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			return nil, errors.New("служба уже работает")
		}
		return nil, err
	}
	return func() { f.Close() }, nil
}
