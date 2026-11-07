//go:build unix

package tui

import "golang.org/x/sys/unix"

// Raw переводит терминал fd в посимвольный режим без эха и без сигналов от
// Ctrl+C (его разбирает само меню) и возвращает, как вернуть всё обратно.
// Вывод остаётся обычным: перевод строки по-прежнему возвращает каретку.
func Raw(fd int) (restore func() error, err error) {
	old, err := unix.IoctlGetTermios(fd, getTermios)
	if err != nil {
		return nil, err
	}
	raw := *old
	raw.Lflag &^= unix.ICANON | unix.ECHO | unix.ISIG | unix.IEXTEN
	raw.Iflag &^= unix.IXON
	raw.Cc[unix.VMIN] = 1
	raw.Cc[unix.VTIME] = 0
	if err := unix.IoctlSetTermios(fd, setTermios, &raw); err != nil {
		return nil, err
	}
	return func() error { return unix.IoctlSetTermios(fd, setTermios, old) }, nil
}
