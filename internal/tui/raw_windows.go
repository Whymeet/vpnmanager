package tui

import (
	"errors"

	"golang.org/x/sys/windows"
)

// Raw переводит консоль fd в посимвольный режим без эха и без сигнала от
// Ctrl+C (его разбирает само меню) и возвращает, как вернуть всё обратно.
// Стрелки консоль присылает теми же escape-последовательностями, что терминал
// macOS, и так же понимает их на выводе: меню рисуется одним кодом.
func Raw(fd int) (restore func() error, err error) {
	in := windows.Handle(fd)
	out, err := windows.GetStdHandle(windows.STD_OUTPUT_HANDLE)
	if err != nil {
		return nil, err
	}
	var oldIn, oldOut uint32
	if err := windows.GetConsoleMode(in, &oldIn); err != nil {
		return nil, err
	}
	if err := windows.GetConsoleMode(out, &oldOut); err != nil {
		return nil, err
	}
	raw := oldIn&^(windows.ENABLE_LINE_INPUT|windows.ENABLE_ECHO_INPUT|windows.ENABLE_PROCESSED_INPUT) |
		windows.ENABLE_VIRTUAL_TERMINAL_INPUT
	if err := windows.SetConsoleMode(in, raw); err != nil {
		return nil, err
	}
	if err := windows.SetConsoleMode(out, oldOut|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING); err != nil {
		windows.SetConsoleMode(in, oldIn)
		return nil, err
	}
	return func() error {
		return errors.Join(windows.SetConsoleMode(in, oldIn), windows.SetConsoleMode(out, oldOut))
	}, nil
}
