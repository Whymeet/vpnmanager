package install

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

// Systemctl — systemd через системную утилиту systemctl.
type Systemctl struct{}

func (Systemctl) Reload() error { return systemctl("daemon-reload") }

func (Systemctl) Start(unit string) error { return systemctl("enable", "--now", unit) }

// Halt не считает ошибкой юнит, которого нет: так выглядит первая установка.
func (Systemctl) Halt(unit string) error { return ifLoaded(unit, "stop") }

func (Systemctl) Disable(unit string) error { return ifLoaded(unit, "disable") }

func ifLoaded(unit, verb string) error {
	out, err := exec.Command("systemctl", "show", "-p", "LoadState", "--value", "--", unit).Output()
	if err != nil {
		return fmt.Errorf("systemctl show %s: %w", unit, err)
	}
	if strings.TrimSpace(string(out)) != "loaded" {
		return nil
	}
	return systemctl(verb, unit)
}

// Forget не ошибается: юнит, у которого нечего забывать, — обычное дело.
func (Systemctl) Forget(unit string) { exec.Command("systemctl", "reset-failed", "--", unit).Run() }

// StopDetached не ждёт: systemd завершит и вызвавшую службу, и этот systemctl в её
// группе, поэтому ответа дожидаться некому.
func (Systemctl) StopDetached(unit string) error { return systemctl("--no-block", "stop", unit) }

func systemctl(args ...string) error {
	out, err := exec.Command("systemctl", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl %s: %v: %s", strings.Join(args, " "), err, bytes.TrimSpace(out))
	}
	return nil
}
