package install

import (
	"bytes"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const launchctl = "/bin/launchctl"

// Launchctl — launchd через системную утилиту launchctl.
type Launchctl struct{}

// Bootstrap загружает службу. Сразу после bootout launchd иногда ещё не отпустил
// прежнюю и отвечает «Bootstrap failed: 5», поэтому несколько попыток.
func (Launchctl) Bootstrap(plist string) error {
	var err error
	for range 5 {
		if err = run("bootstrap", "system", plist); err == nil {
			return nil
		}
		time.Sleep(time.Second)
	}
	return err
}

func (Launchctl) Bootout(label string) error {
	if !loaded(label) {
		return nil
	}
	if err := run("bootout", "system/"+label); err != nil {
		return err
	}
	for i := 0; i < 50 && loaded(label); i++ {
		time.Sleep(100 * time.Millisecond)
	}
	return nil
}

// BootoutDetached запускает launchctl в своей сессии: снимая службу, launchd
// завершает её группу процессов, и launchctl в ней оборвался бы на полпути.
func (Launchctl) BootoutDetached(label string) error {
	cmd := exec.Command(launchctl, "bootout", "system/"+label)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	go cmd.Wait()
	return nil
}

// BootstrapUser загружает задачу в сеанс пользователя uid (домен gui/<uid>).
// Сеанса нет — ошибка сразу: задача загрузится сама при следующем входе. Сеанс есть —
// несколько попыток, как у Bootstrap: значок работает постоянно, и после bootout launchd
// отпускает его не сразу.
func (Launchctl) BootstrapUser(uid int, plist string) error {
	domain := "gui/" + strconv.Itoa(uid)
	var err error
	for range 5 {
		if err = run("bootstrap", domain, plist); err == nil {
			return nil
		}
		if exec.Command(launchctl, "print", domain).Run() != nil {
			return err
		}
		time.Sleep(time.Second)
	}
	return err
}

func (Launchctl) BootoutUser(uid int, label string) error {
	target := "gui/" + strconv.Itoa(uid) + "/" + label
	if exec.Command(launchctl, "print", target).Run() != nil {
		return nil
	}
	return run("bootout", target)
}

// Enable снимает запрет, только если он стоит: `launchctl enable` оставляет в базе
// launchd запись о службе, которую потом штатно не удалить, а чистая установка
// следов после удаления оставлять не должна.
func (Launchctl) Enable(label string) error {
	out, err := exec.Command(launchctl, "print-disabled", "system").Output()
	if err != nil {
		return fmt.Errorf("launchctl print-disabled system: %w", err)
	}
	if !disabled(string(out), label) {
		return nil
	}
	return run("enable", "system/"+label)
}

// disabled ищет службу среди запрещённых в выводе `launchctl print-disabled`:
// `"<label>" => disabled` в новых macOS, `=> true` в старых.
func disabled(printDisabled, label string) bool {
	for line := range strings.Lines(printDisabled) {
		name, state, ok := strings.Cut(strings.TrimSpace(line), "=>")
		if ok && strings.Trim(strings.TrimSpace(name), `"`) == label {
			state = strings.TrimSpace(state)
			return state == "disabled" || state == "true"
		}
	}
	return false
}

func loaded(label string) bool {
	return exec.Command(launchctl, "print", "system/"+label).Run() == nil
}

func run(args ...string) error {
	out, err := exec.Command(launchctl, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("launchctl %s: %v: %s", strings.Join(args, " "), err, bytes.TrimSpace(out))
	}
	return nil
}
