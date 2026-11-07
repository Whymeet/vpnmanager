// Package notify — системные уведомления вошедшему пользователю. Служба
// работает от root и без своего сеанса, поэтому уведомление показывается от
// имени того, кто сидит за экраном, в его сеансе.
package notify

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"
)

// Title — заголовок уведомлений.
const Title = "vpnlock"

// timeout — сколько ждать показа: osascript может задуматься, а журнал от
// уведомления не зависит.
const timeout = 10 * time.Second

// Console — уведомления пользователю, вошедшему в систему за экраном.
type Console struct{}

// Notify показывает уведомление с текстом text. Никто не вошёл — показывать
// некому, это не ошибка.
func (Console) Notify(text string) error {
	uid, ok := consoleUser()
	if !ok {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/launchctl", command(uid, text)...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("уведомление: %w: %s", err, bytes.TrimSpace(out))
	}
	return nil
}

// command — аргументы launchctl: в сеансе пользователя uid и от его имени
// osascript показывает уведомление. Текст передаётся аргументом скрипта, а не
// вклеивается в него: кавычки и прочее в причине ничего не сломают.
func command(uid int, text string) []string {
	return []string{
		"asuser", strconv.Itoa(uid),
		"/usr/bin/sudo", "-u", "#" + strconv.Itoa(uid),
		"/usr/bin/osascript",
		"-e", "on run argv",
		"-e", "display notification (item 1 of argv) with title (item 2 of argv)",
		"-e", "end run",
		text, Title,
	}
}

// consoleUser — кто вошёл в систему за экраном: владелец /dev/console. Пока
// никто не вошёл, им владеет root.
func consoleUser() (int, bool) {
	fi, err := os.Stat("/dev/console")
	if err != nil {
		return 0, false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st.Uid == 0 {
		return 0, false
	}
	return int(st.Uid), true
}
