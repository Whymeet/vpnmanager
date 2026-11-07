// Package notify — системные уведомления вошедшему пользователю. Служба
// работает от root и без своего сеанса, поэтому уведомление показывается от
// имени того, кто сидит за экраном, через шину его сеанса.
package notify

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Title — заголовок уведомлений.
const Title = "vpnlock"

// timeout — сколько ждать показа: журнал от уведомления не зависит.
const timeout = 10 * time.Second

// Console — уведомления пользователю графического сеанса.
type Console struct{}

// Notify показывает уведомление с текстом text. Никого за экраном нет (сервер,
// вход только по SSH) или нет notify-send — показывать некому и нечем, это не
// ошибка: журнал пишется всегда.
func (Console) Notify(text string) error {
	send, err := exec.LookPath("notify-send")
	if err != nil {
		return nil
	}
	uid, gid, ok := seatUser()
	if !ok {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	// Текст — отдельным аргументом после «--»: начало причины не станет ключом.
	cmd := exec.CommandContext(ctx, send, "--app-name="+Title, "--", Title, text)
	cmd.Env = sessionEnv(uid)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}}
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("уведомление: %w: %s", err, bytes.TrimSpace(out))
	}
	return nil
}

// sessionEnv — окружение, в котором notify-send находит шину сеанса uid.
func sessionEnv(uid int) []string {
	run := "/run/user/" + strconv.Itoa(uid)
	return []string{"XDG_RUNTIME_DIR=" + run, "DBUS_SESSION_BUS_ADDRESS=unix:path=" + run + "/bus", "LANG=C.UTF-8"}
}

// seatUser — кто сидит за экраном: активный местный графический сеанс из
// loginctl. Вход по SSH уведомление показать не может.
func seatUser() (uid, gid int, ok bool) {
	out, err := exec.Command("loginctl", "list-sessions", "--no-legend", "--no-pager").Output()
	if err != nil {
		return 0, 0, false
	}
	for line := range strings.Lines(string(out)) {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		info, err := exec.Command("loginctl", "show-session", fields[0], "-p", "Active", "-p", "Remote", "-p", "Type", "-p", "User").Output()
		if err != nil {
			continue
		}
		if uid, ok := graphicalUser(string(info)); ok {
			var st syscall.Stat_t
			if syscall.Stat("/run/user/"+strconv.Itoa(uid), &st) != nil {
				continue
			}
			return uid, int(st.Gid), true
		}
	}
	return 0, 0, false
}

// graphicalUser разбирает `loginctl show-session`: uid пользователя, если сеанс
// активный, местный и графический.
func graphicalUser(info string) (int, bool) {
	vals := map[string]string{}
	for line := range strings.Lines(info) {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
			vals[k] = v
		}
	}
	uid, err := strconv.Atoi(vals["User"])
	if err != nil || uid == 0 || vals["Active"] != "yes" || vals["Remote"] != "no" {
		return 0, false
	}
	return uid, vals["Type"] == "x11" || vals["Type"] == "wayland"
}
