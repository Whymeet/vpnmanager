package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"vpnlock/internal/ipc"
	"vpnlock/internal/tray"
)

// Как часто значок спрашивает службу и сколько ждёт ответа. Три неудачи подряд
// скрывают значок, поэтому от остановки службы до его исчезновения проходит не больше
// (5+5+5)+3 с — меньше 30 с из К40.
var (
	trayEvery = 5 * time.Second
	trayWait  = 3 * time.Second
)

// trayCmd — значок службы в сеансе пользователя: его запускает автозапуск при входе в
// систему. Служебная команда, как notify-agent: в справку не входит, настроек не
// меняет. Второй экземпляр и сеанс без шины — не ошибка: молча выходит.
func trayCmd(env Env) int {
	if env.Tray == nil {
		fmt.Fprintln(env.Err, "Значка на этой системе нет.")
		return 2
	}
	icon, err := env.Tray()
	switch {
	case errors.Is(err, tray.ErrBusy), errors.Is(err, tray.ErrNoSession):
		return 0
	case err != nil:
		fmt.Fprintf(env.Err, "значок: %v\n", err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	tray.Loop{
		Icon: icon,
		Alive: func() bool {
			_, err := ipc.CallWait(env.Layout.Socket, ipc.Request{Cmd: ipc.CmdStatus}, trayWait)
			return err == nil
		},
		Installed: func() bool { return installed(env.Layout) },
		Every:     trayEvery,
		Logf:      func(format string, args ...any) { fmt.Fprintf(env.Err, format+"\n", args...) },
	}.Run(ctx)
	return 0
}
