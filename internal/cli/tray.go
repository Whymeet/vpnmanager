package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"appguard/internal/ipc"
	"appguard/internal/tray"
)

// Как часто значок спрашивает службу и сколько ждёт ответа. Картинка отстаёт от
// защиты не больше чем на trayEvery. Три неудачи подряд скрывают значок, поэтому от
// остановки службы до его исчезновения проходит не больше 3·(2+3) с — меньше 30 с из
// К40.
var (
	trayEvery = 2 * time.Second
	trayWait  = 3 * time.Second
)

// trayBusyWait — сколько новый значок ждёт, пока уйдёт прежний: при обновлении
// установка снимает старый и тут же запускает новый, а старый уходит не мгновенно.
// Настоящий второй экземпляр после этого молча выходит.
var trayBusyWait = 5 * time.Second

// trayCmd — значок службы в сеансе пользователя: его запускает автозапуск при входе в
// систему. Служебная команда, как notify-agent: в справку не входит. Из настроек
// меняет одну — уведомления, пунктом меню. Второй экземпляр и сеанс без шины — не
// ошибка: молча выходит.
func trayCmd(env Env) int {
	if env.Tray == nil {
		fmt.Fprintln(env.Err, "Значка на этой системе нет.")
		return 2
	}
	icon, err := env.Tray()
	for deadline := time.Now().Add(trayBusyWait); errors.Is(err, tray.ErrBusy) && time.Now().Before(deadline); {
		time.Sleep(trayBusyWait / 20)
		icon, err = env.Tray()
	}
	switch {
	case errors.Is(err, tray.ErrBusy), errors.Is(err, tray.ErrNoSession):
		return 0
	case err != nil:
		fmt.Fprintf(env.Err, "значок: %v\n", err)
		return 1
	}
	tray.OpenVPN = vpnOpener(env)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	tray.Loop{
		Icon: icon,
		State: func() (ipc.Protection, error) {
			resp, err := ipc.CallWait(env.Layout.Socket, ipc.Request{Cmd: ipc.CmdProtection}, trayWait)
			switch {
			case err != nil:
				return ipc.Protection{}, err
			case resp.Protection == nil:
				// Служба старше значка: отвечает, но защиту не называет — открыто без
				// выхода значок показывает как «appguard работает».
				return ipc.Protection{Open: true}, nil
			}
			return *resp.Protection, nil
		},
		SetNotify: func(on bool) error {
			resp, err := ipc.CallWait(env.Layout.Socket, ipc.Request{Cmd: ipc.CmdNotify, Notify: on}, trayWait)
			if err == nil && !resp.OK {
				err = errors.New(resp.Error)
			}
			return err
		},
		Installed: func() bool { return installed(env.Layout) },
		Every:     trayEvery,
		Logf:      func(format string, args ...any) { fmt.Fprintf(env.Err, format+"\n", args...) },
	}.Run(ctx)
	return 0
}
