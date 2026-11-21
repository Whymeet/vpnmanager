package cli

import (
	"fmt"
	"time"

	"appguard/internal/ipc"
)

// agentRetry — через сколько агент уведомлений переподключается к службе,
// которая перезапускается или ещё не стартовала.
var agentRetry = 5 * time.Second

// notifyAgent — агент уведомлений в сеансе пользователя (Windows): его
// запускает задача при входе в систему. Он слушает уведомления службы и
// показывает их, пока appguard установлен; после удаления выходит сам.
func notifyAgent(env Env) int {
	if env.Toast == nil {
		fmt.Fprintln(env.Err, "Агент уведомлений нужен только на Windows: на macOS уведомления показывает сама служба.")
		return 2
	}
	for {
		ipc.Stream(env.Layout.Socket, ipc.Request{Cmd: ipc.CmdNotifications}, func(r ipc.Response) error {
			if r.OK && r.Event != nil {
				if err := env.Toast(r.Event.Text); err != nil {
					fmt.Fprintf(env.Err, "уведомление: %v\n", err)
				}
			}
			return nil
		})
		if !installed(env.Layout) {
			return 0
		}
		time.Sleep(agentRetry)
	}
}
