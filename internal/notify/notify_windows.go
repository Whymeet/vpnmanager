// Package notify — системные уведомления пользователю. На Windows у службы
// своего сеанса нет: уведомления показывает агент в сеансе пользователя
// (vpnlock notify-agent), получая их от службы.
package notify

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
	"unicode/utf16"

	"golang.org/x/sys/windows"
)

// timeout — сколько ждать показа: PowerShell может задуматься, а журнал от
// уведомления не зависит.
const timeout = 15 * time.Second

// toastScript показывает уведомление Windows от имени PowerShell (своего
// идентификатора приложения у vpnlock нет). Текст приходит переменной
// окружения, а не вклеивается в скрипт: кавычки в причине ничего не сломают.
const toastScript = `$ErrorActionPreference = 'Stop'
[void][Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime]
[void][Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime]
$x = New-Object Windows.Data.Xml.Dom.XmlDocument
$x.LoadXml('<toast><visual><binding template="ToastGeneric"><text>vpnlock</text><text></text></binding></visual></toast>')
[void]$x.GetElementsByTagName('text').Item(1).AppendChild($x.CreateTextNode($env:VPNLOCK_NOTE))
$app = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe'
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($app).Show([Windows.UI.Notifications.ToastNotification]::new($x))
`

// Toast показывает уведомление с текстом text в сеансе того, кто его вызвал.
func Toast(text string) error {
	sys, err := windows.GetSystemDirectory()
	if err != nil {
		return err
	}
	ps := filepath.Join(sys, "WindowsPowerShell", "v1.0", "powershell.exe")
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, ps, "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-EncodedCommand", encode(toastScript))
	cmd.Env = append(os.Environ(), "VPNLOCK_NOTE="+text)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("уведомление: %w: %s", err, out)
	}
	return nil
}

// encode — скрипт для -EncodedCommand: UTF-16LE в base64.
func encode(script string) string {
	u := utf16.Encode([]rune(script))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		b[2*i], b[2*i+1] = byte(c), byte(c>>8)
	}
	return base64.StdEncoding.EncodeToString(b)
}
