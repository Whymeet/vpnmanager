//go:build live && darwin

// Живая проверка: tools/go test -tags live -v -run LiveNotification ./internal/notify
// Показывает на экране одно уведомление appguard.

package notify

import (
	"os"
	"os/exec"
	"testing"
)

// Тот же скрипт, что у службы, но от себя: launchctl asuser нужен только root.
func TestLiveNotification(t *testing.T) {
	uid, ok := consoleUser()
	if !ok {
		t.Skip("никто не вошёл в систему за экраном")
	}
	if uid != os.Getuid() {
		t.Skipf("за экраном другой пользователь (uid %d)", uid)
	}
	args := command(uid, "Проверка уведомлений: «кавычки» и \"тоже\" — на месте")
	out, err := exec.Command(args[5], args[6:]...).CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	t.Log("уведомление показано — посмотри в правый верхний угол экрана")
}
