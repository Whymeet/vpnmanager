//go:build live && darwin

package tray

import (
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// На несколько секунд ставит значок в строку меню: сначала перечёркнутый щит, потом
// щит с замком. tools/go test -tags live -v ./internal/tray. Нужен графический
// сеанс, sudo не нужен.
func TestLiveIconShowsAndHides(t *testing.T) {
	icon, err := System()
	if err != nil {
		t.Fatal(err)
	}
	died, err := icon.Show(View{Title: "Приложения без сети", Detail: "VPN выключен", Notify: true}, func() {})
	if err != nil {
		t.Fatal(err)
	}
	s := icon.(*statusItem)
	select {
	case err := <-died:
		t.Fatalf("значок умер сразу: %v", err)
	case <-time.After(2 * time.Second):
	}
	icon.Update(View{Open: true, Title: "Приложения в сети", Detail: "Выход 185.1.2.3, Германия"})
	select {
	case err := <-died:
		t.Fatalf("значок умер после смены вида: %v", err)
	case <-time.After(2 * time.Second):
	}
	if !utf8.ValidString(script) || !strings.Contains(script, "appguard") {
		t.Fatal("скрипт испорчен")
	}
	gone := s.gone
	icon.Hide()
	select {
	case <-gone:
	default:
		t.Fatal("Hide вернулся, а osascript работает")
	}
}
