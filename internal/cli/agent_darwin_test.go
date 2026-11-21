package cli_test

import (
	"os"
	"slices"
	"sync"
	"testing"
	"time"

	"appguard/internal/cli"
	"appguard/internal/ipc"
	"appguard/internal/service/servicetest"
)

// Агент уведомлений (на Windows его запускает задача при входе) показывает
// то, что раздаёт служба, и выходит сам, когда appguard больше не установлен.
func TestNotifyAgentShowsNotesAndLeavesWithTheTool(t *testing.T) {
	s := servicetest.Start(t, "", servicetest.Fakes{Accounts: &servicetest.Accounts{Admin: true}})
	var mu sync.Mutex
	var shown []string
	env := cli.Env{Layout: s.Layout, Toast: func(text string) error {
		mu.Lock()
		defer mu.Unlock()
		shown = append(shown, text)
		return nil
	}}
	done := make(chan run, 1)
	go func() { done <- appguard(env, "", "notify-agent") }()
	time.Sleep(200 * time.Millisecond) // агент подписался

	s.Web.Set("185.1.2.3", "DE", "DE")
	s.Network.Set(servicetest.Tunnel("utun11", "10.8.0.2"))
	s.WaitStatus(t, 2*time.Second, func(st ipc.Status) bool { return len(st.Paths) == 1 && st.Paths[0].State == "verified" })
	s.Network.Set()
	want := []string{"Защищённые приложения в сети: выход 185.1.2.3, Германия", "Защищённые приложения без сети: VPN выключен"}
	for deadline := time.Now().Add(2 * time.Second); ; {
		mu.Lock()
		got := slices.Clone(shown)
		mu.Unlock()
		if slices.Equal(got, want) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("агент показал %q", got)
		}
		time.Sleep(10 * time.Millisecond)
	}

	// appguard удалён: файлов установки нет, служба ушла — агенту больше нечего
	// делать.
	os.RemoveAll(s.Layout.AppDir)
	s.Stop()
	select {
	case r := <-done:
		if r.code != 0 {
			t.Fatalf("агент вышел с %+v", r)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("агент не вышел после удаления")
	}
}

func TestNotifyAgentIsForWindowsOnly(t *testing.T) {
	if r := appguard(cli.Env{Layout: emptyLayout(t)}, "", "notify-agent"); r.code != 2 {
		t.Fatalf("%+v", r)
	}
}
