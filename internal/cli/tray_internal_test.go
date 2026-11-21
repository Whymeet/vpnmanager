//go:build !windows

package cli

import (
	"bytes"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"vpnlock/internal/service/servicetest"
	"vpnlock/internal/tray"
)

// testIcon — показ значка в тесте; служба и сокет настоящие.
type testIcon struct {
	mu     sync.Mutex
	on     bool
	view   tray.View
	toggle func()
}

func (i *testIcon) Show(v tray.View, toggle func()) (<-chan error, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.on, i.view, i.toggle = true, v, toggle
	return make(chan error, 1), nil
}

func (i *testIcon) Update(v tray.View) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.view = v
}

func (i *testIcon) shownView() tray.View {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.view
}

func (i *testIcon) Hide() {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.on = false
}

func (i *testIcon) shown() bool {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.on
}

// point направляет сокет значка на настоящий сокет службы: при каждом запуске
// servicetest у службы новый адрес, а значок знает один.
func point(t *testing.T, link, socket string) {
	t.Helper()
	os.Remove(link)
	if err := os.Symlink(socket, link); err != nil {
		t.Fatal(err)
	}
}

func waitIcon(t *testing.T, i *testIcon, on bool, what string) {
	t.Helper()
	for deadline := time.Now().Add(3 * time.Second); i.shown() != on; {
		if time.Now().After(deadline) {
			t.Fatal(what)
		}
		time.Sleep(time.Millisecond)
	}
}

func fastTray(t *testing.T) {
	t.Helper()
	every, wait, busy := trayEvery, trayWait, trayBusyWait
	trayEvery, trayWait, trayBusyWait = 10*time.Millisecond, 50*time.Millisecond, 100*time.Millisecond
	t.Cleanup(func() { trayEvery, trayWait, trayBusyWait = every, wait, busy })
}

// Значок за настоящей службой: появляется при её ответе, исчезает, когда она
// остановилась, зависшая служба его тоже гасит, вернувшаяся — возвращает, а удаление
// vpnlock завершает значок.
func TestTrayFollowsRealService(t *testing.T) {
	fastTray(t)
	root := t.TempDir()
	first := servicetest.Start(t, root, servicetest.Fakes{})
	link := servicetest.Socket(t)
	point(t, link, first.Layout.Socket)

	env := Env{Layout: first.Layout, Err: &bytes.Buffer{}}
	env.Layout.Socket = link
	icon := &testIcon{}
	env.Tray = func() (tray.Icon, error) { return icon, nil }
	done := make(chan int, 1)
	go func() { done <- trayCmd(env) }()

	waitIcon(t, icon, true, "значок не появился при ответе службы")

	first.Stop()
	waitIcon(t, icon, false, "значок не скрылся после остановки службы")

	second := servicetest.Start(t, root, servicetest.Fakes{})
	point(t, link, second.Layout.Socket)
	waitIcon(t, icon, true, "значок не вернулся вместе со службой")

	// Служба зависла: соединение принимается, ответа нет (SIGSTOP).
	hung, err := net.Listen("unix", servicetest.Socket(t))
	if err != nil {
		t.Fatal(err)
	}
	defer hung.Close()
	point(t, link, hung.Addr().String())
	waitIcon(t, icon, false, "значок не скрылся у зависшей службы")
	point(t, link, second.Layout.Socket)
	waitIcon(t, icon, true, "значок не вернулся после зависания")

	if err := os.RemoveAll(env.Layout.AppDir); err != nil {
		t.Fatal(err)
	}
	second.Stop()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("значок вышел с кодом %d", code)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("значок не вышел после удаления vpnlock")
	}
	if icon.shown() {
		t.Fatal("значок остался после удаления")
	}
}

// Картинка и меню — защита настоящей службы; пункт «Уведомления» выключает их у
// службы, хотя значок работает без прав администратора.
func TestTrayShowsProtectionAndSwitchesNotifications(t *testing.T) {
	fastTray(t)
	s := servicetest.Start(t, "", servicetest.Fakes{Accounts: &servicetest.Accounts{Admin: false}})
	icon := &testIcon{}
	env := Env{Layout: s.Layout, Err: &bytes.Buffer{}, Tray: func() (tray.Icon, error) { return icon, nil }}
	done := make(chan int, 1)
	go func() { done <- trayCmd(env) }()
	t.Cleanup(func() {
		os.RemoveAll(s.Layout.AppDir) // значок выходит сам, когда vpnlock удалён
		s.Stop()
		<-done
	})
	waitView := func(want tray.View, what string) {
		t.Helper()
		for deadline := time.Now().Add(3 * time.Second); icon.shownView() != want; {
			if time.Now().After(deadline) {
				t.Fatalf("%s: показано %+v", what, icon.shownView())
			}
			time.Sleep(time.Millisecond)
		}
	}
	waitView(tray.View{Title: "Приложения без сети", Detail: "VPN выключен", Notify: true}, "без VPN")

	s.Web.Set("185.1.2.3", "DE", "DE")
	s.Network.Set(servicetest.Tunnel("utun11", "10.8.0.2"))
	online := tray.View{Open: true, Title: "Приложения в сети", Detail: "Выход 185.1.2.3, Германия", Notify: true}
	waitView(online, "с VPN")

	icon.mu.Lock()
	toggle := icon.toggle
	icon.mu.Unlock()
	toggle()
	online.Notify = false
	waitView(online, "после выбора в меню")
	if st := s.Status(t); !st.NotifyOff {
		t.Fatalf("служба уведомления не выключила: %+v", st)
	}
}

func TestTraySecondInstanceAndNoSessionLeaveQuietly(t *testing.T) {
	fastTray(t)
	for _, reason := range []error{tray.ErrBusy, tray.ErrNoSession} {
		var errOut bytes.Buffer
		env := Env{Err: &errOut, Tray: func() (tray.Icon, error) { return nil, reason }}
		if code := Run([]string{"tray"}, env); code != 0 || errOut.Len() != 0 {
			t.Errorf("%v: код %d, вывод %q", reason, code, errOut.String())
		}
	}
}

// При обновлении прежний значок уходит не мгновенно: новый дожидается места.
func TestTrayWaitsForThePreviousOneToLeave(t *testing.T) {
	fastTray(t)
	s := servicetest.Start(t, "", servicetest.Fakes{})
	icon := &testIcon{}
	tries := 0
	env := Env{Layout: s.Layout, Err: &bytes.Buffer{}, Tray: func() (tray.Icon, error) {
		if tries++; tries < 3 {
			return nil, tray.ErrBusy
		}
		return icon, nil
	}}
	done := make(chan int, 1)
	go func() { done <- trayCmd(env) }()
	t.Cleanup(func() {
		os.RemoveAll(s.Layout.AppDir)
		s.Stop()
		<-done
	})
	waitIcon(t, icon, true, "новый значок не дождался, пока уйдёт прежний")
}

func TestTrayNamesOtherFailure(t *testing.T) {
	var errOut bytes.Buffer
	env := Env{Err: &errOut, Tray: func() (tray.Icon, error) { return nil, errors.New("диск полон") }}
	if code := Run([]string{"tray"}, env); code != 1 || !strings.Contains(errOut.String(), "диск полон") {
		t.Fatalf("код %d, вывод %q", code, errOut.String())
	}
}

// Служебная команда: в справке её нет, как notify-agent.
func TestTrayIsNotInHelp(t *testing.T) {
	var out bytes.Buffer
	usage(&out)
	if strings.Contains(out.String(), "tray") {
		t.Fatal("значок попал в справку")
	}
}

// Показ значка обращается к настоящему сокету только на чтение: файлов рядом с ним
// значок не заводит (настроек не меняет).
func TestTrayChangesNothingOnDisk(t *testing.T) {
	fastTray(t)
	s := servicetest.Start(t, "", servicetest.Fakes{})
	before := listing(t, s.Layout.AppDir)
	env := Env{Layout: s.Layout, Err: &bytes.Buffer{}}
	icon := &testIcon{}
	env.Tray = func() (tray.Icon, error) { return icon, nil }
	done := make(chan int, 1)
	go func() { done <- trayCmd(env) }()
	waitIcon(t, icon, true, "значок не появился")
	time.Sleep(50 * time.Millisecond)
	if after := listing(t, s.Layout.AppDir); after != before {
		t.Fatalf("значок поменял файлы службы:\n%s\n---\n%s", before, after)
	}
	os.RemoveAll(env.Layout.AppDir)
	s.Stop()
	<-done
}

func listing(t *testing.T, dir string) string {
	t.Helper()
	var b strings.Builder
	filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && !strings.Contains(p, "journal") {
			data, _ := os.ReadFile(p)
			b.WriteString(p + " " + string(data) + "\n")
		}
		return nil
	})
	return b.String()
}
