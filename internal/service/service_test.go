package service_test

import (
	"context"
	"errors"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"appguard/internal/core"
	"appguard/internal/ipc"
	"appguard/internal/paths"
	"appguard/internal/service"
	"appguard/internal/service/servicetest"
)

// deps — адаптеры для службы, которая должна отказаться стартовать.
func deps(L paths.Layout) service.Deps {
	return service.Deps{
		Layout: L, Version: "2", Accounts: &servicetest.Accounts{}, Installation: &servicetest.Installation{},
		Network: servicetest.NewNetwork(), Fetch: &servicetest.Web{}, Enforce: &servicetest.Enforcer{},
		SystemDNS: &servicetest.SystemDNS{}, DNSAddr: "127.0.0.1:0", Apps: &servicetest.Scanner{},
		PhysicalAddr: func() (netip.Addr, bool) { return netip.Addr{}, false },
		ScanEvery:    time.Second, LearnFor: time.Minute, RemindEvery: time.Hour, CheckEvery: time.Second, ProbeEvery: time.Second,
		Physical: func() (core.Tunnel, bool) { return core.Tunnel{}, false }, Now: time.Now,
		Logf: func(string, ...any) {},
	}
}

func call(t *testing.T, s *servicetest.Service, cmd string) ipc.Response {
	t.Helper()
	resp, err := ipc.Call(s.Layout.Socket, ipc.Request{Cmd: cmd})
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestStatusIsOpenToAnyUser(t *testing.T) {
	acc := &servicetest.Accounts{Admin: false}
	s := servicetest.Start(t, "", servicetest.Fakes{Accounts: acc})

	resp := call(t, s, ipc.CmdStatus)
	if !resp.OK || resp.Status == nil || resp.Status.Version != servicetest.Version {
		t.Fatalf("статус: %+v", resp)
	}
	if since := time.Since(resp.Status.StartedAt); since < 0 || since > time.Minute {
		t.Fatalf("время старта %v", resp.Status.StartedAt)
	}
	if len(acc.Asked()) > 0 {
		t.Fatal("для статуса служба проверяла права администратора")
	}
}

func TestUninstallIsRefusedForNonAdmin(t *testing.T) {
	acc := &servicetest.Accounts{Admin: false}
	inst := &servicetest.Installation{}
	s := servicetest.Start(t, "", servicetest.Fakes{Accounts: acc, Installation: inst})

	resp := call(t, s, ipc.CmdUninstall)
	if resp.OK || resp.Code != ipc.CodeForbidden {
		t.Fatalf("ответ %+v, ждали отказ", resp)
	}
	for _, want := range []string{"администратор", "student"} {
		if !strings.Contains(resp.Error, want) {
			t.Fatalf("в отказе нет %q: %s", want, resp.Error)
		}
	}
	if inst.Removed.Load() || inst.Stopped.Load() {
		t.Fatal("установка снята по запросу не администратора")
	}
	// Права проверяются у того, кто подключился, а его называет ядро.
	if asked := acc.Asked(); !slices.Equal(asked, []int{os.Getuid()}) {
		t.Fatalf("права проверялись у uid %v, а подключился %d", asked, os.Getuid())
	}
}

func TestUninstallByAdminRemovesAndStopsService(t *testing.T) {
	inst := &servicetest.Installation{}
	s := servicetest.Start(t, "", servicetest.Fakes{Accounts: &servicetest.Accounts{Admin: true}, Installation: inst})

	resp := call(t, s, ipc.CmdUninstall)
	if !resp.OK {
		t.Fatalf("удаление: %+v", resp)
	}
	if !inst.Removed.Load() {
		t.Fatal("файлы установки не сняты")
	}
	select {
	case <-s.Done:
		if err := s.Err(); err != nil {
			t.Fatalf("служба остановилась с ошибкой: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("после удаления служба не остановилась")
	}
	if !inst.Stopped.Load() {
		t.Fatal("служба не снята с launchd")
	}
	if _, err := os.Stat(s.Layout.Socket); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("канал службы остался после остановки")
	}
}

func TestUnknownCommandIsExplained(t *testing.T) {
	s := servicetest.Start(t, "", servicetest.Fakes{})
	if resp := call(t, s, "pause"); resp.OK || resp.Code != ipc.CodeUnknown {
		t.Fatalf("ответ на неизвестную команду: %+v", resp)
	}
}

func TestSecondServiceDoesNotStealTheChannel(t *testing.T) {
	root := t.TempDir()
	s := servicetest.Start(t, root, servicetest.Fakes{})

	second := s.Layout
	second.Socket = servicetest.Socket(t)
	err := service.Run(context.Background(), deps(second))
	if err == nil || !strings.Contains(err.Error(), "уже работает") {
		t.Fatalf("вторая служба: %v", err)
	}
	if resp := call(t, s, ipc.CmdStatus); !resp.OK {
		t.Fatal("первая служба перестала отвечать")
	}
}

func TestBrokenSettingsKeepServiceSilent(t *testing.T) {
	L := paths.Under(t.TempDir())
	L.Socket = servicetest.Socket(t)
	os.MkdirAll(filepath.Dir(L.ConfigFile), 0o700)
	os.WriteFile(L.ConfigFile, []byte("{"), 0o600)

	err := service.Run(context.Background(), deps(L))
	if err == nil || !strings.Contains(err.Error(), "повреждены") {
		t.Fatalf("служба с повреждёнными настройками: %v", err)
	}
	if _, err := os.Stat(L.Socket); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("служба с повреждёнными настройками открыла канал")
	}
}
