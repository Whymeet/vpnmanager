package service_test

import (
	"slices"
	"strings"
	"testing"
	"time"

	"vpnlock/internal/enforce"
	"vpnlock/internal/ipc"
	"vpnlock/internal/service/servicetest"
)

// Сценарии таски 38: защита одним файлом и адреса без домена.

func importList(t *testing.T, s *servicetest.Service, domains, addrs []string) ipc.Response {
	t.Helper()
	resp, err := ipc.Call(s.Layout.Socket, ipc.Request{Cmd: ipc.CmdImport, Domains: domains, Addrs: addrs})
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// Всё из файла закрыто сразу, без приложений и обучения; что закрывать нельзя,
// отброшено с причиной; после перезапуска защита на месте.
func TestImportProtectsEverythingAtOnce(t *testing.T) {
	root := t.TempDir()
	s := servicetest.Start(t, root, servicetest.Fakes{Accounts: &servicetest.Accounts{Admin: true}})
	s.DNS.Maps("claude.ai", "160.79.104.20")
	resp := importList(t, s,
		[]string{"claude.ai", "yandex.ru", "printer.local", "не домен"},
		[]string{"160.79.104.10", "2607:6bc0::10", "192.168.1.1", "1.1.1.1", "x"})
	if !resp.OK || resp.Imported == nil || resp.Imported.Domains != 1 || resp.Imported.Addrs != 2 || len(resp.Warnings) != 6 {
		t.Fatalf("импорт: %+v", resp)
	}
	// Адреса закрыты сразу, домен направлен на резолвер службы, его адреса
	// узнаются фоном. VPN нет — всё закрыто.
	waitRules(t, s, 2*time.Second, func(r enforce.Rules) bool {
		return len(r.OpenIfaces) == 0 && has(r, "160.79.104.10") && has(r, "2607:6bc0::10") && has(r, "160.79.104.20")
	})
	if r := s.Enforce.Rules(); has(r, "192.168.1.1") || has(r, "1.1.1.1") {
		t.Fatalf("закрыто то, что закрывать нельзя: %+v", r)
	}
	if got := s.SystemDNS.Domains(); !slices.Equal(got, []string{"claude.ai"}) {
		t.Fatalf("на службу направлены %v", got)
	}
	hasLine(t, s, "импорт: защищено вручную 1 домен и 2 адреса")
	if st := s.Status(t); !slices.Equal(st.Manual, []string{"claude.ai"}) || st.ManualAddrs != 2 {
		t.Fatalf("статус: %v %d", st.Manual, st.ManualAddrs)
	}

	// Повторный импорт ничего не добавляет.
	if resp := importList(t, s, []string{"claude.ai"}, []string{"160.79.104.10"}); !resp.OK || resp.Imported.Domains+resp.Imported.Addrs != 0 {
		t.Fatalf("повторный импорт: %+v", resp)
	}

	// После перезапуска адреса в таблицах сразу, без сети.
	s.Stop()
	again := servicetest.Start(t, root, servicetest.Fakes{})
	waitRules(t, again, time.Second, func(r enforce.Rules) bool { return has(r, "160.79.104.10") && has(r, "2607:6bc0::10") })

	// Импорт — только администратору.
	user := servicetest.Start(t, "", servicetest.Fakes{Accounts: &servicetest.Accounts{Admin: false}})
	if resp := importList(t, user, nil, []string{"160.79.104.10"}); resp.OK || resp.Code != ipc.CodeForbidden {
		t.Fatalf("не администратор: %+v", resp)
	}
}

// protect и unprotect принимают адрес.
func TestProtectAddress(t *testing.T) {
	s := servicetest.Start(t, "", servicetest.Fakes{Accounts: &servicetest.Accounts{Admin: true}})
	s.Protect(t, "34.149.66.165")
	waitRules(t, s, 2*time.Second, func(r enforce.Rules) bool { return has(r, "34.149.66.165") })
	resp, err := ipc.Call(s.Layout.Socket, ipc.Request{Cmd: ipc.CmdProtect, Domain: "127.0.0.1"})
	if err != nil || resp.OK || !strings.Contains(resp.Error, "нельзя закрывать") {
		t.Fatalf("петля: %v %+v", err, resp)
	}
	if resp, err := ipc.Call(s.Layout.Socket, ipc.Request{Cmd: ipc.CmdUnprotect, Domain: "34.149.66.165"}); err != nil || !resp.OK {
		t.Fatalf("снять: %v %+v", err, resp)
	}
	waitRules(t, s, 2*time.Second, func(r enforce.Rules) bool { return !has(r, "34.149.66.165") })
	if st := s.Status(t); st.ManualAddrs != 0 {
		t.Fatalf("после снятия: %d", st.ManualAddrs)
	}
}
