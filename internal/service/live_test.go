//go:build live && darwin

// Живая проверка: служба с настоящими наблюдателем и проверкой выхода, но во
// временном каталоге и от обычного пользователя. tools/go test -tags live -v ./internal/service

package service_test

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"appguard/internal/core"
	"appguard/internal/exitcheck"
	"appguard/internal/ipc"
	"appguard/internal/netwatch"
	"appguard/internal/paths"
	"appguard/internal/service"
	"appguard/internal/service/servicetest"
)

func TestLiveServiceVerifiesCurrentVPN(t *testing.T) {
	snap, err := netwatch.Take()
	if err != nil || len(snap.Tunnels) == 0 {
		t.Skip("VPN не подключён")
	}
	L := paths.Under(t.TempDir())
	L.Socket = servicetest.Socket(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	start := time.Now()
	// Настоящие — наблюдатель и проверка выхода; всё, что меняет систему, —
	// подделки, а зонда «Россия напрямую» нет: без физического интерфейса он
	// не идёт.
	enf := &servicetest.Enforcer{}
	go service.Run(ctx, service.Deps{
		Layout: L, Version: "live", Accounts: &servicetest.Accounts{}, Installation: &servicetest.Installation{},
		Network: netwatch.Observer{}, Fetch: exitcheck.Bound{Timeout: 3 * time.Second},
		Enforce: enf, Reach: enf.Reach, SystemDNS: &servicetest.SystemDNS{}, Apps: &servicetest.Scanner{},
		DNSAddr: "127.0.0.1:0", ScanEvery: time.Second, LearnFor: time.Minute, RemindEvery: time.Hour,
		PhysicalAddr: func() (netip.Addr, bool) { return netip.Addr{}, false },
		Physical:     func() (core.Tunnel, bool) { return core.Tunnel{}, false },
		CheckEvery:   4 * time.Second, ProbeEvery: time.Minute, GuardEvery: time.Second, Now: time.Now, Logf: t.Logf,
	})
	for {
		resp, err := ipc.Call(L.Socket, ipc.Request{Cmd: ipc.CmdStatus})
		if err == nil && len(resp.Status.Paths) > 0 && resp.Status.Paths[0].State != "pending" {
			for _, p := range resp.Status.Paths {
				t.Logf("через %v после старта: %s — %s (маршрут по умолчанию: %v)", time.Since(start).Round(time.Millisecond), p.Iface, p.Summary, p.Default)
			}
			if d := time.Since(start); d > 2*time.Second {
				t.Fatalf("выход проверен за %v, а должен за 2 секунды", d)
			}
			return
		}
		if time.Since(start) > 10*time.Second {
			t.Fatalf("за 10 секунд выход не проверен: %v %+v", err, resp)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
