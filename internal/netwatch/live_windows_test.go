//go:build live

// Живые проверки на стенде Windows: go test -tags live -v ./internal/netwatch
// (из PowerShell, Go клона — .toolchain\go\bin\go.exe).

package netwatch

import (
	"context"
	"testing"
	"time"
)

func TestLiveSnapshot(t *testing.T) {
	list, err := adapters()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range list {
		t.Logf("адаптер %q (%s): тип %d, index %d, работает %v, шлюз %v, метрика %d, адреса %v, туннель %v",
			a.name, a.description, a.ifType, a.index, a.up, a.gateway, a.metric, a.addrs, isTunnel(a))
	}
	snap, err := Take()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("маршрут по умолчанию: %q", snap.DefaultIface)
	name, index, ok := Physical()
	t.Logf("физический адаптер: %q (index %d, %v)", name, index, ok)
	if !ok {
		t.Fatal("физический адаптер не найден")
	}
	for _, tun := range snap.Tunnels {
		t.Logf("туннель %s (index %d): %v", tun.Name, tun.Index, tun.Addrs)
		if tun.Name == name {
			t.Errorf("%s — и туннель, и физический адаптер", name)
		}
	}
	if len(snap.Tunnels) == 0 && snap.DefaultIface != name {
		t.Errorf("без VPN маршрут по умолчанию через %q, а физический адаптер — %q", snap.DefaultIface, name)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if first, ok := <-(Observer{}).Watch(ctx); !ok || !equal(first, snap) {
		t.Fatalf("Watch начал не с текущего снимка: %+v", first)
	}
}
