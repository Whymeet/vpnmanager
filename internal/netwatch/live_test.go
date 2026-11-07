//go:build live && darwin

// Живые проверки на этой машине: tools/go test -tags live -v ./internal/netwatch

package netwatch

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestLiveSnapshot(t *testing.T) {
	snap, err := Take()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("маршрут по умолчанию: %q", snap.DefaultIface)
	name, index, ok := Physical()
	t.Logf("физический интерфейс: %q (index %d, %v)", name, index, ok)
	if !ok || isTunnelName(name) {
		t.Fatalf("физический интерфейс не найден: %q", name)
	}
	for _, tun := range snap.Tunnels {
		t.Logf("туннель %s (index %d): %v", tun.Name, tun.Index, tun.Addrs)
	}
	for _, px := range snap.Proxies {
		t.Logf("системный прокси %s (%s, адреса %v), порт слушает %q", px.Endpoint(), px.Scheme, px.Addrs, px.Process)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if first, ok := <-(Observer{}).Watch(ctx); !ok || !equal(first, snap) {
		t.Fatalf("Watch начал не с текущего снимка: %+v", first)
	}
}

// Routing-сокет действительно сообщает о переменах: пакет на незанятый адрес
// локальной сети заставляет ядро завести ARP-запись, и об этом приходит сообщение.
func TestLiveRouteSocketReportsChanges(t *testing.T) {
	en0, err := net.InterfaceByName("en0")
	if err != nil {
		t.Skip("нет en0")
	}
	addrs, _ := en0.Addrs()
	var target net.IP
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
			target = ipn.IP.Mask(ipn.Mask).To4()
			target[3] = 251
		}
	}
	if target == nil {
		t.Skip("у en0 нет IPv4")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	changed := make(chan struct{}, 1)
	go listen(ctx, changed)
	time.Sleep(100 * time.Millisecond)

	conn, err := net.Dial("udp4", net.JoinHostPort(target.String(), "9"))
	if err != nil {
		t.Fatal(err)
	}
	conn.Write([]byte{0})
	conn.Close()
	select {
	case <-changed:
		t.Logf("сообщение routing-сокета пришло после пакета на %s", target)
	case <-ctx.Done():
		t.Fatal("routing-сокет молчит")
	}
}
