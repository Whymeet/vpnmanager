package netwatch

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTunnelIfaceBySysfs(t *testing.T) {
	sys := t.TempDir()
	dev := func(name string, files map[string]string) {
		dir := filepath.Join(sys, name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		for f, v := range files {
			if err := os.WriteFile(filepath.Join(dir, f), []byte(v), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	dev("eth0", map[string]string{"type": "1\n"})
	dev("wg0", map[string]string{"type": "65534\n"})
	dev("nordlynx", map[string]string{"type": "65534\n"})
	dev("tun0", map[string]string{"type": "65534\n", "tun_flags": "0x1001\n"})
	dev("tap0", map[string]string{"type": "1\n", "tun_flags": "0x1002\n"})
	dev("ppp0", map[string]string{"type": "512\n"})
	dev("vnet3", map[string]string{"type": "1\n", "tun_flags": "0x1002\n", "brport": ""})
	dev("vpnlock0", map[string]string{"type": "1\n"})
	for name, want := range map[string]bool{"eth0": false, "wg0": true, "nordlynx": true, "tun0": true, "tap0": true,
		"ppp0": true, "vnet3": false, "vpnlock0": false, "gone0": false} {
		if got := tunnelIface(sys, name); got != want {
			t.Errorf("tunnelIface(%s) = %v, а нужно %v", name, got, want)
		}
	}
}

func TestPickPhysical(t *testing.T) {
	const table = `Iface	Destination	Gateway	Flags	RefCnt	Use	Metric	Mask	MTU	Window	IRTT
wlan0	00000000	0101A8C0	0003	0	0	600	00000000	0	0	0
eth0	00000000	0101A8C0	0003	0	0	100	00000000	0	0	0
wlan0	0001A8C0	00000000	0001	0	0	600	00FFFFFF	0	0	0
`
	tun := func(n string) bool { return n == "tun0" || n == "wg0" }
	if name, ok := pickPhysical(parseRoutes([]byte(table)), tun); !ok || name != "eth0" {
		t.Errorf("нужен маршрут по умолчанию с наименьшей метрикой: %q %v", name, ok)
	}
	// OpenVPN с def1: 0/1 и 128/1 через туннель, физический маршрут по умолчанию на месте.
	const def1 = `Iface	Destination	Gateway	Flags	RefCnt	Use	Metric	Mask	MTU	Window	IRTT
tun0	00000000	0100080A	0003	0	0	0	00000080	0	0	0
tun0	00000080	0100080A	0003	0	0	0	00000080	0	0	0
eth0	00000000	0101A8C0	0003	0	0	100	00000000	0	0	0
`
	if name, ok := pickPhysical(parseRoutes([]byte(def1)), tun); !ok || name != "eth0" {
		t.Errorf("def1: %q %v", name, ok)
	}
	// VPN заменил маршрут по умолчанию: остался маршрут к серверу через шлюз.
	const replaced = `Iface	Destination	Gateway	Flags	RefCnt	Use	Metric	Mask	MTU	Window	IRTT
tun0	00000000	00000000	0001	0	0	0	00000000	0	0	0
eth0	050403CB	0101A8C0	0007	0	0	0	FFFFFFFF	0	0	0
`
	if name, ok := pickPhysical(parseRoutes([]byte(replaced)), tun); !ok || name != "eth0" {
		t.Errorf("маршрут к серверу: %q %v", name, ok)
	}
	if _, ok := pickPhysical(parseRoutes([]byte("Iface\n")), tun); ok {
		t.Error("без маршрутов физического интерфейса нет")
	}
}
