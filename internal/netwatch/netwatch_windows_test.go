package netwatch

import (
	"testing"

	"golang.org/x/sys/windows"
)

// Какие адаптеры Windows — туннели VPN: тип интерфейса, а у TAP — описание драйвера.
func TestTunnelKinds(t *testing.T) {
	for _, tc := range []struct {
		a    adapter
		want bool
	}{
		{adapter{ifType: ifTypePropVirtual, description: "Wintun Userspace Tunnel"}, true},
		{adapter{ifType: ifTypePropVirtual, description: "WireGuard Tunnel"}, true},
		{adapter{ifType: ifTypePropVirtual, description: "AmneziaWG Tunnel"}, true},
		{adapter{ifType: windows.IF_TYPE_PPP, description: "WAN Miniport (IKEv2)"}, true},
		{adapter{ifType: windows.IF_TYPE_ETHERNET_CSMACD, description: "TAP-Windows Adapter V9"}, true},
		{adapter{ifType: windows.IF_TYPE_ETHERNET_CSMACD, description: "Intel(R) Ethernet Connection I219-V"}, false},
		{adapter{ifType: windows.IF_TYPE_ETHERNET_CSMACD, description: "Hyper-V Virtual Ethernet Adapter"}, false},
		{adapter{ifType: windows.IF_TYPE_IEEE80211, description: "Intel(R) Wi-Fi 6 AX201 160MHz"}, false},
		{adapter{ifType: windows.IF_TYPE_TUNNEL, description: "Teredo Tunneling Pseudo-Interface"}, false},
		{adapter{ifType: windows.IF_TYPE_SOFTWARE_LOOPBACK, description: "Software Loopback Interface 1"}, false},
	} {
		if got := isTunnel(tc.a); got != tc.want {
			t.Errorf("%s (тип %d): туннель %v, ждали %v", tc.a.description, tc.a.ifType, got, tc.want)
		}
	}
}
