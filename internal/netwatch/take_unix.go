//go:build unix

package netwatch

import (
	"net"
	"net/netip"
	"slices"
	"strings"

	"vpnlock/internal/core"
)

// Take снимает текущее состояние сети.
func Take() (core.Snapshot, error) { return take(listenerOf) }

// take — снимок сети; listener называет процесс, который слушает порт прокси.
func take(listener func(port uint16) string) (core.Snapshot, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return core.Snapshot{}, err
	}
	var snap core.Snapshot
	for _, ifi := range ifs {
		if !isTunnel(ifi) {
			continue
		}
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		var usable []netip.Addr
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(ipn.IP)
			if !ok {
				continue
			}
			// У системных utun (iCloud, Continuity) только link-local — это не VPN.
			if ip = ip.Unmap(); ip.IsLinkLocalUnicast() || ip.IsLoopback() {
				continue
			}
			usable = append(usable, ip)
		}
		if len(usable) == 0 {
			continue
		}
		slices.SortFunc(usable, netip.Addr.Compare)
		snap.Tunnels = append(snap.Tunnels, core.Tunnel{Name: ifi.Name, Index: ifi.Index, Addrs: usable})
	}
	slices.SortFunc(snap.Tunnels, func(a, b core.Tunnel) int { return strings.Compare(a.Name, b.Name) })
	snap.DefaultIface = defaultIface()
	snap.Proxies = proxies(listener)
	return snap, nil
}
