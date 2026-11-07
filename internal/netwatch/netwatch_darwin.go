package netwatch

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// tunnelPrefixes — интерфейсы, через которые работают VPN на macOS: utun —
// сетевые расширения и WireGuard, ipsec — IKEv2, ppp — L2TP, tun/tap — старые драйверы.
var tunnelPrefixes = []string{"utun", "ipsec", "ppp", "tun", "tap"}

// listen сообщает о каждом сообщении routing-сокета: появился или пропал
// интерфейс, адрес, маршрут.
func listen(ctx context.Context, changed chan<- struct{}) {
	fd, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		return // остаётся опрос раз в repoll
	}
	unix.SetNonblock(fd, true)
	f := os.NewFile(uintptr(fd), "route")
	go func() {
		<-ctx.Done()
		f.Close()
	}()
	buf := make([]byte, 64<<10)
	for {
		_, err := f.Read(buf)
		if err != nil && !errors.Is(err, unix.ENOBUFS) {
			return
		}
		select {
		case changed <- struct{}{}:
		default:
		}
	}
}

func isTunnel(ifi net.Interface) bool {
	if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagRunning == 0 {
		return false
	}
	return isTunnelName(ifi.Name)
}

// isTunnelName — имя виртуального интерфейса VPN: префикс и номер.
func isTunnelName(name string) bool {
	for _, p := range tunnelPrefixes {
		if rest, ok := strings.CutPrefix(name, p); ok && rest != "" && strings.Trim(rest, "0123456789") == "" {
			return true
		}
	}
	return false
}

// defaultIface — интерфейс маршрута IPv4 по умолчанию, не привязанного к
// интерфейсу (у привязанных RTF_IFSCOPE: они есть у каждого интерфейса).
func defaultIface() string {
	rib, err := route.FetchRIB(unix.AF_INET, route.RIBTypeRoute, 0)
	if err != nil {
		return ""
	}
	msgs, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return ""
	}
	for _, m := range msgs {
		rm, ok := m.(*route.RouteMessage)
		if !ok || rm.Flags&unix.RTF_UP == 0 || rm.Flags&unix.RTF_IFSCOPE != 0 || len(rm.Addrs) <= unix.RTAX_NETMASK {
			continue
		}
		dst, ok := rm.Addrs[unix.RTAX_DST].(*route.Inet4Addr)
		if !ok || dst.IP != [4]byte{} {
			continue
		}
		if mask, ok := rm.Addrs[unix.RTAX_NETMASK].(*route.Inet4Addr); ok && mask.IP != [4]byte{} {
			continue
		}
		if ifi, err := net.InterfaceByIndex(rm.Index); err == nil {
			return ifi.Name
		}
	}
	return ""
}

// Physical — физический интерфейс маршрута по умолчанию: тот, через который
// трафик пошёл бы без VPN. Когда VPN занял маршрут по умолчанию, у физического
// остаётся маршрут, привязанный к интерфейсу (RTF_IFSCOPE) — его и берём.
func Physical() (name string, index int, ok bool) {
	rib, err := route.FetchRIB(unix.AF_INET, route.RIBTypeRoute, 0)
	if err != nil {
		return "", 0, false
	}
	msgs, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return "", 0, false
	}
	var scoped *net.Interface
	for _, m := range msgs {
		rm, ok := m.(*route.RouteMessage)
		if !ok || rm.Flags&unix.RTF_UP == 0 || len(rm.Addrs) <= unix.RTAX_NETMASK {
			continue
		}
		dst, ok := rm.Addrs[unix.RTAX_DST].(*route.Inet4Addr)
		if !ok || dst.IP != [4]byte{} {
			continue
		}
		if mask, ok := rm.Addrs[unix.RTAX_NETMASK].(*route.Inet4Addr); ok && mask.IP != [4]byte{} {
			continue
		}
		ifi, err := net.InterfaceByIndex(rm.Index)
		if err != nil || isTunnelName(ifi.Name) {
			continue
		}
		if rm.Flags&unix.RTF_IFSCOPE == 0 {
			return ifi.Name, ifi.Index, true // маршрут по умолчанию и так физический
		}
		if scoped == nil {
			scoped = ifi
		}
	}
	if scoped != nil {
		return scoped.Name, scoped.Index, true
	}
	return "", 0, false
}
