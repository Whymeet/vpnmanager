package netwatch

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"appguard/internal/core"
)

// proxyPoll — как часто наблюдатель перечитывает системный прокси: о его смене
// IP Helper не сообщает. Тот же снимок страхует от потерянного уведомления.
const proxyPoll = 2 * time.Second

// Типы интерфейсов (ipifcons.h). Адаптеры VPN: Wintun (WireGuard, AmneziaWG,
// sing-box, Clash), wireguard-nt и OpenVPN DCO — PROP_VIRTUAL; встроенные VPN
// Windows (IKEv2, L2TP, SSTP) — PPP. Петля, Teredo и прочие туннели IPv6
// (IF_TYPE_TUNNEL) — не VPN.
const (
	ifTypePPP         = windows.IF_TYPE_PPP
	ifTypePropVirtual = 53
)

// tapDrivers — адаптеры TAP-Windows (OpenVPN и клиенты на нём) выглядят как
// Ethernet и узнаются по описанию драйвера.
var tapDrivers = []string{"tap-windows", "tap-win32"}

// adapter — сетевой адаптер так, как его видит IP Helper.
type adapter struct {
	name        string // как в «Сетевых подключениях»: «Ethernet», «AmneziaVPN»
	description string // описание драйвера
	index       int
	ifType      uint32
	up          bool
	addrs       []netip.Addr // кроме link-local и петли
	gateway     bool         // есть шлюз IPv4: через адаптер можно в интернет
	metric      uint32       // метрика IPv4 интерфейса
}

func isTunnel(a adapter) bool {
	switch a.ifType {
	case ifTypePPP, ifTypePropVirtual:
		return true
	}
	d := strings.ToLower(a.description)
	return slices.ContainsFunc(tapDrivers, func(t string) bool { return strings.Contains(d, t) })
}

// Take снимает текущее состояние сети.
func Take() (core.Snapshot, error) { return take(listenerOf) }

// take — снимок сети; listener называет процесс, который слушает порт прокси.
func take(listener func(port uint16) string) (core.Snapshot, error) {
	list, err := adapters()
	if err != nil {
		return core.Snapshot{}, err
	}
	var snap core.Snapshot
	for _, a := range list {
		if a.up && isTunnel(a) && len(a.addrs) > 0 {
			snap.Tunnels = append(snap.Tunnels, core.Tunnel{Name: a.name, Index: a.index, Addrs: a.addrs})
		}
	}
	slices.SortFunc(snap.Tunnels, func(a, b core.Tunnel) int { return strings.Compare(a.Name, b.Name) })
	snap.DefaultIface = defaultIface(list)
	snap.Proxies = proxies(listener)
	return snap, nil
}

// probeDst — адрес из TEST-NET-1: особых маршрутов к нему ни у кого нет, и
// лучший маршрут до него — тот, по которому идёт весь трафик в интернет.
var probeDst = &windows.SockaddrInet4{Addr: [4]byte{192, 0, 2, 1}}

// defaultIface — адаптер, через который идёт трафик в интернет. Лучший маршрут
// до адреса учитывает и маршрут 0.0.0.0/0, и пару 0.0.0.0/1 + 128.0.0.0/1,
// которой многие клиенты VPN его перекрывают.
func defaultIface(list []adapter) string {
	var index uint32
	if windows.GetBestInterfaceEx(probeDst, &index) != nil {
		return ""
	}
	for _, a := range list {
		if a.index == int(index) {
			return a.name
		}
	}
	return ""
}

// Physical — физический адаптер, через который трафик пошёл бы без VPN: из
// работающих адаптеров со шлюзом IPv4, кроме туннелей, — с наименьшей
// метрикой; по ней Windows и выбирает маршрут по умолчанию.
func Physical() (name string, index int, ok bool) {
	list, err := adapters()
	if err != nil {
		return "", 0, false
	}
	var best *adapter
	for i := range list {
		a := &list[i]
		if !a.up || !a.gateway || isTunnel(*a) || a.ifType == windows.IF_TYPE_SOFTWARE_LOOPBACK {
			continue
		}
		if best == nil || a.metric < best.metric {
			best = a
		}
	}
	if best == nil {
		return "", 0, false
	}
	return best.name, best.index, true
}

// adapters — сетевые адаптеры системы с адресами и шлюзами.
func adapters() ([]adapter, error) {
	const flags = windows.GAA_FLAG_SKIP_ANYCAST | windows.GAA_FLAG_SKIP_MULTICAST |
		windows.GAA_FLAG_SKIP_DNS_SERVER | windows.GAA_FLAG_INCLUDE_GATEWAYS
	size := uint32(16 << 10)
	for {
		buf := make([]byte, size)
		first := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, flags, 0, first, &size)
		switch {
		case errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) && size > uint32(len(buf)):
			continue // адаптеров стало больше, чем помещалось
		case errors.Is(err, windows.ERROR_NO_DATA):
			return nil, nil
		case err != nil:
			return nil, err
		}
		var list []adapter
		for a := first; a != nil; a = a.Next {
			list = append(list, read(a))
		}
		return list, nil
	}
}

func read(a *windows.IpAdapterAddresses) adapter {
	ad := adapter{
		name:        windows.UTF16PtrToString(a.FriendlyName),
		description: windows.UTF16PtrToString(a.Description),
		index:       int(a.IfIndex),
		ifType:      a.IfType,
		up:          a.OperStatus == windows.IfOperStatusUp,
		metric:      a.Ipv4Metric,
	}
	if ad.index == 0 {
		ad.index = int(a.Ipv6IfIndex) // адаптер только с IPv6 — так же номер выбирает net.Interfaces
	}
	for u := a.FirstUnicastAddress; u != nil; u = u.Next {
		ip, ok := netip.AddrFromSlice(u.Address.IP())
		if !ok {
			continue
		}
		if ip = ip.Unmap(); ip.IsLinkLocalUnicast() || ip.IsLoopback() {
			continue
		}
		ad.addrs = append(ad.addrs, ip)
	}
	slices.SortFunc(ad.addrs, netip.Addr.Compare)
	for g := a.FirstGatewayAddress; g != nil; g = g.Next {
		if ip := g.Address.IP(); ip != nil && ip.To4() != nil {
			ad.gateway = true
		}
	}
	return ad
}

// proxies — системный прокси того, кто сидит за экраном: по одному на адрес с
// портом. Автонастройка (PAC) не разбирается.
func proxies(listener func(port uint16) string) []core.Proxy {
	server, ok := userProxy()
	if !ok {
		return nil
	}
	list := parseWinProxy(server, resolveHost)
	for i := range list {
		list[i].Process = listener(list[i].Port)
	}
	return list
}

// internetSettings — где WinINET держит системный прокси пользователя.
const internetSettings = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`

// userProxy — ProxyServer из настроек пользователя, если прокси включён.
// Служба работает от имени системы и находит пользователя по сеансу консоли;
// не из службы (живые тесты) читается свой раздел.
func userProxy() (string, bool) {
	root, path := registry.CURRENT_USER, internetSettings
	if sid, ok := consoleUserSID(); ok {
		root, path = registry.USERS, sid+`\`+internetSettings
	}
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE)
	if err != nil {
		return "", false
	}
	defer k.Close()
	if on, _, err := k.GetIntegerValue("ProxyEnable"); err != nil || on == 0 {
		return "", false
	}
	server, _, err := k.GetStringValue("ProxyServer")
	return server, err == nil && server != ""
}

// consoleUserSID — SID того, кто вошёл в систему за экраном. Маркер его сеанса
// отдают только службе; никто не вошёл — false.
func consoleUserSID() (string, bool) {
	session := windows.WTSGetActiveConsoleSessionId()
	if session == 0xffffffff {
		return "", false
	}
	var tok windows.Token
	if err := windows.WTSQueryUserToken(session, &tok); err != nil {
		return "", false
	}
	defer tok.Close()
	u, err := tok.GetTokenUser()
	if err != nil {
		return "", false
	}
	return u.User.Sid.String(), true
}

// listenerOf — кто слушает порт прокси; на Windows пока не узнаётся, и в
// статусе прокси без имени программы.
func listenerOf(uint16) string { return "" }

// Уведомления IP Helper приходят в поток системы: обратный вызов один на
// процесс (их число ограничено), он будит всех, кто сейчас слушает.
var (
	waitersMu sync.Mutex
	waiters   = map[chan<- struct{}]bool{}
	onChange  = windows.NewCallback(func(_, _, _ uintptr) uintptr {
		waitersMu.Lock()
		defer waitersMu.Unlock()
		for ch := range waiters {
			select {
			case ch <- struct{}{}:
			default:
			}
		}
		return 0
	})
)

// listen сообщает о каждой перемене, о которой говорит IP Helper: интерфейс
// поднялся или упал, появился или пропал адрес, маршрут.
func listen(ctx context.Context, changed chan<- struct{}) {
	waitersMu.Lock()
	waiters[changed] = true
	waitersMu.Unlock()
	defer func() {
		waitersMu.Lock()
		delete(waiters, changed)
		waitersMu.Unlock()
	}()
	var handles []windows.Handle
	for _, notify := range []func(uint16, uintptr, unsafe.Pointer, bool, *windows.Handle) error{
		windows.NotifyIpInterfaceChange,
		windows.NotifyUnicastIpAddressChange,
		windows.NotifyRouteChange2,
	} {
		var h windows.Handle
		if notify(windows.AF_UNSPEC, onChange, nil, false, &h) == nil {
			handles = append(handles, h)
		}
	}
	// Без уведомлений остаётся опрос раз в proxyPoll.
	<-ctx.Done()
	for _, h := range handles {
		windows.CancelMibChangeNotify2(h)
	}
}
