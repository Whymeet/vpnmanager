package procs

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"unsafe"

	"golang.org/x/sys/windows"
)

var procGetExtendedTcpTable = windows.NewLazySystemDLL("iphlpapi.dll").NewProc("GetExtendedTcpTable")

// tcpTableOwnerPIDAll — TCP_TABLE_OWNER_PID_ALL: все соединения с номером
// процесса.
const tcpTableOwnerPIDAll = 5

// System — процессы и соединения живой системы.
type System struct{}

// Peers — соединения TCP всех процессов, у которых локальный адрес local. Таблица
// UDP Windows удалённых адресов не знает, поэтому сервер VPN на UDP (WireGuard)
// так не виден.
func (System) Peers(_ context.Context, local netip.Addr) ([]Conn, error) {
	local = local.Unmap()
	af := uint32(windows.AF_INET)
	if local.Is6() {
		af = windows.AF_INET6
	}
	conns, err := tcpConns(af)
	if err != nil {
		return nil, err
	}
	var peers []Conn
	for _, c := range conns {
		if c.Local.Addr() == local {
			peers = append(peers, c)
		}
	}
	return peers, nil
}

// tcpConns — исходящие соединения TCP семейства af.
func tcpConns(af uint32) ([]Conn, error) {
	buf, err := tcpTable(af)
	if err != nil {
		return nil, err
	}
	if af == windows.AF_INET6 {
		return ParseTCPTable6(buf), nil
	}
	return ParseTCPTable4(buf), nil
}

// tcpTable — таблица соединений TCP семейства af. Между вызовами соединений
// может стать больше — тогда буфер растёт и вызов повторяется.
func tcpTable(af uint32) ([]byte, error) {
	size := uint32(64 << 10)
	for range 5 {
		buf := make([]byte, size)
		r, _, _ := procGetExtendedTcpTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0,
			uintptr(af), tcpTableOwnerPIDAll, 0)
		switch err := windows.Errno(r); err {
		case 0:
			return buf, nil
		case windows.ERROR_INSUFFICIENT_BUFFER:
			size += 16 << 10
		default:
			return nil, fmt.Errorf("GetExtendedTcpTable: %w", err)
		}
	}
	return nil, fmt.Errorf("GetExtendedTcpTable: таблица всё время растёт")
}

// ProxyOwners — какие из процессов pids слушают TCP на одном из адресов at:
// так опознаётся клиент VPN в режиме системного прокси.
func (System) ProxyOwners(_ context.Context, at []netip.AddrPort, pids []int) ([]int, error) {
	if len(pids) == 0 || len(at) == 0 {
		return nil, nil
	}
	var owners []int
	for _, af := range []uint32{windows.AF_INET, windows.AF_INET6} {
		buf, err := tcpTable(af)
		if err != nil {
			return nil, err
		}
		for _, pid := range TCPListeners(buf, af == windows.AF_INET6, at) {
			if slices.Contains(pids, pid) && !slices.Contains(owners, pid) {
				owners = append(owners, pid)
			}
		}
	}
	return owners, nil
}

// TunnelOwners — какие из процессов pids могут держать туннель. Кто открыл
// адаптер Wintun, wireguard-nt или TAP, Windows без перебора дескрипторов ядра
// не скажет; но открыть его может только процесс с правами администратора —
// служба клиента VPN (SYSTEM) или сам клиент, запущенный с повышением. Обычная
// программа, в том числе защищённое приложение, так себе адрес не откроет.
func (System) TunnelOwners(_ context.Context, iface string, pids []int) ([]int, error) {
	if iface == "" {
		return nil, nil
	}
	var owners []int
	for _, pid := range pids {
		if elevated(pid) {
			owners = append(owners, pid)
		}
	}
	return owners, nil
}

// elevated — процесс работает с повышенными правами или от имени SYSTEM.
func elevated(pid int) bool {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)
	var tok windows.Token
	if windows.OpenProcessToken(h, windows.TOKEN_QUERY, &tok) != nil {
		return false
	}
	defer tok.Close()
	if tok.IsElevated() {
		return true
	}
	u, err := tok.GetTokenUser()
	return err == nil && u.User.Sid.IsWellKnown(windows.WinLocalSystemSid)
}
