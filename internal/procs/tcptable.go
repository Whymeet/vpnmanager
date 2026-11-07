package procs

import (
	"encoding/binary"
	"net/netip"
	"slices"
)

// Разбор таблиц соединений Windows (GetExtendedTcpTable, TCP_TABLE_OWNER_PID_ALL)
// — без Windows: раскладка проверяется тестами на любой системе.
//
//	MIB_TCPTABLE_OWNER_PID:  DWORD dwNumEntries; MIB_TCPROW_OWNER_PID  table[]
//	MIB_TCPROW_OWNER_PID:    dwState, dwLocalAddr, dwLocalPort, dwRemoteAddr,
//	                         dwRemotePort, dwOwningPid — 24 байта
//	MIB_TCP6TABLE_OWNER_PID: DWORD dwNumEntries; MIB_TCP6ROW_OWNER_PID table[]
//	MIB_TCP6ROW_OWNER_PID:   ucLocalAddr[16], dwLocalScopeId, dwLocalPort,
//	                         ucRemoteAddr[16], dwRemoteScopeId, dwRemotePort,
//	                         dwState, dwOwningPid — 56 байт
//
// Адреса и порты — в сетевом порядке байт (у порта — младшие 16 бит DWORD),
// остальное — DWORD в порядке байт машины (x64 и ARM64 — little-endian).

const (
	tcpRow4Size = 24
	tcpRow6Size = 56
)

// tcpStates — имена состояний MIB_TCP_STATE, как их пишет lsof.
var tcpStates = map[uint32]string{
	1: "CLOSED", 2: "LISTEN", 3: "SYN_SENT", 4: "SYN_RCVD", 5: "ESTABLISHED", 6: "FIN_WAIT_1",
	7: "FIN_WAIT_2", 8: "CLOSE_WAIT", 9: "CLOSING", 10: "LAST_ACK", 11: "TIME_WAIT", 12: "DELETE_TCB",
}

// ParseTCPTable4 разбирает MIB_TCPTABLE_OWNER_PID: исходящие соединения.
func ParseTCPTable4(buf []byte) []Conn { return outgoing(tcpAll4(buf)) }

// ParseTCPTable6 разбирает MIB_TCP6TABLE_OWNER_PID: исходящие соединения.
func ParseTCPTable6(buf []byte) []Conn { return outgoing(tcpAll6(buf)) }

// TCPListeners — процессы, которые по таблице buf (семейство v6) слушают один
// из адресов at.
func TCPListeners(buf []byte, v6 bool, at []netip.AddrPort) []int {
	all := tcpAll4(buf)
	if v6 {
		all = tcpAll6(buf)
	}
	var pids []int
	for _, c := range all {
		if c.State == "LISTEN" && ListensOn(c.Local, at) && !slices.Contains(pids, c.PID) {
			pids = append(pids, c.PID)
		}
	}
	return pids
}

// tcpAll4 — все строки MIB_TCPTABLE_OWNER_PID, со слушающими.
func tcpAll4(buf []byte) []Conn {
	var all []Conn
	for _, row := range tcpRows(buf, tcpRow4Size) {
		all = append(all, Conn{
			PID:    int(binary.LittleEndian.Uint32(row[20:])),
			Proto:  "tcp",
			Local:  netip.AddrPortFrom(netip.AddrFrom4([4]byte(row[4:8])), netPort(row[8:])),
			Remote: netip.AddrPortFrom(netip.AddrFrom4([4]byte(row[12:16])), netPort(row[16:])),
			State:  tcpStates[binary.LittleEndian.Uint32(row[0:])],
		})
	}
	return all
}

// tcpAll6 — все строки MIB_TCP6TABLE_OWNER_PID, со слушающими.
func tcpAll6(buf []byte) []Conn {
	var all []Conn
	for _, row := range tcpRows(buf, tcpRow6Size) {
		all = append(all, Conn{
			PID:    int(binary.LittleEndian.Uint32(row[52:])),
			Proto:  "tcp",
			Local:  netip.AddrPortFrom(netip.AddrFrom16([16]byte(row[0:16])), netPort(row[20:])),
			Remote: netip.AddrPortFrom(netip.AddrFrom16([16]byte(row[24:40])), netPort(row[44:])),
			State:  tcpStates[binary.LittleEndian.Uint32(row[48:])],
		})
	}
	return all
}

// outgoing — исходящие соединения из строк таблицы: с удалённым концом и не на
// порт, который тот же процесс слушает, — иначе это входящее соединение к
// самому приложению, а не к его сервису.
func outgoing(all []Conn) []Conn {
	listening := map[int]map[uint16]bool{}
	for _, c := range all {
		if c.State == "LISTEN" {
			if listening[c.PID] == nil {
				listening[c.PID] = map[uint16]bool{}
			}
			listening[c.PID][c.Local.Port()] = true
		}
	}
	var out []Conn
	for _, c := range all {
		if c.State != "LISTEN" && !c.Remote.Addr().IsUnspecified() && !listening[c.PID][c.Local.Port()] {
			out = append(out, c)
		}
	}
	return out
}

// tcpRows — строки таблицы по size байт. Число строк из заголовка не больше,
// чем помещается в буфере.
func tcpRows(buf []byte, size int) [][]byte {
	if len(buf) < 4 {
		return nil
	}
	n := min(int(binary.LittleEndian.Uint32(buf)), (len(buf)-4)/size)
	rows := make([][]byte, 0, n)
	for i := range n {
		rows = append(rows, buf[4+i*size:4+(i+1)*size])
	}
	return rows
}

// netPort — порт из DWORD в сетевом порядке байт: первые два байта.
func netPort(b []byte) uint16 { return binary.BigEndian.Uint16(b[:2]) }
