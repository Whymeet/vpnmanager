package bind

import (
	"encoding/binary"
	"fmt"
	"syscall"

	"golang.org/x/sys/windows"
)

// IP_UNICAST_IF и IPV6_UNICAST_IF из ws2ipdef.h — то же, что IP_BOUND_IF на
// macOS: соединение уходит только через заданный интерфейс.
const (
	ipUnicastIf   = 31
	ipv6UnicastIf = 31
)

// Control — для net.Dialer.Control: сокет уходит только через интерфейс index.
func Control(index int) func(network, address string, c syscall.RawConn) error {
	return func(network, _ string, c syscall.RawConn) error {
		var serr error
		err := c.Control(func(fd uintptr) {
			switch network {
			case "tcp4", "udp4":
				// Для IPv4 Windows ждёт номер интерфейса в сетевом порядке байт.
				var b [4]byte
				binary.BigEndian.PutUint32(b[:], uint32(index))
				serr = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, ipUnicastIf, int(binary.NativeEndian.Uint32(b[:])))
			case "tcp6", "udp6":
				serr = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IPV6, ipv6UnicastIf, index)
			default:
				serr = fmt.Errorf("неожиданная сеть %s", network)
			}
		})
		if err != nil {
			return err
		}
		return serr
	}
}
