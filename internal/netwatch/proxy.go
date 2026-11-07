package netwatch

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"vpnlock/internal/core"
)

// resolveHost — адреса узла прокси: на них файрвол закрывает порт. Обычно это
// 127.0.0.1; localhost — оба адреса петли.
func resolveHost(host string) []netip.Addr {
	if a, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{a.Unmap().WithZone("")}
	}
	if strings.EqualFold(host, "localhost") {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.IPv6Loopback()}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil // имя не разрешается — программы до прокси не доберутся тоже
	}
	for i, a := range addrs {
		addrs[i] = a.Unmap().WithZone("")
	}
	slices.SortFunc(addrs, netip.Addr.Compare)
	return slices.Compact(addrs)
}

// parseWinProxy разбирает ProxyServer из настроек WinINET: «адрес:порт» —
// один прокси для всего, «http=…;https=…;socks=…» — по протоколам. HTTP и
// HTTPS — один HTTP-прокси (HTTPS идёт через CONNECT); SOCKS говорит на
// SOCKS5. Если один порт объявлен и как HTTP, и как SOCKS, он один, и с ним
// говорим по HTTP — так же, как на macOS.
func parseWinProxy(server string, resolve func(host string) []netip.Addr) []core.Proxy {
	byEndpoint := map[string]core.Proxy{}
	var order []string
	for _, entry := range strings.Split(server, ";") {
		entry = strings.TrimSpace(entry)
		scheme := "http"
		if proto, rest, ok := strings.Cut(entry, "="); ok {
			switch strings.ToLower(strings.TrimSpace(proto)) {
			case "http", "https":
			case "socks":
				scheme = "socks5"
			default:
				continue // ftp и прочее
			}
			entry = strings.TrimSpace(rest)
		}
		if i := strings.Index(entry, "://"); i >= 0 {
			entry = entry[i+3:]
		}
		host, portText, err := net.SplitHostPort(entry)
		if err != nil || host == "" {
			continue
		}
		port, err := strconv.ParseUint(portText, 10, 16)
		if err != nil || port == 0 {
			continue
		}
		key := net.JoinHostPort(strings.ToLower(host), portText)
		if cur, ok := byEndpoint[key]; ok {
			if cur.Scheme != "http" && scheme == "http" {
				cur.Scheme = "http"
				byEndpoint[key] = cur
			}
			continue
		}
		byEndpoint[key] = core.Proxy{Scheme: scheme, Host: host, Port: uint16(port), Addrs: resolve(host)}
		order = append(order, key)
	}
	var out []core.Proxy
	for _, k := range order {
		out = append(out, byEndpoint[k])
	}
	return out
}
