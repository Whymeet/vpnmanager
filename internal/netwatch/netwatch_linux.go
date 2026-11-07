package netwatch

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// sysNet — где ядро показывает сетевые интерфейсы.
const sysNet = "/sys/class/net"

// Типы интерфейсов из <linux/if_arp.h>: без канального уровня (WireGuard,
// AmneziaWG, xfrm) и PPP (L2TP, PPTP).
const (
	arphrdNone = "65534"
	arphrdPPP  = "512"
)

// rtnlGroups — о чём ядро сообщает: интерфейсы, адреса, маршруты и правила
// маршрутизации (последние ставит wg-quick).
const rtnlGroups = unix.RTMGRP_LINK | unix.RTMGRP_IPV4_IFADDR | unix.RTMGRP_IPV6_IFADDR |
	unix.RTMGRP_IPV4_ROUTE | unix.RTMGRP_IPV6_ROUTE | unix.RTMGRP_IPV4_RULE

// listen сообщает о каждом сообщении rtnetlink: появился или пропал интерфейс,
// адрес, маршрут.
func listen(ctx context.Context, changed chan<- struct{}) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.NETLINK_ROUTE)
	if err != nil {
		return // остаётся опрос раз в repoll
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: rtnlGroups}); err != nil {
		unix.Close(fd)
		return
	}
	f := os.NewFile(uintptr(fd), "rtnetlink")
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
	return tunnelIface(sysNet, ifi.Name)
}

// tunnelIface — интерфейс name из каталога sys — туннель VPN. Имена на Linux
// выбирает сам клиент (wg0, nordlynx, proton0, amn0, sing-box и другие), поэтому
// смотрим на устройство: TUN/TAP, интерфейс без канального уровня или PPP. Порт
// моста — сетевая карта виртуалки или контейнера, а не VPN.
func tunnelIface(sys, name string) bool {
	dir := filepath.Join(sys, name)
	if _, err := os.Stat(filepath.Join(dir, "brport")); err == nil {
		return false
	}
	if _, err := os.Stat(filepath.Join(dir, "tun_flags")); err == nil {
		return true
	}
	data, err := os.ReadFile(filepath.Join(dir, "type"))
	if err != nil {
		return false
	}
	t := strings.TrimSpace(string(data))
	return t == arphrdNone || t == arphrdPPP
}

// defaultIface — интерфейс, через который ядро отправило бы пакет в интернет.
// Вопрос задаётся ядру, а не таблице main: wg-quick уводит маршрут по умолчанию
// в свою таблицу и правило. Подключение UDP пакетов не шлёт; 192.0.2.1 —
// документационный адрес, маршрут до него — маршрут по умолчанию.
func defaultIface() string {
	c, err := net.Dial("udp4", "192.0.2.1:9")
	if err != nil {
		return ""
	}
	defer c.Close()
	local, ok := c.LocalAddr().(*net.UDPAddr)
	if !ok {
		return ""
	}
	ifs, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, ifi := range ifs {
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.Equal(local.IP) {
				return ifi.Name
			}
		}
	}
	return ""
}

// route — строка /proc/net/route.
type route struct {
	iface   string
	dflt    bool // маршрут по умолчанию
	gateway bool // через шлюз
	metric  int
}

// parseRoutes разбирает /proc/net/route: Iface Destination Gateway Flags RefCnt
// Use Metric Mask… — адреса в шестнадцатеричном виде.
func parseRoutes(data []byte) []route {
	var out []route
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 8 || f[0] == "Iface" {
			continue
		}
		flags, err1 := strconv.ParseUint(f[3], 16, 32)
		metric, err2 := strconv.Atoi(f[6])
		if err1 != nil || err2 != nil || flags&unix.RTF_UP == 0 {
			continue
		}
		out = append(out, route{iface: f[0], dflt: isZero(f[1]) && isZero(f[7]), gateway: flags&unix.RTF_GATEWAY != 0, metric: metric})
	}
	return out
}

func isZero(hexAddr string) bool {
	b, err := hex.DecodeString(hexAddr)
	return err == nil && !slices.ContainsFunc(b, func(x byte) bool { return x != 0 })
}

// pickPhysical — интерфейс, через который трафик пошёл бы без VPN: маршрут по
// умолчанию мимо туннелей с наименьшей метрикой. Если VPN заменил маршрут по
// умолчанию, у физического остался маршрут через шлюз до сервера VPN.
func pickPhysical(routes []route, tunnel func(string) bool) (string, bool) {
	var found []route
	for _, r := range routes {
		if r.gateway && !tunnel(r.iface) || r.dflt && !tunnel(r.iface) {
			found = append(found, r)
		}
	}
	if len(found) == 0 {
		return "", false
	}
	slices.SortStableFunc(found, func(a, b route) int {
		if a.dflt != b.dflt {
			if a.dflt {
				return -1
			}
			return 1
		}
		return cmp.Compare(a.metric, b.metric)
	})
	return found[0].iface, true
}

// Physical — физический интерфейс: тот, через который трафик пошёл бы без VPN.
func Physical() (name string, index int, ok bool) {
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return "", 0, false
	}
	name, ok = pickPhysical(parseRoutes(data), func(n string) bool { return tunnelIface(sysNet, n) })
	if !ok {
		return "", 0, false
	}
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return "", 0, false
	}
	return ifi.Name, ifi.Index, true
}
