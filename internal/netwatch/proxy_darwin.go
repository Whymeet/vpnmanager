package netwatch

import (
	"bufio"
	"bytes"
	"net/netip"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"time"

	"vpnlock/internal/core"
)

// proxyPoll — как часто наблюдатель перечитывает системный прокси. О смене
// прокси routing-сокет не сообщает, а уведомления configd без cgo не
// получить, поэтому — опрос `scutil --proxy` (несколько миллисекунд).
const proxyPoll = 2 * time.Second

// proxies — системный прокси сейчас: по одному на адрес с портом. listener
// называет процесс, который слушает порт.
func proxies(listener func(port uint16) string) []core.Proxy {
	out, err := exec.Command("/usr/sbin/scutil", "--proxy").Output()
	if err != nil {
		return nil
	}
	list := parseProxies(out, resolveHost)
	for i := range list {
		list[i].Process = listener(list[i].Port)
	}
	return list
}

// parseProxies разбирает вывод `scutil --proxy`: верхний уровень словаря —
// прокси основной службы сети. HTTP- и HTTPS-прокси системы — это один и тот
// же HTTP-прокси (HTTPS идёт через CONNECT); если тот же порт объявлен и как
// SOCKS, он один, и с ним говорим по HTTP. Автонастройка (PAC) не разбирается.
func parseProxies(out []byte, resolve func(host string) []netip.Addr) []core.Proxy {
	top := map[string]string{}
	depth := 0
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if depth == 1 {
			if k, v, ok := strings.Cut(line, " : "); ok {
				top[k] = v
			}
		}
		depth += strings.Count(line, "{") - strings.Count(line, "}")
	}
	var list []core.Proxy
	for _, kind := range []struct{ key, scheme string }{{"HTTP", "http"}, {"HTTPS", "http"}, {"SOCKS", "socks5"}} {
		if top[kind.key+"Enable"] != "1" {
			continue
		}
		host := strings.Trim(top[kind.key+"Proxy"], "[]")
		port, err := strconv.ParseUint(top[kind.key+"Port"], 10, 16)
		if host == "" || err != nil || port == 0 {
			continue
		}
		if slices.ContainsFunc(list, func(p core.Proxy) bool { return p.Host == host && p.Port == uint16(port) }) {
			continue
		}
		list = append(list, core.Proxy{Scheme: kind.scheme, Host: host, Port: uint16(port), Addrs: resolve(host)})
	}
	return list
}

// listenerOf — имя процесса, который слушает TCP-порт port; пусто — никто или
// не узнать. От root lsof видит процессы всех пользователей.
func listenerOf(port uint16) string {
	out, err := exec.Command("/usr/sbin/lsof", "-nP", "-iTCP:"+strconv.Itoa(int(port)), "-sTCP:LISTEN", "-Fc").Output()
	if err != nil {
		return ""
	}
	for line := range strings.SplitSeq(string(out), "\n") {
		if name, ok := strings.CutPrefix(line, "c"); ok && name != "" {
			return name
		}
	}
	return ""
}
