//go:build live

// Живые проверки на этой машине: tools/go test -tags live -v ./internal/exitcheck

package exitcheck

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"runtime"
	"testing"
	"time"

	"appguard/internal/core"
	"appguard/internal/netwatch"
)

// Проверка через каждый туннель, который сейчас есть.
func TestLiveCheckThroughTunnels(t *testing.T) {
	snap, err := netwatch.Take()
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Tunnels) == 0 {
		t.Skip("VPN не подключён")
	}
	c := &Checker{Fetch: Bound{Timeout: 3 * time.Second}, Now: time.Now}
	for _, tun := range snap.Tunnels {
		start := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		res := c.Check(ctx, tun)
		cancel()
		t.Logf("%s за %v: %s", tun.Name, time.Since(start).Round(time.Millisecond), core.Path{Tunnel: tun, Check: res}.Summary())
	}
}

// Проверка через системный прокси, если он включён.
func TestLiveCheckThroughSystemProxy(t *testing.T) {
	snap, err := netwatch.Take()
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Proxies) == 0 {
		t.Skip("системный прокси не включён")
	}
	c := &Checker{Fetch: Bound{Timeout: 3 * time.Second}, Now: time.Now}
	for _, px := range snap.Proxies {
		path := px.AsPath()
		start := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		res := c.Check(ctx, path)
		cancel()
		t.Logf("%s (%s, слушает %q) за %v: %s", path.Name, px.Scheme, px.Process, time.Since(start).Round(time.Millisecond), core.Path{Tunnel: path, Check: res}.Summary())
	}
}

// Проверка через временный прокси на петле — HTTP (CONNECT) и SOCKS5: так
// путь через прокси проверяется по-настоящему, даже когда системного прокси
// нет. Прокси выходит маршрутом по умолчанию, поэтому выход — тот же, что у
// системы.
func TestLiveCheckThroughLocalProxy(t *testing.T) {
	connect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "только CONNECT", http.StatusMethodNotAllowed)
			return
		}
		up, err := net.DialTimeout("tcp", r.Host, 3*time.Second)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		c, buf, err := w.(http.Hijacker).Hijack()
		if err != nil {
			up.Close()
			return
		}
		io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n")
		go func() { io.Copy(up, buf); up.Close() }()
		io.Copy(c, up)
		c.Close()
	}))
	defer connect.Close()
	sl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer sl.Close()
	go socks5(sl, func(asked string) string { return asked }, make(chan string, 1))

	c := &Checker{Fetch: Bound{Timeout: 3 * time.Second}, Now: time.Now}
	for _, px := range []core.Proxy{proxyOn(t, connect.Listener, "http"), proxyOn(t, sl, "socks5")} {
		path := px.AsPath()
		start := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		res := c.Check(ctx, path)
		cancel()
		t.Logf("%s (%s) за %v: %s", path.Name, px.Scheme, time.Since(start).Round(time.Millisecond), core.Path{Tunnel: path, Check: res}.Summary())
		if res.Outcome == core.Unverified {
			t.Errorf("%s: выход через прокси не проверен: %s", path.Name, res.Detail)
		}
	}
}

// Интерфейс без маршрута в интернет: запрос не проходит, а не уходит в
// физический интерфейс. На macOS это системный utun0, на Windows — петля.
func TestLiveBoundRequestDoesNotFallBack(t *testing.T) {
	ifs, _ := net.Interfaces()
	for _, ifi := range ifs {
		if runtime.GOOS == "windows" && ifi.Flags&net.FlagLoopback == 0 || runtime.GOOS != "windows" && ifi.Name != "utun0" {
			continue
		}
		tun := core.Tunnel{Name: ifi.Name, Index: ifi.Index, Addrs: []netip.Addr{netip.MustParseAddr("10.255.255.1")}}
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		body, err := Bound{Timeout: 2 * time.Second}.Get(ctx, tun, "https://1.1.1.1/cdn-cgi/trace")
		if err == nil {
			t.Fatalf("запрос через %s прошёл: %s", ifi.Name, body)
		}
		t.Logf("через %s запрос не прошёл, как и должен: %v", ifi.Name, err)
		return
	}
	t.Skip("нет интерфейса без маршрута в интернет")
}

// Зонд «Россия напрямую» через каждый туннель: российский сервис через туннель
// и через физический интерфейс.
func TestLiveRussiaDirectProbe(t *testing.T) {
	snap, err := netwatch.Take()
	if err != nil || len(snap.Tunnels) == 0 {
		t.Skip("VPN не подключён")
	}
	name, index, ok := netwatch.Physical()
	if !ok {
		t.Skip("нет физического интерфейса")
	}
	ifi, err := net.InterfaceByIndex(index)
	if err != nil {
		t.Fatal(err)
	}
	var phys core.Tunnel
	addrs, _ := ifi.Addrs()
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
			ip, _ := netip.AddrFromSlice(ipn.IP.To4())
			phys = core.Tunnel{Name: name, Index: index, Addrs: []netip.Addr{ip}}
		}
	}
	c := &Checker{Fetch: Bound{Timeout: 3 * time.Second}, Now: time.Now}
	for _, tun := range snap.Tunnels {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		check := c.Check(ctx, tun)
		if check.Outcome != core.Verified {
			cancel()
			t.Logf("%s: выход не проверен — зонд не нужен", tun.Name)
			continue
		}
		start := time.Now()
		pr := c.Probe(ctx, tun, check.Exit, phys, true)
		cancel()
		state := map[core.ProbeState]string{core.ProbeThrough: "через туннель", core.ProbeDirect: "«Россия напрямую»", core.ProbeUnavailable: "сервис не ответил"}[pr.State]
		t.Logf("%s за %v: %s — российский сервис видит %s, выход %s", tun.Name, time.Since(start).Round(time.Millisecond), state, pr.Seen, check.Exit.IP)
		if pr.State == core.ProbeUnavailable {
			t.Errorf("%s: российский сервис не ответил", tun.Name)
		}
	}
}

// Соединение мимо VPN, как его делает «Проверка»: через физический интерфейс
// до Cloudflare доходит (правил нет), до адреса из TEST-NET — нет.
func TestLiveReachThroughPhysical(t *testing.T) {
	name, index, ok := netwatch.Physical()
	if !ok {
		t.Skip("нет физического интерфейса")
	}
	phys := core.Tunnel{Name: name, Index: index}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := Reach(ctx, phys, netip.MustParseAddrPort("1.1.1.1:443")); err != nil {
		t.Fatalf("1.1.1.1 через %s: %v", name, err)
	}
	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := Reach(ctx, phys, netip.MustParseAddrPort("192.0.2.1:443")); err == nil {
		t.Fatal("достучался до TEST-NET")
	}
	t.Logf("через %s: 1.1.1.1 доступен, 192.0.2.1 — нет", name)
}
