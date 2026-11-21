package exitcheck

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"appguard/internal/core"
)

// Запросы пути через прокси идут через сам прокси: страницу отдаёт тот, до кого
// прокси довёл, а имя узла разрешает прокси.

// target — сервер проверки: отвечает адресом, который он видит.
func target(t *testing.T) string {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "seen="+r.Host)
	}))
	t.Cleanup(srv.Close)
	return srv.Listener.Addr().String()
}

func proxyOn(t *testing.T, ln net.Listener, scheme string) core.Proxy {
	ap := netip.MustParseAddrPort(ln.Addr().String())
	return core.Proxy{Scheme: scheme, Host: ap.Addr().String(), Port: ap.Port(), Addrs: []netip.Addr{ap.Addr()}}
}

func TestCheckGoesThroughHTTPProxy(t *testing.T) {
	addr := target(t)
	var asked string
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = r.URL.String() // прокси получает полный адрес
		resp, err := http.Get("http://" + addr + r.URL.Path)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		io.Copy(w, resp.Body)
	}))
	defer proxy.Close()

	px := proxyOn(t, proxy.Listener, "http")
	body, err := Bound{Timeout: time.Second}.Get(context.Background(), px.AsPath(), "http://exit.test/trace")
	if err != nil || string(body) != "seen="+addr {
		t.Fatalf("%q %v", body, err)
	}
	if asked != "http://exit.test/trace" {
		t.Fatalf("прокси спросили %q", asked)
	}
}

func TestCheckGoesThroughSOCKS5WithNameResolvedByProxy(t *testing.T) {
	addr := target(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	names := make(chan string, 1)
	go socks5(ln, func(string) string { return addr }, names)

	px := proxyOn(t, ln, "socks5")
	body, err := Bound{Timeout: time.Second}.Get(context.Background(), px.AsPath(), "http://exit.test/trace")
	if err != nil || string(body) != "seen=exit.test" {
		t.Fatalf("%q %v", body, err)
	}
	if got := <-names; got != "exit.test:80" {
		t.Fatalf("SOCKS5 получил %q вместо имени узла", got)
	}
}

func TestClosedProxyFailsTheCheck(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	px := proxyOn(t, ln, "http")
	ln.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	c := &Checker{Fetch: Bound{Timeout: time.Second}, Now: time.Now}
	if res := c.Check(ctx, px.AsPath()); res.Outcome != core.Unverified {
		t.Fatalf("выход через неработающий прокси: %+v", res)
	}
}

// socks5 — простейший SOCKS5 без пароля: запоминает, куда просили, и соединяет
// с тем, что для этого назовёт route.
func socks5(ln net.Listener, route func(asked string) string, names chan<- string) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			r := bufio.NewReader(c)
			hello := make([]byte, 2)
			io.ReadFull(r, hello)
			io.ReadFull(r, make([]byte, hello[1]))
			c.Write([]byte{5, 0})
			head := make([]byte, 4)
			io.ReadFull(r, head)
			var host string
			switch head[3] {
			case 3:
				n, _ := r.ReadByte()
				b := make([]byte, n)
				io.ReadFull(r, b)
				host = string(b)
			case 1:
				b := make([]byte, 4)
				io.ReadFull(r, b)
				host = net.IP(b).String()
			}
			pb := make([]byte, 2)
			io.ReadFull(r, pb)
			asked := net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(pb))))
			select {
			case names <- asked:
			default:
			}
			up, err := net.Dial("tcp", route(asked))
			if err != nil {
				c.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
				return
			}
			defer up.Close()
			c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
			go io.Copy(up, r)
			io.Copy(c, up)
		}()
	}
}
