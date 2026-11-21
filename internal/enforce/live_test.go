//go:build live && darwin

// Живая проверка исполнителя на этом маке. Нужен root, а собирать под sudo
// нельзя (кэш сборки станет чужим), поэтому тест собирается обычным
// пользователем и запускается собранным файлом:
//
//	tools/go test -c -tags live -o /tmp/appguard-enforce.test ./internal/enforce
//	sudo /tmp/appguard-enforce.test -test.v -test.run Live
//
// Закрывает и открывает только адреса example.com и порт временного «прокси»
// на петле, а в конце снимает всё.

package enforce

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"appguard/internal/netwatch"
)

func TestLivePFClosesAndOpens(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("нужен root — см. шапку файла")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", "example.com")
	if err != nil || len(addrs) == 0 {
		t.Skipf("example.com не разрешается: %v", err)
	}
	target := net.JoinHostPort(addrs[0].String(), "443")
	reach := func() bool {
		conn, err := net.DialTimeout("tcp4", target, 3*time.Second)
		if err == nil {
			conn.Close()
		}
		return err == nil
	}
	if !reach() {
		t.Skip("example.com недоступен и без правил")
	}
	snap, err := netwatch.Take()
	if err != nil || snap.DefaultIface == "" {
		t.Fatalf("маршрут по умолчанию не найден: %v", err)
	}

	p := &PF{TokenFile: filepath.Join(t.TempDir(), "pf.token")}
	defer p.Clear()
	v4 := []netip.Addr{}
	for _, a := range addrs {
		v4 = append(v4, a.Unmap())
	}

	if err := p.Apply(Rules{V4: v4}); err != nil {
		t.Fatal(err)
	}
	if reach() {
		t.Fatal("закрытый адрес доступен")
	}
	t.Logf("закрыто: %s недоступен", target)

	if err := p.Apply(Rules{OpenIfaces: []string{snap.DefaultIface}, V4: v4}); err != nil {
		t.Fatal(err)
	}
	if !reach() {
		t.Fatalf("адрес не открылся через %s", snap.DefaultIface)
	}
	t.Logf("открыто через %s: %s доступен", snap.DefaultIface, target)

	// Защиту сняли (таблица пуста): адрес снова доступен, хоть правила и стоят.
	if err := p.Apply(Rules{V4: v4}); err != nil {
		t.Fatal(err)
	}
	if err := p.Apply(Rules{}); err != nil {
		t.Fatal(err)
	}
	if !reach() {
		t.Fatal("после очистки таблицы адрес по-прежнему закрыт")
	}
	t.Log("таблица очищена — адрес снова доступен")

	if err := p.Clear(); err != nil {
		t.Fatal(err)
	}
	out, _ := exec.Command(pfctl, "-a", Anchor, "-sr").CombinedOutput()
	if bytes.Contains(out, []byte("block")) || bytes.Contains(out, []byte("pass")) {
		t.Fatalf("после снятия в якоре остались правила:\n%s", out)
	}
	if !reach() {
		t.Fatal("после снятия адрес недоступен")
	}
	t.Log("после снятия правил нет, адрес доступен")
}

// Соединение, установленное до того, как адрес попал в таблицу, не должно
// рваться: pf видит его пакеты впервые, без SYN и без состояния. Так бывает
// при обучении и на чистом маке, где pf включается позже соединений.
func TestLiveEstablishedConnectionSurvivesRuleChange(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("нужен root — см. шапку файла")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", "example.com")
	if err != nil || len(addrs) == 0 {
		t.Skipf("example.com не разрешается: %v", err)
	}
	snap, err := netwatch.Take()
	if err != nil || snap.DefaultIface == "" {
		t.Fatalf("маршрут по умолчанию не найден: %v", err)
	}
	p := &PF{TokenFile: filepath.Join(t.TempDir(), "pf.token")}
	defer p.Clear()

	conn, err := net.DialTimeout("tcp4", net.JoinHostPort(addrs[0].String(), "80"), 3*time.Second)
	if err != nil {
		t.Skipf("example.com:80 недоступен: %v", err)
	}
	defer conn.Close()
	// Ответ читается целиком: иначе остаток прошлого ответа лежит в буфере
	// сокета, и следующий запрос «успешен» без единого пакета в сеть.
	reader := bufio.NewReader(conn)
	get := func(wait time.Duration) error {
		conn.SetDeadline(time.Now().Add(wait))
		if _, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")); err != nil {
			return err
		}
		resp, err := http.ReadResponse(reader, nil)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		_, err = io.Copy(io.Discard, resp.Body)
		return err
	}
	states := func() string {
		out, _ := exec.Command(pfctl, "-ss").CombinedOutput()
		var mine []string
		for _, l := range strings.Split(string(out), "\n") {
			if strings.Contains(l, addrs[0].String()) {
				mine = append(mine, strings.Join(strings.Fields(l), " "))
			}
		}
		return strings.Join(mine, " | ")
	}
	if err := get(4 * time.Second); err != nil {
		t.Fatalf("соединение не работает и без правил: %v", err)
	}
	t.Logf("состояния до: %q", states())

	// Состояние этого соединения (только его) убито — как у соединения, которое
	// появилось раньше pf.
	if out, err := exec.Command(pfctl, "-k", "0.0.0.0/0", "-k", addrs[0].String()).CombinedOutput(); err != nil {
		t.Fatalf("не удалось убить состояние: %v: %s", err, out)
	}
	t.Logf("состояния после убийства: %q", states())

	var v4 []netip.Addr
	for _, a := range addrs {
		v4 = append(v4, a.Unmap())
	}
	// Контроль: если путь закрыт, соединение без состояния должно упереться в запрет.
	if err := p.Apply(Rules{V4: v4}); err != nil {
		t.Fatal(err)
	}
	if err := get(2 * time.Second); err == nil {
		t.Fatal("контроль: при закрытом пути безгосударственное соединение не остановлено")
	}
	t.Log("контроль: при закрытом пути соединение остановлено")

	// Путь открыт: тот же поток обязан продолжиться (повторы TCP его вернут).
	if err := p.Apply(Rules{OpenIfaces: []string{snap.DefaultIface}, V4: v4}); err != nil {
		t.Fatal(err)
	}
	if err := get(8 * time.Second); err != nil {
		t.Fatalf("соединение не вернулось после открытия пути: %v", err)
	}
	t.Logf("состояния в конце: %q", states())
	t.Log("соединение без состояния продолжило работу через открытый путь")
}

// Порт прокси с непроверенным выходом закрыт для всех программ, кроме root:
// служба проверяет выход через этот же порт. «Прокси» — временный слушатель на
// 127.0.0.1, «программа» — nc от пользователя nobody.
func TestLiveProxyPortClosedForAllButRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("нужен root — см. шапку файла")
	}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	conns := make(chan net.Conn, 8)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			conns <- c
		}
	}()
	ap := netip.MustParseAddrPort(ln.Addr().String())
	port := strconv.Itoa(int(ap.Port()))
	nobody, err := user.Lookup("nobody")
	if err != nil {
		t.Fatal(err)
	}
	uid, _ := strconv.Atoi(nobody.Uid)
	gid, _ := strconv.Atoi(nobody.Gid)
	asNobody := func(args ...string) *exec.Cmd {
		cmd := exec.Command("/usr/bin/nc", args...)
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}}
		return cmd
	}
	programReaches := func() bool { return asNobody("-z", "-G", "2", "127.0.0.1", port).Run() == nil }
	rootReaches := func() bool {
		c, err := net.DialTimeout("tcp4", ap.String(), 2*time.Second)
		if err == nil {
			c.Close()
		}
		return err == nil
	}
	if !programReaches() {
		t.Skip("nc от nobody не подключается к петле и без правил")
	}

	p := &PF{TokenFile: filepath.Join(t.TempDir(), "pf.token")}
	defer p.Clear()
	if err := p.Apply(Rules{ClosedProxies: []netip.AddrPort{ap}}); err != nil {
		t.Fatal(err)
	}
	if programReaches() {
		t.Fatal("закрытый порт прокси доступен программе")
	}
	if !rootReaches() {
		t.Fatal("root не подключается к закрытому порту — службе нечем проверить выход прокси")
	}
	t.Logf("порт %s закрыт для nobody, открыт для root", ap)

	if err := p.Apply(Rules{}); err != nil {
		t.Fatal(err)
	}
	if !programReaches() {
		t.Fatal("правило снято, а порт по-прежнему закрыт")
	}
	t.Log("правило снято — порт снова доступен программе")

	// Соединение программы, открытое до закрытия порта, тоже останавливается:
	// состояния в pf у него нет.
	for len(conns) > 0 {
		(<-conns).Close()
	}
	nc := asNobody("127.0.0.1", port)
	in, err := nc.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := nc.Start(); err != nil {
		t.Fatal(err)
	}
	defer nc.Process.Kill()
	var conn net.Conn
	select {
	case conn = <-conns:
	case <-time.After(3 * time.Second):
		t.Fatal("nc не подключился")
	}
	defer conn.Close()
	r := bufio.NewReader(conn)
	line := func(wait time.Duration) (string, error) {
		conn.SetReadDeadline(time.Now().Add(wait))
		return r.ReadString('\n')
	}
	io.WriteString(in, "до\n")
	if s, err := line(2 * time.Second); err != nil || s != "до\n" {
		t.Fatalf("соединение не работает и без правил: %q %v", s, err)
	}
	if err := p.Apply(Rules{ClosedProxies: []netip.AddrPort{ap}}); err != nil {
		t.Fatal(err)
	}
	io.WriteString(in, "после\n")
	if s, err := line(3 * time.Second); err == nil {
		t.Fatalf("через закрытый порт прошло открытое раньше соединение: %q", s)
	}
	t.Log("открытое раньше соединение программы остановлено")

	if err := p.Clear(); err != nil {
		t.Fatal(err)
	}
	if out, _ := exec.Command(pfctl, "-a", Anchor, "-sr").CombinedOutput(); bytes.Contains(out, []byte("user")) {
		t.Fatalf("после снятия правило для порта осталось:\n%s", out)
	}
	if !programReaches() {
		t.Fatal("после снятия порт недоступен")
	}
	t.Log("после снятия правила для порта нет")
}

// Сторож видит, что якорь очистила чужая программа, а Apply возвращает всё
// как было.
func TestLiveVerifySeesFlushedAnchor(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("нужен root — см. шапку файла")
	}
	p := &PF{TokenFile: filepath.Join(t.TempDir(), "pf.token")}
	defer p.Clear()
	r := Rules{
		V4:            []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")},
		ClosedProxies: []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:1")},
	}
	if err := p.Apply(r); err != nil {
		t.Fatal(err)
	}
	if err := p.Verify(r); err != nil {
		t.Fatalf("сразу после Apply: %v", err)
	}
	for _, flush := range [][]string{{"-F", "rules"}, {"-F", "Tables"}, {"-F", "all"}} {
		if err := run(pfctl, append([]string{"-a", Anchor}, flush...)...); err != nil {
			t.Fatal(err)
		}
		drift := p.Verify(r)
		if drift == nil {
			t.Fatalf("после pfctl -a %s %v сторож ничего не заметил", Anchor, flush)
		}
		t.Logf("pfctl -a … %v: %v", flush, drift)
		if err := p.Apply(r); err != nil {
			t.Fatal(err)
		}
		if err := p.Verify(r); err != nil {
			t.Fatalf("после восстановления: %v", err)
		}
	}
}
