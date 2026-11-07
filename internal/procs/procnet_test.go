package procs

import (
	"net/netip"
	"slices"
	"testing"
)

// Строки — с настоящего ядра, порядок байтов little-endian: тест проверяет разбор
// на машинах с ним, а других среди целей vpnlock нет.
const procTCP = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1001 1 0000000000000000 100 0 0 10 0
   1: 0F02000A:D431 0A0A0AC0:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 1002 1 0000000000000000 20 4 30 10 -1
   2: 0100007F:0050 0100007F:C350 01 00000000:00000000 00:00000000 00000000     0        0 1003 1 0000000000000000 20 4 30 10 -1
   3: 0F02000A:D432 0A0A0AC0:01BB 02 00000000:00000000 00:00000000 00000000     0        0 0 1 0000000000000000 20 4 30 10 -1
`

const procTCP6 = `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0000000000000000FFFF00000F02000A:D433 0000000000000000FFFF00000A0A0AC0:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 2001 1 0000000000000000 20 4 30 10 -1
   1: B80D0120000000000000000001000000:D434 B80D0120000000000000000002000000:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 2002 1 0000000000000000 20 4 30 10 -1
`

func TestParseProcNetTCP(t *testing.T) {
	socks := ParseProcNet("tcp", []byte(procTCP))
	if len(socks) != 3 {
		t.Fatalf("строка без сокета (inode 0) не считается: %+v", socks)
	}
	if socks[0].Conn.State != "LISTEN" || socks[1].Conn.State != "ESTABLISHED" {
		t.Errorf("%+v", socks)
	}
	out := Outgoing(socks)
	if len(out) != 1 || out[0].Inode != 1002 {
		t.Fatalf("входящее и слушающий порт — не исходящие: %+v", out)
	}
	if out[0].Conn.Local != netip.MustParseAddrPort("10.0.2.15:54321") ||
		out[0].Conn.Remote != netip.MustParseAddrPort("192.10.10.10:443") {
		t.Errorf("%+v", out[0].Conn)
	}
}

func TestParseProcNetTCP6(t *testing.T) {
	socks := ParseProcNet("tcp", []byte(procTCP6))
	if len(socks) != 2 {
		t.Fatalf("%+v", socks)
	}
	if got := socks[0].Conn.Remote; got != netip.MustParseAddrPort("192.10.10.10:443") {
		t.Errorf("IPv4 внутри tcp6 разворачивается: %v", got)
	}
	if got := socks[1].Conn.Remote; got != netip.MustParseAddrPort("[2001:db8::2]:443") {
		t.Errorf("IPv6: %v", got)
	}
}

func TestOwnerlessUDPPorts(t *testing.T) {
	sock := func(proto, local string, inode uint64) Socket {
		return Socket{Inode: inode, Conn: Conn{Proto: proto, Local: netip.MustParseAddrPort(local)}}
	}
	list := []Socket{
		sock("udp", "0.0.0.0:51820", 10), // WireGuard: процесса нет
		sock("udp", "[::]:51820", 11),    // он же в IPv6
		sock("udp", "127.0.0.53:53", 12), // resolved: процесс есть
		sock("tcp", "0.0.0.0:8080", 13),  // не UDP
		sock("udp", "0.0.0.0:0", 14),     // порта нет
		sock("udp", "0.0.0.0:4789", 15),  // VXLAN
	}
	user := sock("udp", "0.0.0.0:5353", 16)
	user.UID = 1000 // обычный пользователь ядерного сокета завести не может
	peer := sock("udp", "0.0.0.0:6000", 17)
	peer.Conn.Remote = netip.MustParseAddrPort("192.0.2.1:443") // сокет ядра ни с кем не соединён
	got := OwnerlessUDPPorts(append(list, user, peer), map[uint64]int{12: 500})
	if !slices.Equal(got, []uint16{4789, 51820}) {
		t.Errorf("%v", got)
	}
}

// Сокет, закрытый посреди обхода процессов, остался бы без владельца.
func TestLastingDropsSocketsSeenOnce(t *testing.T) {
	before := []Socket{{Inode: 1}, {Inode: 2}}
	after := []Socket{{Inode: 2}, {Inode: 3}}
	got := Lasting(before, after)
	if len(got) != 1 || got[0].Inode != 2 {
		t.Errorf("%+v", got)
	}
}

func TestParseProcNetUID(t *testing.T) {
	if s := ParseProcNet("tcp", []byte(procTCP)); s[0].UID != 0 || s[1].UID != 1000 {
		t.Errorf("%+v", s)
	}
}

func TestAbsScript(t *testing.T) {
	for _, c := range []struct {
		argv []string
		cwd  string
		want []string
	}{
		{[]string{"python3", "bot.py"}, "/opt/bot", []string{"python3", "/opt/bot/bot.py"}},
		{[]string{"python3", "-u", "sub/bot.py", "x"}, "/opt/bot", []string{"python3", "-u", "/opt/bot/sub/bot.py", "x"}},
		{[]string{"python3", "/opt/bot/bot.py"}, "/tmp", []string{"python3", "/opt/bot/bot.py"}},
		{[]string{"python3", "bot.py"}, "", []string{"python3", "bot.py"}},
		{[]string{"python3"}, "/opt/bot", []string{"python3"}},
	} {
		if got := AbsScript(c.argv, c.cwd); !slices.Equal(got, c.want) {
			t.Errorf("%q в %s: %q", c.argv, c.cwd, got)
		}
	}
}

func TestParseProcNetUDP(t *testing.T) {
	const udp = `   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
  100: 00000000:D431 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 3001 2 0000000000000000 0
  101: 0F02000A:D432 0A0A0AC0:01BB 01 00000000:00000000 00:00000000 00000000     0        0 3002 2 0000000000000000 0
`
	out := Outgoing(ParseProcNet("udp", []byte(udp)))
	if len(out) != 1 || out[0].Inode != 3002 || !out[0].Conn.Established() {
		t.Errorf("считается только подключённый UDP: %+v", out)
	}
}

func TestSocketInode(t *testing.T) {
	if n, ok := SocketInode("socket:[12345]"); !ok || n != 12345 {
		t.Errorf("%d %v", n, ok)
	}
	for _, s := range []string{"/dev/null", "pipe:[1]", "socket:[x]"} {
		if _, ok := SocketInode(s); ok {
			t.Errorf("%s — не сокет", s)
		}
	}
}

func TestParseArgv(t *testing.T) {
	if got := ParseArgv([]byte("node\x00/opt/x/cli.js\x00--flag\x00")); !slices.Equal(got, []string{"node", "/opt/x/cli.js", "--flag"}) {
		t.Errorf("%q", got)
	}
	if got := ParseArgv(nil); got != nil {
		t.Errorf("%q", got)
	}
}

func TestParseCgroups(t *testing.T) {
	u, n := ParseCgroups([]byte("3:net_cls,net_prio:/vpnlock/ab12\n1:name=systemd:/x\n0::/system.slice/nginx.service\n"))
	if u != "/system.slice/nginx.service" || n != "/vpnlock/ab12" {
		t.Errorf("%q %q", u, n)
	}
	if u, n := ParseCgroups([]byte("0::/user.slice\n")); u != "/user.slice" || n != "" {
		t.Errorf("%q %q", u, n)
	}
}

func TestInUnit(t *testing.T) {
	for _, c := range []struct {
		path, unit string
		want       bool
	}{
		{"/system.slice/nginx.service", "nginx.service", true},
		{"/system.slice/nginx.service/worker", "nginx.service", true},
		{"/system.slice/nginx.service.d", "nginx.service", false},
		{"/system.slice/my-nginx.service", "nginx.service", false},
		{"/user.slice/user-1000.slice", "nginx.service", false},
	} {
		if got := InUnit(c.path, c.unit); got != c.want {
			t.Errorf("InUnit(%s, %s) = %v", c.path, c.unit, got)
		}
	}
}

func TestExePath(t *testing.T) {
	if got := ExePath("/usr/bin/foo (deleted)"); got != "/usr/bin/foo" {
		t.Error(got)
	}
}
