package procs

import (
	"net/netip"
	"slices"
	"testing"
)

// Вывод ps как есть: пробелы в путях, лишние отступы.
const psOut = `    1 /sbin/launchd
  763 /Applications/Notion.app/Contents/MacOS/Notion
  932 /Applications/Notion.app/Contents/Frameworks/Notion Helper.app/Contents/MacOS/Notion Helper
49876 /usr/libexec/pfd
 1234 /Users/student/Library/Caches/notion.id.ShipIt/ShipIt
    7
abc /broken/line
`

func TestParseProcs(t *testing.T) {
	got := ParseProcs([]byte(psOut))
	want := []Proc{
		{1, "/sbin/launchd"},
		{763, "/Applications/Notion.app/Contents/MacOS/Notion"},
		{932, "/Applications/Notion.app/Contents/Frameworks/Notion Helper.app/Contents/MacOS/Notion Helper"},
		{49876, "/usr/libexec/pfd"},
		{1234, "/Users/student/Library/Caches/notion.id.ShipIt/ShipIt"},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("%+v", got)
	}
}

// Вывод lsof у Notion на живой системе: слушающий сокет основного процесса,
// соединения вспомогательного.
const lsofOut = `p763
f38
PTCP
n127.0.0.1:54339
TST=LISTEN
TQR=0
TQS=0
p933
f25
PTCP
n10.8.1.1:65460->208.103.161.17:443
TST=ESTABLISHED
TQR=0
TQS=0
f26
PTCP
n10.8.1.1:51939->208.103.161.2:443
TST=ESTABLISHED
f40
PUDP
n10.8.1.1:50000->104.18.0.1:443
f41
PUDP
n*:5353
f42
PTCP
n[2606:4700::6812:1]:443
`

func TestParseConnsTakesOutgoingConnectionsOfEveryProcess(t *testing.T) {
	got := ParseConns([]byte(lsofOut))
	want := []Conn{
		{933, "tcp", netip.MustParseAddrPort("10.8.1.1:65460"), netip.MustParseAddrPort("208.103.161.17:443"), "ESTABLISHED"},
		{933, "tcp", netip.MustParseAddrPort("10.8.1.1:51939"), netip.MustParseAddrPort("208.103.161.2:443"), "ESTABLISHED"},
		{933, "udp", netip.MustParseAddrPort("10.8.1.1:50000"), netip.MustParseAddrPort("104.18.0.1:443"), ""},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("%+v", got)
	}
}

// Попытка, которую файрвол отбросил, тоже видна в lsof — но не установленной.
func TestConnEstablished(t *testing.T) {
	for _, c := range []struct {
		conn Conn
		want bool
	}{
		{Conn{Proto: "tcp", State: "ESTABLISHED"}, true},
		{Conn{Proto: "tcp", State: "SYN_SENT"}, false},
		{Conn{Proto: "tcp"}, false},
		{Conn{Proto: "udp"}, true},
	} {
		if got := c.conn.Established(); got != c.want {
			t.Errorf("%+v: %v", c.conn, got)
		}
	}
}

// Вывод `lsof -F ptn` на маке с AmneziaVPN: туннель маршрута по умолчанию utun11
// держит её расширение Network Extension (управляющий сокет unit 12), utun1 —
// системная служба. Сам сокет к серверу у расширения не привязан к адресу.
// Процесс 666 завёл unix-сокет с тем же именем — так выглядит подделка.
const lsofOwners = `p641
f5
tsystm
n[ctl com.apple.net.utun_control id 5 unit 2]
p34221
fcwd
tDIR
n/Applications/AmneziaVPN.app/Contents/PlugIns/AmneziaVPNNetworkExtension.appex
f5
tsystm
n[ctl com.apple.net.utun_control id 5 unit 12]
f8
tsystm
n[ctl com.apple.net.utun_control id 5 unit 12]
f10
tIPv4
n*:57887
p666
f3
tunix
n[ctl com.apple.net.utun_control id 5 unit 12]
`

func TestParseTunnelOwnersFindsWhoHoldsTheTunnel(t *testing.T) {
	for iface, want := range map[string][]int{"utun11": {34221}, "utun1": {641}, "utun4": nil, "en0": nil, "utun": nil} {
		if got := ParseTunnelOwners([]byte(lsofOwners), iface); !slices.Equal(got, want) {
			t.Errorf("%s: %v, а нужно %v", iface, got, want)
		}
	}
}

func TestParseConnsSkipsInboundConnectionsToAListeningPort(t *testing.T) {
	// Процесс слушает 3000 (после соединения в выводе — порядок не важен) и
	// принял клиента; своё исходящее соединение у него тоже есть.
	out := `p500
f10
PTCP
n192.168.68.124:3000->95.1.2.3:41234
TST=ESTABLISHED
f11
PTCP
n192.168.68.124:51111->104.18.0.1:443
TST=ESTABLISHED
f12
PTCP
n*:3000
TST=LISTEN
`
	got := ParseConns([]byte(out))
	if len(got) != 1 || got[0].Remote != netip.MustParseAddrPort("104.18.0.1:443") {
		t.Fatalf("входящее соединение учтено как исходящее: %+v", got)
	}
}

func TestParseConnsIPv6AndZones(t *testing.T) {
	out := `p9
f3
PTCP
n[2606:4700::1]:50000->[2606:4700::6812:1]:443
TST=ESTABLISHED
f4
PTCP
n[fe80::1%utun0]:50001->[fe80::2%utun0]:443
TST=ESTABLISHED
f5
PTCP
garbage->nonsense
`
	got := ParseConns([]byte(out))
	if len(got) != 2 || got[0].Remote.Addr().String() != "2606:4700::6812:1" || got[1].Remote.Addr().Zone() != "utun0" {
		t.Fatalf("%+v", got)
	}
}

func TestMatch(t *testing.T) {
	notion := AppRef{ID: "notion.id", Path: "/Applications/Notion.app"}
	safari := AppRef{ID: "com.apple.Safari", Path: "/Applications/Safari.app"}
	for _, tc := range []struct {
		app  AppRef
		real string
		exe  string
		want bool
		why  string
	}{
		{notion, "", "/Applications/Notion.app/Contents/MacOS/Notion", true, "основной процесс"},
		{notion, "", "/Applications/Notion.app/Contents/Frameworks/Notion Helper.app/Contents/MacOS/Notion Helper", true, "вспомогательный процесс"},
		{notion, "", "/Applications/Notion.app/Contents/XPCServices/x.xpc/Contents/MacOS/x", true, "XPC-служба"},
		{notion, "", "/Users/s/Library/Caches/notion.id.ShipIt/ShipIt", true, "обновлятор в кэше (ShipIt)"},
		{notion, "", "/Users/s/Library/Caches/notion.id/org.sparkle-project.Sparkle/Launcher/Updater.app/Contents/MacOS/Updater", true, "обновлятор в кэше (Sparkle)"},
		{notion, "", "/Applications/Notion.app.old/Contents/MacOS/Notion", false, "соседний каталог с похожим именем"},
		{notion, "", "/Applications/Notion.app", false, "сам пакет не процесс"},
		{notion, "", "/Applications/Notion Calendar.app/Contents/MacOS/Notion Calendar", false, "другое приложение"},
		{notion, "", "/Users/s/Downloads/Notion.app/Contents/MacOS/Notion", false, "копия в другом месте"},
		{notion, "", "/Users/s/Library/Caches/other.id.ShipIt/ShipIt", false, "кэш другого приложения"},
		{notion, "", "/Users/s/Library/Caches/notion.identity/x", false, "идентификатор — только целиком"},
		{notion, "", "/Users/s/Documents/notion.id/x", false, "каталог с таким именем не в Library/Caches"},
		{safari, "/System/Cryptexes/App/System/Applications/Safari.app", "/System/Cryptexes/App/System/Applications/Safari.app/Contents/MacOS/Safari", true, "путь по ссылке, процесс по настоящему пути"},
	} {
		if got := Match(tc.exe, tc.app, tc.real); got != tc.want {
			t.Errorf("%s: %v, ждали %v (%s)", tc.why, got, tc.want, tc.exe)
		}
	}
}

// Вывод `lsof -iTCP -sTCP:LISTEN -F pn`: клиент VPN 744 слушает порт системного
// прокси, 618 — все адреса на своём порту, 900 — тот же порт на другом адресе.
const lsofListen = `p618
f10
n*:51437
p744
f35
n127.0.0.1:12334
p900
f5
n192.168.68.124:12334
p901
f6
n[::1]:12334
`

func TestParseListenersFindsWhoListensOnTheProxy(t *testing.T) {
	at := []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:12334")}
	if got := ParseListeners([]byte(lsofListen), at); !slices.Equal(got, []int{744}) {
		t.Fatalf("%v", got)
	}
	// Слушающий «все адреса» принимает соединения и на 127.0.0.1.
	if got := ParseListeners([]byte(lsofListen), []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:51437")}); !slices.Equal(got, []int{618}) {
		t.Fatalf("%v", got)
	}
}
