package procs

import (
	"encoding/binary"
	"net/netip"
	"slices"
	"testing"
)

// row4 — строка MIB_TCPROW_OWNER_PID так, как её кладёт Windows.
func row4(state uint32, local, remote string, pid uint32) []byte {
	b := make([]byte, tcpRow4Size)
	l, r := netip.MustParseAddrPort(local), netip.MustParseAddrPort(remote)
	binary.LittleEndian.PutUint32(b[0:], state)
	copy(b[4:8], l.Addr().AsSlice())
	binary.BigEndian.PutUint16(b[8:], l.Port())
	copy(b[12:16], r.Addr().AsSlice())
	binary.BigEndian.PutUint16(b[16:], r.Port())
	binary.LittleEndian.PutUint32(b[20:], pid)
	return b
}

func row6(state uint32, local, remote string, pid uint32) []byte {
	b := make([]byte, tcpRow6Size)
	l, r := netip.MustParseAddrPort(local), netip.MustParseAddrPort(remote)
	copy(b[0:16], l.Addr().AsSlice())
	binary.BigEndian.PutUint16(b[20:], l.Port())
	copy(b[24:40], r.Addr().AsSlice())
	binary.BigEndian.PutUint16(b[44:], r.Port())
	binary.LittleEndian.PutUint32(b[48:], state)
	binary.LittleEndian.PutUint32(b[52:], pid)
	return b
}

func table(n uint32, rows ...[]byte) []byte {
	b := binary.LittleEndian.AppendUint32(nil, n)
	return append(b, slices.Concat(rows...)...)
}

func TestParseTCPTable4(t *testing.T) {
	buf := table(3,
		row4(5, "192.168.1.20:51000", "104.18.0.1:443", 1234), // клиент VPN к серверу на CDN
		row4(3, "192.168.1.20:51001", "104.18.0.2:443", 777),  // попытка, которую отбросил файрвол
		row4(2, "0.0.0.0:445", "0.0.0.0:0", 4),                // слушает
	)
	got := ParseTCPTable4(buf)
	want := []Conn{
		{1234, "tcp", netip.MustParseAddrPort("192.168.1.20:51000"), netip.MustParseAddrPort("104.18.0.1:443"), "ESTABLISHED"},
		{777, "tcp", netip.MustParseAddrPort("192.168.1.20:51001"), netip.MustParseAddrPort("104.18.0.2:443"), "SYN_SENT"},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("%+v", got)
	}
}

func TestParseTCPTable6(t *testing.T) {
	buf := table(2,
		row6(5, "[2a02:6b8::1]:51000", "[2606:4700::6812:1]:443", 1234),
		row6(2, "[::]:445", "[::]:0", 4),
	)
	got := ParseTCPTable6(buf)
	want := []Conn{{1234, "tcp", netip.MustParseAddrPort("[2a02:6b8::1]:51000"), netip.MustParseAddrPort("[2606:4700::6812:1]:443"), "ESTABLISHED"}}
	if !slices.Equal(got, want) {
		t.Fatalf("%+v", got)
	}
}

// Соединение к порту, который слушает тот же процесс, — входящее к самому
// приложению, а не к его сервису.
func TestParseTCPTableSkipsInbound(t *testing.T) {
	buf := table(3,
		row4(2, "0.0.0.0:3000", "0.0.0.0:0", 500),
		row4(5, "192.168.1.20:3000", "95.1.2.3:41234", 500),
		row4(5, "192.168.1.20:51111", "104.18.0.1:443", 500),
	)
	got := ParseTCPTable4(buf)
	if len(got) != 1 || got[0].Remote != netip.MustParseAddrPort("104.18.0.1:443") {
		t.Fatalf("%+v", got)
	}
}

func TestTargetHas(t *testing.T) {
	notion := `C:\Users\student\AppData\Local\Programs\Notion`
	pkg := []string{`C:\Program Files\WindowsApps\OpenAI.ChatGPT-Desktop_1.2025.1.0_x64__2p2nqsd0c76g0`}
	for _, c := range []struct {
		exe, target string
		isDir       bool
		pkgDirs     []string
		want        bool
	}{
		{`C:\Users\student\AppData\Local\Programs\Notion\Notion.exe`, notion, true, nil, true},
		{`c:\users\STUDENT\appdata\local\programs\notion\resources\helper.exe`, notion, true, nil, true},
		{`C:\Users\student\AppData\Local\Programs\NotionX\NotionX.exe`, notion, true, nil, false},
		{`C:\Windows\System32\curl.exe`, `C:\Windows\System32\curl.exe`, false, nil, true},
		{`C:\Windows\System32\cmd.exe`, `C:\Windows\System32\curl.exe`, false, nil, false},
		{`C:\Program Files\WindowsApps\OpenAI.ChatGPT-Desktop_1.2025.1.0_x64__2p2nqsd0c76g0\app\ChatGPT.exe`, "package:OpenAI.ChatGPT-Desktop_2p2nqsd0c76g0", false, pkg, true},
		{`C:\Program Files\WindowsApps\Other_1.0_x64__abc\Other.exe`, "package:OpenAI.ChatGPT-Desktop_2p2nqsd0c76g0", false, pkg, false},
	} {
		if got := (Target{Path: c.target, Dir: c.isDir, PackageDirs: c.pkgDirs}).Has(c.exe); got != c.want {
			t.Errorf("%s ⟵ %s: %v", c.exe, c.target, got)
		}
	}
}

// Кто слушает порт системного прокси — по таблице TCP Windows.
func TestTCPListeners(t *testing.T) {
	buf := table(3,
		row4(2, "127.0.0.1:10808", "0.0.0.0:0", 4242),
		row4(2, "0.0.0.0:445", "0.0.0.0:0", 4),
		row4(5, "127.0.0.1:51000", "127.0.0.1:10808", 777),
	)
	at := []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:10808")}
	if got := TCPListeners(buf, false, at); !slices.Equal(got, []int{4242}) {
		t.Fatalf("%v", got)
	}
	if got := TCPListeners(buf, false, []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:445")}); !slices.Equal(got, []int{4}) {
		t.Fatalf("все адреса: %v", got)
	}
}

// Заголовок обещает больше строк, чем в буфере, — берётся столько, сколько есть.
func TestParseTCPTableTruncated(t *testing.T) {
	buf := table(5, row4(5, "192.168.1.20:51000", "104.18.0.1:443", 1234))
	if got := ParseTCPTable4(append(buf, 1, 2, 3)); len(got) != 1 {
		t.Fatalf("%+v", got)
	}
	if got := ParseTCPTable4([]byte{1}); got != nil {
		t.Fatalf("%+v", got)
	}
}
