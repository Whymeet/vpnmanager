package dnswatch

import (
	"encoding/binary"
	"net"
	"net/netip"
	"slices"
	"testing"

	"github.com/miekg/dns"
	"golang.org/x/net/bpf"
)

// reply — ответ DNS на name с адресами addrs (через CNAME на cdn.example.net).
func reply(t *testing.T, name string, addrs ...string) []byte {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	m.Response = true
	m.Answer = append(m.Answer, &dns.CNAME{Hdr: dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60}, Target: "cdn.example.net."})
	for _, s := range addrs {
		a := netip.MustParseAddr(s)
		hdr := dns.RR_Header{Name: "cdn.example.net.", Class: dns.ClassINET, Ttl: 60}
		if a.Is4() {
			hdr.Rrtype = dns.TypeA
			m.Answer = append(m.Answer, &dns.A{Hdr: hdr, A: net.IP(a.AsSlice())})
		} else {
			hdr.Rrtype = dns.TypeAAAA
			m.Answer = append(m.Answer, &dns.AAAA{Hdr: hdr, AAAA: net.IP(a.AsSlice())})
		}
	}
	b, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// udp4 — пакет IPv4 с датаграммой UDP; ihl — длина заголовка в словах, frag —
// поле флагов и смещения.
func udp4(src, dst uint16, payload []byte, ihl int, frag uint16) []byte {
	h := make([]byte, ihl*4)
	h[0] = 0x40 | byte(ihl)
	binary.BigEndian.PutUint16(h[2:], uint16(len(h)+8+len(payload)))
	binary.BigEndian.PutUint16(h[6:], frag)
	h[8], h[9] = 64, 17
	copy(h[12:16], []byte{1, 1, 1, 1})
	copy(h[16:20], []byte{10, 8, 1, 1})
	return append(h, udpDatagram(src, dst, payload)...)
}

func udp6(src, dst uint16, payload []byte) []byte {
	h := make([]byte, 40)
	h[0] = 0x60
	binary.BigEndian.PutUint16(h[4:], uint16(8+len(payload)))
	h[6], h[7] = 17, 64
	return append(h, udpDatagram(src, dst, payload)...)
}

func udpDatagram(src, dst uint16, payload []byte) []byte {
	u := make([]byte, 8)
	binary.BigEndian.PutUint16(u[0:], src)
	binary.BigEndian.PutUint16(u[2:], dst)
	binary.BigEndian.PutUint16(u[4:], uint16(8+len(payload)))
	return append(u, payload...)
}

// onUtun — пакет IP так, как его видит BPF на utun: 4 байта семейства.
func onUtun(family uint32, ip []byte) []byte {
	return append(binary.LittleEndian.AppendUint32(nil, family), ip...)
}

func onEthernet(etherType uint16, ip []byte) []byte {
	h := make([]byte, 14)
	binary.BigEndian.PutUint16(h[12:], etherType)
	return append(h, ip...)
}

func TestFilterLetsOnlyDNSRepliesThrough(t *testing.T) {
	answer := reply(t, "api.example.com", "203.0.113.5")
	tcp := udp4(53, 51000, answer, 5, 0)
	tcp[9] = 6
	for _, c := range []struct {
		name string
		dlt  int
		pkt  []byte
		want bool
	}{
		{"utun, IPv4, ответ DNS", DLTNull, onUtun(2, udp4(53, 51000, answer, 5, 0)), true},
		{"utun, IPv4 с опциями", DLTNull, onUtun(2, udp4(53, 51000, answer, 6, 0)), true},
		{"utun, IPv6, ответ DNS", DLTNull, onUtun(30, udp6(53, 51000, answer)), true},
		{"utun, запрос DNS (порт назначения 53)", DLTNull, onUtun(2, udp4(51000, 53, answer, 5, 0)), false},
		{"utun, QUIC", DLTNull, onUtun(2, udp4(443, 51000, answer, 5, 0)), false},
		{"utun, TCP с порта 53", DLTNull, onUtun(2, tcp), false},
		{"utun, фрагмент", DLTNull, onUtun(2, udp4(53, 51000, answer, 5, 0x2000|8)), false},
		{"raw, IPv4", DLTRaw, udp4(53, 51000, answer, 5, 0), true},
		{"ethernet, IPv4", DLTEN10MB, onEthernet(0x0800, udp4(53, 51000, answer, 5, 0)), true},
		{"ethernet, IPv6", DLTEN10MB, onEthernet(0x86dd, udp6(53, 51000, answer)), true},
		{"ethernet, ARP", DLTEN10MB, onEthernet(0x0806, make([]byte, 28)), false},
	} {
		prog, err := Filter(c.dlt)
		if err != nil {
			t.Fatal(err)
		}
		insns, _ := bpf.Disassemble(prog)
		vm, err := bpf.NewVM(insns)
		if err != nil {
			t.Fatal(err)
		}
		n, err := vm.Run(c.pkt)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got := n > 0; got != c.want {
			t.Errorf("%s: принят %v", c.name, got)
		}
		if got := func() bool { _, ok := Parse(c.dlt, c.pkt); return ok }(); got != c.want {
			t.Errorf("%s: разобран %v", c.name, got)
		}
	}
	if _, err := Filter(127); err == nil {
		t.Fatal("неизвестный канальный уровень принят")
	}
}

func TestParseTakesTheQuestionNameAndAllAddresses(t *testing.T) {
	a, ok := Parse(DLTNull, onUtun(2, udp4(53, 51000, reply(t, "API.Example.com", "203.0.113.5", "2001:db8::5"), 5, 0)))
	want := []netip.Addr{netip.MustParseAddr("203.0.113.5"), netip.MustParseAddr("2001:db8::5")}
	if !ok || a.Name != "api.example.com" || !slices.Equal(a.Addrs, want) || a.From != netip.MustParseAddr("1.1.1.1") {
		t.Fatalf("%v %+v", ok, a)
	}
	// Ответ без адресов и ошибка — не ответы для обучения.
	if _, ok := Parse(DLTNull, onUtun(2, udp4(53, 51000, reply(t, "api.example.com"), 5, 0))); ok {
		t.Fatal("ответ без адресов разобран")
	}
	m := new(dns.Msg)
	m.SetQuestion("gone.example.com.", dns.TypeA)
	m.Response, m.Rcode = true, dns.RcodeNameError
	b, _ := m.Pack()
	if _, ok := Parse(DLTNull, onUtun(2, udp4(53, 51000, b, 5, 0))); ok {
		t.Fatal("NXDOMAIN разобран")
	}
}

// Буфер чтения BPF на macOS: заголовок 18 байт, записи по 4 байта.
func TestSplitReadsEveryPacketOfTheBuffer(t *testing.T) {
	var buf []byte
	pkts := [][]byte{[]byte("abcde"), []byte("0123456789"), []byte("xyz")}
	for _, p := range pkts {
		h := make([]byte, bpfHdrLen)
		binary.LittleEndian.PutUint32(h[8:], uint32(len(p)))
		binary.LittleEndian.PutUint32(h[12:], uint32(len(p)))
		binary.LittleEndian.PutUint16(h[16:], bpfHdrLen)
		rec := append(h, p...)
		for len(rec)%4 != 0 {
			rec = append(rec, 0)
		}
		buf = append(buf, rec...)
	}
	got := split(buf)
	if len(got) != 3 || string(got[0]) != "abcde" || string(got[1]) != "0123456789" || string(got[2]) != "xyz" {
		t.Fatalf("%q", got)
	}
	if got := split(buf[:30]); len(got) != 1 {
		t.Fatalf("обрезанный буфер: %q", got)
	}
}

// Кэш DNS Windows опрашивается раз в 10 секунд: новое — то, чего не было в
// прошлом опросе; первый опрос молчит.
func TestPairsFresh(t *testing.T) {
	a := func(name string, addrs ...string) Answer {
		ans := Answer{Name: name}
		for _, s := range addrs {
			ans.Addrs = append(ans.Addrs, netip.MustParseAddr(s))
		}
		return ans
	}
	known, news := Pairs(nil).Fresh([]Answer{a("old.example.com", "203.0.113.1")})
	if len(news) != 0 {
		t.Fatalf("первый опрос: %+v", news)
	}
	_, news = known.Fresh([]Answer{a("old.example.com", "203.0.113.1", "203.0.113.2"), a("api.example.com", "203.0.113.5")})
	if len(news) != 2 || news[0].Name != "old.example.com" || len(news[0].Addrs) != 1 || news[0].Addrs[0] != netip.MustParseAddr("203.0.113.2") || news[1].Name != "api.example.com" {
		t.Fatalf("второй опрос: %+v", news)
	}
}

// Вывод `scutil --dns` на маке с AmneziaVPN: серверы DNS туннеля.
const scutilDNS = `DNS configuration

resolver #1
  nameserver[0] : 1.1.1.1
  nameserver[1] : 1.0.0.1
  if_index : 37 (utun11)
  flags    : Supplemental, Request A records

resolver #2
  nameserver[0] : 1.1.1.1
  nameserver[1] : fe80::1%en0
  if_index : 37 (utun11)

resolver #3
  domain   : local
  options  : mdns
`

func TestNameservers(t *testing.T) {
	want := []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("1.0.0.1"), netip.MustParseAddr("fe80::1")}
	if got := Nameservers([]byte(scutilDNS)); !slices.Equal(got, want) {
		t.Fatalf("%v", got)
	}
}
