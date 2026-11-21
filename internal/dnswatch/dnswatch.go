// Package dnswatch — ответы DNS, видные на интерфейсе туннеля: какие имена
// стоят за адресами, к которым ходит приложение. Обучению нужны домены, а
// резолвер службы видит только запросы к уже защищённым доменам — остальные
// имена приложение спрашивает у системы. Служба только слушает входящие ответы
// (BPF на macOS): ничего не меняет, а из услышанного запоминает лишь имена
// адресов, к которым ходило защищённое приложение.
package dnswatch

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/miekg/dns"
	"golang.org/x/net/bpf"

	"appguard/internal/resolver"
)

// Answer — ответ DNS: имя, которое спросили, и адреса из ответа (вместе с
// адресами по цепочке CNAME).
type Answer struct {
	Name  string // без точки в конце, строчными
	Addrs []netip.Addr
	From  netip.Addr // кто ответил: сервер DNS (у кэша Windows — пусто)
}

// Nameservers — серверы DNS из вывода `scutil --dns` (строки
// «nameserver[0] : 1.1.1.1»), без повторов.
func Nameservers(out []byte) []netip.Addr {
	var list []netip.Addr
	for line := range strings.Lines(string(out)) {
		key, val, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok || !strings.HasPrefix(strings.TrimSpace(key), "nameserver[") {
			continue
		}
		if a, err := netip.ParseAddr(strings.TrimSpace(val)); err == nil && !slices.Contains(list, a.WithZone("").Unmap()) {
			list = append(list, a.WithZone("").Unmap())
		}
	}
	return list
}

// Pairs — пары «имя — адрес» одного опроса кэша DNS.
type Pairs map[string]map[netip.Addr]bool

// Fresh — пары из answers, которых не было в прошлом опросе p, и пары этого
// опроса. p == nil — опроса ещё не было: нового нет, когда пришли уже лежащие
// в кэше ответы, не узнать.
func (p Pairs) Fresh(answers []Answer) (Pairs, []Answer) {
	cur := Pairs{}
	var news []Answer
	for _, a := range answers {
		if cur[a.Name] == nil {
			cur[a.Name] = map[netip.Addr]bool{}
		}
		n := Answer{Name: a.Name}
		for _, addr := range a.Addrs {
			cur[a.Name][addr] = true
			if p != nil && !p[a.Name][addr] {
				n.Addrs = append(n.Addrs, addr)
			}
		}
		if len(n.Addrs) > 0 {
			news = append(news, n)
		}
	}
	return cur, news
}

// Канальные уровни, которые понимает фильтр.
const (
	DLTNull   = 0  // utun: 4 байта семейства адресов перед пакетом IP
	DLTEN10MB = 1  // Ethernet
	DLTRaw    = 12 // сразу пакет IP
)

// linkHeader — длина заголовка канального уровня перед пакетом IP.
var linkHeader = map[int]int{DLTNull: 4, DLTEN10MB: 14, DLTRaw: 0}

// snapLen — сколько байт пакета копировать: ответ DNS по UDP целиком.
const snapLen = 0xffff

// Filter — программа BPF для ядра: только UDP с порта 53 (ответы DNS) без
// фрагментов. Остальной трафик туннеля в службу не копируется.
func Filter(dlt int) ([]bpf.RawInstruction, error) {
	off, ok := linkHeader[dlt]
	if !ok {
		return nil, fmt.Errorf("канальный уровень %d не поддерживается", dlt)
	}
	ip := uint32(off) // где начинается пакет IP
	var dispatch []bpf.Instruction
	// Четыре инструкции разбора канального уровня: на IPv6 — к инструкции 11,
	// на IPv4 — к 4, иначе отказ.
	switch dlt {
	case DLTNull, DLTRaw:
		// Версия IP — старшие 4 бита первого байта: порядок байт в заголовке
		// utun тогда не важен.
		dispatch = []bpf.Instruction{
			bpf.LoadAbsolute{Off: ip, Size: 1},
			bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: 0xf0},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x60, SkipTrue: 8},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x40, SkipFalse: 12},
		}
	case DLTEN10MB:
		dispatch = []bpf.Instruction{
			bpf.LoadAbsolute{Off: 12, Size: 2},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x86dd, SkipTrue: 9},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0800, SkipTrue: 1},
			bpf.RetConstant{Val: 0},
		}
	}
	prog := append(dispatch,
		// 4–10: IPv4 — UDP, не фрагмент, порт источника 53.
		bpf.LoadAbsolute{Off: ip + 9, Size: 1},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 17, SkipFalse: 10},
		bpf.LoadAbsolute{Off: ip + 6, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x1fff, SkipTrue: 8},
		bpf.LoadMemShift{Off: ip},
		bpf.LoadIndirect{Off: ip, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 53, SkipTrue: 4, SkipFalse: 5},
		// 11–14: IPv6 — следующий заголовок UDP, порт источника 53.
		bpf.LoadAbsolute{Off: ip + 6, Size: 1},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 17, SkipFalse: 3},
		bpf.LoadAbsolute{Off: ip + 40, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 53, SkipFalse: 1},
		// 15: принять, 16: отказ.
		bpf.RetConstant{Val: snapLen},
		bpf.RetConstant{Val: 0},
	)
	return bpf.Assemble(prog)
}

// Parse — ответ DNS из пакета pkt канального уровня dlt. false — это не
// удачный ответ с адресами.
func Parse(dlt int, pkt []byte) (Answer, bool) {
	off, ok := linkHeader[dlt]
	if !ok {
		return Answer{}, false
	}
	pkt = skip(pkt, off)
	payload, from, ok := udpFrom53(pkt)
	if !ok {
		return Answer{}, false
	}
	var m dns.Msg
	if m.Unpack(payload) != nil || !m.Response || m.Rcode != dns.RcodeSuccess || len(m.Question) != 1 {
		return Answer{}, false
	}
	a := Answer{Name: resolver.Normalize(m.Question[0].Name), From: from}
	for _, rr := range m.Answer {
		var addr netip.Addr
		switch r := rr.(type) {
		case *dns.A:
			addr, _ = netip.AddrFromSlice(r.A.To4())
		case *dns.AAAA:
			addr, _ = netip.AddrFromSlice(r.AAAA.To16())
		}
		if addr.IsValid() {
			a.Addrs = append(a.Addrs, addr.Unmap())
		}
	}
	return a, a.Name != "" && len(a.Addrs) > 0
}

// udpFrom53 — данные датаграммы UDP с порта 53 из пакета IP и адрес
// отправителя.
func udpFrom53(pkt []byte) ([]byte, netip.Addr, bool) {
	if len(pkt) < 1 {
		return nil, netip.Addr{}, false
	}
	var udp []byte
	var from netip.Addr
	switch pkt[0] >> 4 {
	case 4:
		if len(pkt) < 20 || pkt[9] != 17 || binary.BigEndian.Uint16(pkt[6:])&0x1fff != 0 {
			return nil, netip.Addr{}, false
		}
		from = netip.AddrFrom4([4]byte(pkt[12:16]))
		udp = skip(pkt, int(pkt[0]&0x0f)*4)
	case 6:
		if len(pkt) < 40 || pkt[6] != 17 {
			return nil, netip.Addr{}, false
		}
		from = netip.AddrFrom16([16]byte(pkt[8:24])).Unmap()
		udp = skip(pkt, 40)
	default:
		return nil, netip.Addr{}, false
	}
	if len(udp) < 8 || binary.BigEndian.Uint16(udp) != 53 {
		return nil, netip.Addr{}, false
	}
	n := int(binary.BigEndian.Uint16(udp[4:]))
	if n < 8 || n > len(udp) {
		return nil, netip.Addr{}, false
	}
	return udp[8:n], from, true
}

func skip(b []byte, n int) []byte {
	if n > len(b) {
		return nil
	}
	return b[n:]
}

// bpfHdrLen — размер struct bpf_hdr на macOS: время (2×int32), caplen,
// datalen (uint32), hdrlen (uint16).
const bpfHdrLen = 18

// split — пакеты из буфера чтения BPF. Заголовок — в порядке байт машины
// (x86-64 и ARM64 — little-endian); записи выровнены по 4 байта.
func split(buf []byte) [][]byte {
	var pkts [][]byte
	for len(buf) >= bpfHdrLen {
		caplen := int(binary.LittleEndian.Uint32(buf[8:]))
		hdrlen := int(binary.LittleEndian.Uint16(buf[16:]))
		end := hdrlen + caplen
		if hdrlen < bpfHdrLen || end > len(buf) {
			break
		}
		pkts = append(pkts, buf[hdrlen:end])
		next := (end + 3) &^ 3
		if next >= len(buf) {
			break
		}
		buf = buf[next:]
	}
	return pkts
}
