package dnswatch

import (
	"context"
	"fmt"
	"net/netip"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"vpnlock/internal/resolver"
)

// На Windows пакеты так просто не послушать (нужен драйвер), зато ответы,
// которые получила система, лежат в кэше службы DNS-клиента: имена — через
// DnsGetCacheDataTable (её же зовёт ipconfig /displaydns), адреса — запросом
// к кэшу без похода в сеть. Интерфейс, через который пришёл ответ, кэш не
// помнит.

var (
	dnsapi                   = windows.NewLazySystemDLL("dnsapi.dll")
	procDnsGetCacheDataTable = dnsapi.NewProc("DnsGetCacheDataTable")
	procDnsFree              = dnsapi.NewProc("DnsFree")
)

const (
	dnsQueryNoWireQuery = 0x10 // DNS_QUERY_NO_WIRE_QUERY: только кэш
	dnsFreeFlat         = 0    // DnsFreeFlat
	dnsFreeRecordList   = 1    // DnsFreeRecordList
	// cacheEvery — как часто перечитывать кэш.
	cacheEvery = 10 * time.Second
)

// dnsCacheEntry — DNS_CACHE_ENTRY: запись кэша, список по pNext.
type dnsCacheEntry struct {
	next   *dnsCacheEntry
	name   *uint16
	typ    uint16
	length uint16
	flags  uint32
}

// System — ответы DNS живой системы: кэш службы DNS-клиента.
type System struct{}

// Listen раз в cacheEvery отдаёт в got пары «имя — адрес», появившиеся в кэше
// DNS с прошлого опроса, пока не отменён ctx: время ответа — время его
// появления. Первый опрос ничего не отдаёт — когда пришли уже лежащие в кэше
// ответы, не узнать. iface не важен: кэш общий на все интерфейсы.
func (System) Listen(ctx context.Context, _ string, got func(Answer)) error {
	tick := time.NewTicker(cacheEvery)
	defer tick.Stop()
	var known Pairs // пары прошлого опроса; nil — опроса не было
	for {
		answers, err := cached()
		if err != nil {
			return err
		}
		var news []Answer
		known, news = known.Fresh(answers)
		for _, a := range news {
			got(a)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
	}
}

// cached — имена A и AAAA из кэша с адресами.
func cached() ([]Answer, error) {
	if err := procDnsGetCacheDataTable.Find(); err != nil {
		return nil, fmt.Errorf("кэш DNS: %w", err)
	}
	var head *dnsCacheEntry
	if r, _, err := procDnsGetCacheDataTable.Call(uintptr(unsafe.Pointer(&head))); r == 0 {
		if head == nil {
			return nil, nil // кэш пуст
		}
		return nil, fmt.Errorf("кэш DNS: %w", err)
	}
	names := map[string][]uint16{} // имя → типы записей в кэше
	for e := head; e != nil; {
		next := e.next
		if e.name != nil {
			if e.typ == windows.DNS_TYPE_A || e.typ == windows.DNS_TYPE_AAAA {
				n := resolver.Normalize(windows.UTF16PtrToString(e.name))
				names[n] = append(names[n], e.typ)
			}
			procDnsFree.Call(uintptr(unsafe.Pointer(e.name)), dnsFreeFlat)
		}
		procDnsFree.Call(uintptr(unsafe.Pointer(e)), dnsFreeFlat)
		e = next
	}
	var out []Answer
	for name, types := range names {
		a := Answer{Name: name}
		for _, t := range types {
			a.Addrs = append(a.Addrs, lookupCache(name, t)...)
		}
		if name != "" && len(a.Addrs) > 0 {
			out = append(out, a)
		}
	}
	return out, nil
}

// lookupCache — адреса имени из кэша, без запроса в сеть.
func lookupCache(name string, typ uint16) []netip.Addr {
	var rec *windows.DNSRecord
	if windows.DnsQuery(name, typ, dnsQueryNoWireQuery, nil, &rec, nil) != nil {
		return nil
	}
	defer windows.DnsRecordListFree(rec, dnsFreeRecordList)
	var out []netip.Addr
	for r := rec; r != nil; r = r.Next {
		switch r.Type {
		case windows.DNS_TYPE_A:
			out = append(out, netip.AddrFrom4([4]byte(r.Data[:4])))
		case windows.DNS_TYPE_AAAA:
			out = append(out, netip.AddrFrom16([16]byte(r.Data[:16])))
		}
	}
	return out
}
