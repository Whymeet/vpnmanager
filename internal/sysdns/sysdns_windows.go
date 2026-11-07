// Package sysdns направляет имена защищённых доменов на резолвер службы. На
// Windows это таблица политики разрешения имён (NRPT): служба DNS Windows
// шлёт запросы домена и всех его поддоменов на указанный сервер, даже если VPN
// выставил свои DNS.
package sysdns

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// Ключи NRPT в реестре: локальная таблица и таблица групповой политики. Если
// таблица политики не пуста, локальную Windows не читает.
const (
	nrptLocal  = `SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig`
	nrptPolicy = `SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig`
)

// marker — значение Comment у наших правил: по нему удаление узнаёт своё и не
// трогает чужое.
const marker = "vpnlock"

// nrptUseServers — ConfigOptions «спрашивать указанные серверы DNS».
const nrptUseServers = 0x8

// NRPT — правила vpnlock в таблице политики разрешения имён.
type NRPT struct {
	// Server — где слушает резолвер службы. Порта NRPT не знает: только 53.
	Server netip.Addr
}

// System — правила на живой системе. Резолвер службы должен слушать addr на
// порту 53.
func System(addr netip.AddrPort) NRPT { return NRPT{Server: addr.Addr()} }

// Set направляет на службу ровно эти домены: правила пишет, свои лишние
// удаляет. Домен, на который уже есть чужое правило, не трогает и возвращает в
// skipped.
func (n NRPT) Set(domains []string) (skipped []string, err error) {
	if policyRules() {
		return nil, errors.New("правила NRPT задаёт групповая политика, и свои Windows не читает — защищённые домены идут мимо службы")
	}
	root, _, err := registry.CreateKey(registry.LOCAL_MACHINE, nrptLocal, registry.ALL_ACCESS)
	if err != nil {
		return nil, fmt.Errorf("NRPT: %w", err)
	}
	defer root.Close()
	ours, foreign, err := rules(root)
	if err != nil {
		return nil, err
	}
	var use []string
	for _, d := range domains {
		if coveredBy(foreign, d) {
			skipped = append(skipped, d)
		} else {
			use = append(use, d)
		}
	}
	want := map[string][]string{}
	for i, names := range nrptChunks(use) {
		want[ruleKey(i)] = names
	}
	changed := false
	for _, id := range ours {
		if _, ok := want[id]; !ok {
			if err := registry.DeleteKey(root, id); err != nil {
				return skipped, fmt.Errorf("NRPT: %w", err)
			}
			changed = true
		}
	}
	server := n.Server.String()
	for id, names := range want {
		if same(root, id, names, server) {
			continue
		}
		if err := writeRule(root, id, names, server); err != nil {
			return skipped, err
		}
		changed = true
	}
	if changed {
		flushCache()
	}
	return skipped, nil
}

// Clear убирает все правила vpnlock.
func (n NRPT) Clear() error {
	root, err := registry.OpenKey(registry.LOCAL_MACHINE, nrptLocal, registry.ALL_ACCESS)
	if errors.Is(err, registry.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("NRPT: %w", err)
	}
	defer root.Close()
	ours, _, err := rules(root)
	if err != nil {
		return err
	}
	var errs []error
	for _, id := range ours {
		if err := registry.DeleteKey(root, id); err != nil {
			errs = append(errs, fmt.Errorf("NRPT: %w", err))
		}
	}
	if len(ours) > 0 {
		flushCache()
	}
	return errors.Join(errs...)
}

// rules — правила таблицы: наши (по метке) и домены чужих.
func rules(root registry.Key) (ours, foreign []string, err error) {
	ids, err := root.ReadSubKeyNames(-1)
	if err != nil {
		return nil, nil, fmt.Errorf("NRPT: %w", err)
	}
	for _, id := range ids {
		k, err := registry.OpenKey(root, id, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		comment, _, _ := k.GetStringValue("Comment")
		names, _, _ := k.GetStringsValue("Name")
		k.Close()
		if comment == marker {
			ours = append(ours, id)
		} else {
			foreign = append(foreign, names...)
		}
	}
	return ours, foreign, nil
}

// same — правило id уже такое, как нужно.
func same(root registry.Key, id string, names []string, server string) bool {
	k, err := registry.OpenKey(root, id, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	cur, _, err1 := k.GetStringsValue("Name")
	srv, _, err2 := k.GetStringValue("GenericDNSServers")
	return err1 == nil && err2 == nil && srv == server && slices.Equal(cur, names)
}

func writeRule(root registry.Key, id string, names []string, server string) error {
	k, _, err := registry.CreateKey(root, id, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("NRPT: %w", err)
	}
	defer k.Close()
	err = errors.Join(
		k.SetDWordValue("Version", 1),
		k.SetStringsValue("Name", names),
		k.SetStringValue("GenericDNSServers", server),
		k.SetDWordValue("ConfigOptions", nrptUseServers),
		k.SetStringValue("IPSECCARestriction", ""),
		k.SetStringValue("Comment", marker),
	)
	if err != nil {
		return fmt.Errorf("NRPT: %w", err)
	}
	return nil
}

// openLocal открывает локальную таблицу NRPT.
func openLocal() (registry.Key, error) {
	return registry.OpenKey(registry.LOCAL_MACHINE, nrptLocal, registry.QUERY_VALUE|registry.ENUMERATE_SUB_KEYS)
}

// policyRules — в таблице групповой политики есть правила.
func policyRules() bool {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, nrptPolicy, registry.READ)
	if err != nil {
		return false
	}
	defer k.Close()
	ids, err := k.ReadSubKeyNames(1)
	return err == nil && len(ids) > 0
}

// ruleKey — имя раздела правила номер i: постоянный GUID, как у правил,
// которые заводит сама Windows.
func ruleKey(i int) string {
	sum := sha256.Sum256([]byte("vpnlock nrpt " + strconv.Itoa(i)))
	g := windows.GUID{
		Data1: binary.LittleEndian.Uint32(sum[0:4]),
		Data2: binary.LittleEndian.Uint16(sum[4:6]),
		Data3: binary.LittleEndian.Uint16(sum[6:8]),
	}
	copy(g.Data4[:], sum[8:16])
	return g.String()
}

var procFlushCache = windows.NewLazySystemDLL("dnsapi.dll").NewProc("DnsFlushResolverCache")

// flushCache сбрасывает кэш DNS Windows: ответы, полученные до правил, не
// должны жить мимо службы.
func flushCache() { procFlushCache.Call() }
