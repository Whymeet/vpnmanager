package service_test

import (
	"errors"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/miekg/dns"

	"appguard/internal/enforce"
	"appguard/internal/ipc"
	"appguard/internal/resolver"
	"appguard/internal/service/servicetest"
)

// Сценарии таски 04: резолвер защищённых доменов. Программа спрашивает
// резолвер службы; адреса из ответов должны быть в таблицах раньше, чем ответ
// дойдёт до неё.

// withResolver — служба с защищённым notion.so и вышестоящими DNS, которые тест
// настраивает сам.
func withResolver(t *testing.T) *servicetest.Service {
	t.Helper()
	up := servicetest.NewDNS("Cloudflare")
	up.Maps(domain, notion4.String(), notion6.String())
	s := servicetest.Start(t, "", servicetest.Fakes{Accounts: &servicetest.Accounts{Admin: true}, DNS: up})
	s.Protect(t, domain)
	return s
}

func inTables(r enforce.Rules, addrs ...string) bool {
	for _, s := range addrs {
		a := netip.MustParseAddr(s)
		if !slices.Contains(r.V4, a) && !slices.Contains(r.V6, a) {
			return false
		}
	}
	return true
}

func TestAddressesReachTablesBeforeTheAnswer(t *testing.T) {
	s := withResolver(t)
	s.DNS.Maps("www.notion.so", "104.18.0.9")

	ans := s.Ask(t, "www.notion.so", dns.TypeA)
	if got := resolver.Addrs(ans); len(got) != 1 || got[0].String() != "104.18.0.9" {
		t.Fatalf("ответ %v", ans)
	}
	// Ответ уже пришёл — значит, адрес уже в таблицах, без ожидания.
	if r := s.Enforce.Rules(); !inTables(r, "104.18.0.9") || len(r.OpenIfaces) != 0 {
		t.Fatalf("ответ пришёл раньше, чем адрес попал в закрытые таблицы: %+v", r)
	}
}

func TestRussianDNSAddressesAlsoReachTables(t *testing.T) {
	s := withResolver(t)
	s.DNS.Maps("www.notion.so", "104.18.0.9")
	s.RussianDNS.Maps("www.notion.so", "95.100.0.1") // узел сервиса внутри России

	ans := s.Ask(t, "www.notion.so", dns.TypeA)
	if got := resolver.Addrs(ans); len(got) != 1 || got[0].String() != "104.18.0.9" {
		t.Fatalf("программе ушёл не ответ шифрованного DNS: %v", got)
	}
	if r := s.Enforce.Rules(); !inTables(r, "104.18.0.9", "95.100.0.1") {
		t.Fatalf("адреса российского DNS не в таблицах: %+v", r)
	}
}

func TestNewSubdomainIsClosedFromTheFirstQuery(t *testing.T) {
	s := withResolver(t)
	s.DNS.Maps("brand-new.api.notion.so", "104.18.7.7")

	s.Ask(t, "brand-new.api.notion.so", dns.TypeA)
	if r := s.Enforce.Rules(); !inTables(r, "104.18.7.7") || len(r.OpenIfaces) != 0 {
		t.Fatalf("новый поддомен не закрыт с первого запроса: %+v", r)
	}
}

func TestIPv6FromAnswersReachTables(t *testing.T) {
	s := withResolver(t)
	s.DNS.Maps("www.notion.so", "2606:4700::6812:99")

	s.Ask(t, "www.notion.so", dns.TypeAAAA)
	if r := s.Enforce.Rules(); !slices.Contains(r.V6, netip.MustParseAddr("2606:4700::6812:99")) {
		t.Fatalf("IPv6 не в таблицах: %+v", r)
	}
}

// Имя вне защищённых доменов приходит сюда, только пока система не перечитала
// /etc/resolver после снятия защиты. Его надо разрешить, но в таблицы не класть.
func TestNamesOutsideProtectedDomainsAreForwardedNotLearned(t *testing.T) {
	s := withResolver(t)
	s.DNS.Maps("google.com", "142.250.0.1")
	s.DNS.Maps("evilnotion.so", "203.0.113.66")
	for name, addr := range map[string]string{"google.com": "142.250.0.1", "evilnotion.so": "203.0.113.66"} {
		ans := s.Ask(t, name, dns.TypeA)
		if got := resolver.Addrs(ans); len(got) != 1 || got[0].String() != addr {
			t.Fatalf("%s: %v", name, ans)
		}
		if r := s.Enforce.Rules(); inTables(r, addr) {
			t.Fatalf("адрес незащищённого %s попал в таблицы", name)
		}
	}
}

func TestNoAnswerWithoutTables(t *testing.T) {
	s := withResolver(t)
	s.DNS.Maps("www.notion.so", "104.18.0.9")

	s.Enforce.Fail(errors.New("pf недоступен"))
	if ans := s.Ask(t, "www.notion.so", dns.TypeA); ans.Rcode != dns.RcodeServerFailure || len(ans.Answer) > 0 {
		t.Fatalf("адрес ушёл программе, хотя в таблицы не попал: %v", ans)
	}
	s.Enforce.Fail(nil)

	s.DNS.Down(true)
	if ans := s.Ask(t, "other.notion.so", dns.TypeA); ans.Rcode != dns.RcodeServerFailure {
		t.Fatalf("без шифрованного DNS: %v", ans)
	}
}

func TestSystemResolversFollowProtectedDomains(t *testing.T) {
	s := withResolver(t)
	if got := s.SystemDNS.Domains(); !slices.Equal(got, []string{domain}) {
		t.Fatalf("на службу направлены %v", got)
	}
	if resp, err := ipc.Call(s.Layout.Socket, ipc.Request{Cmd: ipc.CmdUnprotect, Domain: domain}); err != nil || !resp.OK {
		t.Fatalf("%v %+v", err, resp)
	}
	if got := s.SystemDNS.Domains(); len(got) != 0 {
		t.Fatalf("после снятия защиты на службу направлены %v", got)
	}
	if resp := call(t, s, ipc.CmdUninstall); !resp.OK || !s.SystemDNS.Cleared() {
		t.Fatalf("удаление не убрало доменные резолверы: %+v", resp)
	}
}

func TestForeignResolverIsJournaled(t *testing.T) {
	up := servicetest.NewDNS("Cloudflare")
	up.Maps(domain, notion4.String())
	sys := &servicetest.SystemDNS{}
	sys.Foreign(domain)
	s := servicetest.Start(t, "", servicetest.Fakes{Accounts: &servicetest.Accounts{Admin: true}, DNS: up, SystemDNS: sys})
	s.Protect(t, domain)
	hasLine(t, s, "для notion.so в /etc/resolver уже есть чужой файл")
}

func TestLearnedAddressesSurviveRestart(t *testing.T) {
	root := t.TempDir()
	up := servicetest.NewDNS("Cloudflare")
	up.Maps(domain, notion4.String())
	up.Maps("cdn.notion.so", "104.18.5.5")
	s := servicetest.Start(t, root, servicetest.Fakes{Accounts: &servicetest.Accounts{Admin: true}, DNS: up})
	s.Protect(t, domain)
	s.Ask(t, "cdn.notion.so", dns.TypeA)
	s.Stop()

	again := servicetest.Start(t, root, servicetest.Fakes{})
	waitRules(t, again, time.Second, func(r enforce.Rules) bool { return inTables(r, notion4.String(), "104.18.5.5") })
}

func TestProtectRejectsWhatIsNotADomain(t *testing.T) {
	s := servicetest.Start(t, "", servicetest.Fakes{Accounts: &servicetest.Accounts{Admin: true}})
	for _, bad := range []string{"../../etc/passwd", "localhost", "a b.com"} {
		resp, err := ipc.Call(s.Layout.Socket, ipc.Request{Cmd: ipc.CmdProtect, Domain: bad})
		if err != nil || resp.OK {
			t.Fatalf("%q принят: %v %+v", bad, err, resp)
		}
	}
	if got := s.SystemDNS.Domains(); len(got) != 0 {
		t.Fatalf("на службу направлены %v", got)
	}
}

// Запросы к резолверу службы по петле режет чужой файрвол (клиент VPN с
// защитой от утечек DNS): защищённые домены снимаются с системы — имена
// разрешает её DNS, а не никто. Резолвер вернулся — домены снова на службе.
func TestBlockedResolverHandsDomainsToSystemDNS(t *testing.T) {
	s := withResolver(t)
	waitDomains := func(want []string) {
		t.Helper()
		deadline := time.Now().Add(2 * time.Second)
		for !slices.Equal(s.SystemDNS.Domains(), want) {
			if time.Now().After(deadline) {
				t.Fatalf("на резолвер службы направлены %v, ждали %v", s.SystemDNS.Domains(), want)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	waitDomains([]string{domain})

	s.ResolverDown.Store(true)
	waitDomains(nil)
	hasLine(t, s, "резолвер службы не отвечает")
	waitRules(t, s, time.Second, func(r enforce.Rules) bool { return inTables(r, notion4.String()) }) // адреса в таблицах остаются

	s.ResolverDown.Store(false)
	waitDomains([]string{domain})
	hasLine(t, s, "резолвер службы снова отвечает")
}
