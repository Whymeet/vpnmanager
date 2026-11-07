package resolver

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// fake — вышестоящий DNS, который отвечает заданными адресами.
type fake struct {
	label string
	addrs []string
	delay time.Duration
	fail  bool
	calls atomic.Int32
	last  *dns.Msg
}

func (f *fake) Name() string { return f.label }

func (f *fake) Exchange(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	f.calls.Add(1)
	f.last = q
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if f.fail {
		return nil, errors.New("молчит")
	}
	m := new(dns.Msg)
	m.SetReply(q)
	for _, s := range f.addrs {
		a := netip.MustParseAddr(s)
		hdr := dns.RR_Header{Name: q.Question[0].Name, Class: dns.ClassINET, Ttl: 60}
		if a.Is4() && q.Question[0].Qtype == dns.TypeA {
			hdr.Rrtype = dns.TypeA
			m.Answer = append(m.Answer, &dns.A{Hdr: hdr, A: a.AsSlice()})
		}
		if a.Is6() && q.Question[0].Qtype == dns.TypeAAAA {
			hdr.Rrtype = dns.TypeAAAA
			m.Answer = append(m.Answer, &dns.AAAA{Hdr: hdr, AAAA: a.AsSlice()})
		}
	}
	return m, nil
}

func query(name string, t uint16) *dns.Msg {
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), t)
	return q
}

func strs(addrs []netip.Addr) []string {
	out := make([]string, len(addrs))
	for i, a := range addrs {
		out[i] = a.String()
	}
	return out
}

func TestAddrsIncludeHTTPSHints(t *testing.T) {
	m := new(dns.Msg)
	hdr := dns.RR_Header{Name: "www.notion.so.", Class: dns.ClassINET, Ttl: 60}
	m.Answer = []dns.RR{
		&dns.CNAME{Hdr: hdr, Target: "cdn.notion.so."},
		&dns.A{Hdr: dns.RR_Header{Name: "cdn.notion.so.", Rrtype: dns.TypeA}, A: net.ParseIP("104.18.0.1")},
		&dns.HTTPS{SVCB: dns.SVCB{Hdr: hdr, Priority: 1, Target: ".", Value: []dns.SVCBKeyValue{
			&dns.SVCBIPv4Hint{Hint: []net.IP{net.ParseIP("104.18.0.2")}},
			&dns.SVCBIPv6Hint{Hint: []net.IP{net.ParseIP("2606:4700::1")}},
		}}},
	}
	got := strs(Addrs(m))
	if !slices.Equal(got, []string{"104.18.0.1", "104.18.0.2", "2606:4700::1"}) {
		t.Fatalf("%v", got)
	}
}

func TestRussianAddressesAreMergedButNotAnswered(t *testing.T) {
	cf := &fake{label: "Cloudflare", addrs: []string{"104.18.0.1"}}
	ru := &fake{label: "Яндекс", addrs: []string{"95.100.0.1"}}
	r := &Resolver{Up: Upstreams{Primary: []Upstream{cf}, Russian: []Upstream{ru}}, RussianWait: time.Second}

	ans, addrs, err := r.Resolve(context.Background(), query("www.notion.so", dns.TypeA))
	if err != nil {
		t.Fatal(err)
	}
	if got := strs(Addrs(ans)); !slices.Equal(got, []string{"104.18.0.1"}) {
		t.Fatalf("программе ушли адреса %v, а должны только шифрованного DNS", got)
	}
	if got := strs(addrs); !slices.Equal(got, []string{"95.100.0.1", "104.18.0.1"}) {
		t.Fatalf("в таблицы идут %v", got)
	}
	// Российский DNS спрашивают без подсети клиента.
	opt := ru.last.IsEdns0()
	if opt == nil || !slices.ContainsFunc(opt.Option, func(o dns.EDNS0) bool {
		s, ok := o.(*dns.EDNS0_SUBNET)
		return ok && s.SourceNetmask == 0
	}) {
		t.Fatalf("запрос к российскому DNS без ECS /0: %v", ru.last)
	}
}

func TestSlowRussianDNSDoesNotHoldTheAnswer(t *testing.T) {
	cf := &fake{label: "Cloudflare", addrs: []string{"104.18.0.1"}}
	ru := &fake{label: "Яндекс", addrs: []string{"95.100.0.1"}, delay: time.Second}
	r := &Resolver{Up: Upstreams{Primary: []Upstream{cf}, Russian: []Upstream{ru}}, RussianWait: 50 * time.Millisecond}

	start := time.Now()
	_, addrs, err := r.Resolve(context.Background(), query("www.notion.so", dns.TypeA))
	if err != nil || time.Since(start) > 500*time.Millisecond {
		t.Fatalf("ответ ждал медленный российский DNS: %v, %v", time.Since(start), err)
	}
	if got := strs(addrs); !slices.Equal(got, []string{"104.18.0.1"}) {
		t.Fatalf("%v", got)
	}
	// После отказа российский DNS какое-то время не спрашивается.
	r.Resolve(context.Background(), query("www.notion.so", dns.TypeA))
	if n := ru.calls.Load(); n != 1 {
		t.Fatalf("после отказа российский DNS спрошен ещё раз (%d)", n)
	}
}

func TestPrimaryFallsBackToSpare(t *testing.T) {
	cf := &fake{label: "Cloudflare", fail: true}
	g := &fake{label: "Google", addrs: []string{"104.18.0.1"}}
	r := &Resolver{Up: Upstreams{Primary: []Upstream{cf, g}}, RussianWait: time.Second}
	_, addrs, err := r.Resolve(context.Background(), query("notion.so", dns.TypeA))
	if err != nil || len(addrs) != 1 {
		t.Fatalf("%v %v", addrs, err)
	}
	cf2 := &fake{label: "Cloudflare", fail: true}
	r = &Resolver{Up: Upstreams{Primary: []Upstream{cf2, &fake{label: "Google", fail: true}}}}
	if _, _, err := r.Resolve(context.Background(), query("notion.so", dns.TypeA)); err == nil {
		t.Fatal("без ответивших вышестоящих нет ошибки")
	}
}

func TestValidDomain(t *testing.T) {
	for d, want := range map[string]bool{
		"notion.so": true, "app.notion.so": true, "my-site.co.uk": true, "xn--80ak6aa92e.com": true,
		"": false, "localhost": false, "../../etc/passwd": false, "a/b.com": false, ".notion.so": false,
		"notion.so.": false, "-x.com": false, "a..b": false, "Notion.so": false, "a b.com": false,
	} {
		if got := ValidDomain(d); got != want {
			t.Errorf("%q: %v, ждали %v", d, got, want)
		}
	}
}
