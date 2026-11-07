//go:build live

// Живая проверка NRPT на стенде Windows — из PowerShell от имени
// администратора: go test -tags live -v ./internal/sysdns
// Правило ставится на домен vpnlock-live.test и снимается в конце.

package sysdns

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sys/windows"
)

func TestLiveNRPTSendsDomainToService(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("нужен PowerShell от имени администратора")
	}
	addr := netip.MustParseAddrPort("127.53.53.53:53")
	answer := netip.MustParseAddr("192.0.2.77")
	srv := &dns.Server{Addr: addr.String(), Net: "udp", Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(q)
		if len(q.Question) == 1 && q.Question[0].Qtype == dns.TypeA {
			m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 5}, A: answer.AsSlice()})
		}
		w.WriteMsg(m)
	})}
	go srv.ListenAndServe()
	defer srv.Shutdown()

	n := System(addr)
	t.Cleanup(func() {
		if err := n.Clear(); err != nil {
			t.Errorf("Clear: %v", err)
		}
	})
	skipped, err := n.Set([]string{"vpnlock-live.test"})
	if err != nil || len(skipped) > 0 {
		t.Fatalf("Set: %v, пропущены %v", err, skipped)
	}
	time.Sleep(time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	got, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", "www.vpnlock-live.test")
	if err != nil || len(got) == 0 || got[0] != answer {
		t.Fatalf("имя ушло мимо службы: %v %v", got, err)
	}
	if err := n.Clear(); err != nil {
		t.Fatal(err)
	}
	ours, _, _ := func() ([]string, []string, error) {
		k, err := openLocal()
		if err != nil {
			return nil, nil, err
		}
		defer k.Close()
		return rules(k)
	}()
	if len(ours) > 0 {
		t.Fatalf("после Clear остались правила %v", ours)
	}
}
