package exitcheck

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"vpnlock/internal/core"
)

// pages — ответы по адресу; нет адреса — источник не отвечает.
type pages map[string]string

func (p pages) Get(_ context.Context, _ core.Tunnel, url string) ([]byte, error) {
	body, ok := p[url]
	if !ok {
		return nil, errors.New("нет ответа")
	}
	return []byte(body), nil
}

// Форматы — как отвечают сами сервисы.
const (
	trace     = "fl=12f1\nh=1.1.1.1\nip=185.1.2.3\nts=1760000000.1\nvisit_scheme=https\nuag=Go-http-client/1.1\ncolo=FRA\nsliver=none\nhttp=http/1.1\nloc=DE\ntls=TLSv1.3\nsni=off\nwarp=off\ngateway=off\nrbi=off\nkex=X25519\n"
	ipinfo    = `{"ip": "185.1.2.3", "city": "Frankfurt am Main", "region": "Hesse", "country": "DE", "org": "AS0 Example"}`
	countryIs = `{"ip":"185.1.2.3","country":"DE"}`
	ipwhois   = `{"ip":"185.1.2.3","success":true,"type":"IPv4","country":"Germany","country_code":"DE"}`
)

var tun = core.Tunnel{Name: "utun11", Index: 40, Addrs: []netip.Addr{netip.MustParseAddr("10.8.1.1")}}

func checker(p pages) *Checker { return &Checker{Fetch: p, Now: time.Now} }

func TestEachSecondSourceIsParsed(t *testing.T) {
	for _, s := range second {
		body := map[string]string{"ipinfo": ipinfo, "country.is": countryIs, "ipwho.is": ipwhois}[s.name]
		ip, country, err := s.parse([]byte(body))
		if err != nil || ip.String() != "185.1.2.3" || country != "DE" {
			t.Errorf("%s: %v %q %v", s.name, ip, country, err)
		}
	}
	ip, country, err := parseTrace([]byte(trace))
	if err != nil || ip.String() != "185.1.2.3" || country != "DE" {
		t.Fatalf("trace: %v %q %v", ip, country, err)
	}
}

func TestFallsBackToSpareSources(t *testing.T) {
	c := checker(pages{
		"https://1.0.0.1/cdn-cgi/trace": trace, // 1.1.1.1 молчит
		"https://ipwho.is/":             ipwhois,
	})
	got := c.Check(context.Background(), tun)
	if got.Outcome != core.Verified || got.Exit.IP.String() != "185.1.2.3" {
		t.Fatalf("%+v", got)
	}
}

func TestBrokenAnswerCountsAsSilence(t *testing.T) {
	c := checker(pages{
		"https://1.1.1.1/cdn-cgi/trace": "<html>captive portal</html>",
		"https://ipinfo.io/json":        ipinfo,
	})
	if got := c.Check(context.Background(), tun); got.Outcome != core.Unverified || !strings.Contains(got.Detail, "Cloudflare") {
		t.Fatalf("%+v", got)
	}
}

func TestSecondSourceIsAskedAgainAfterAnHour(t *testing.T) {
	now := time.Now()
	asked := 0
	p := pages{"https://1.1.1.1/cdn-cgi/trace": trace}
	c := &Checker{Fetch: fetchFunc(func(url string) ([]byte, error) {
		if url == "https://ipinfo.io/json" {
			asked++
			return []byte(ipinfo), nil
		}
		return p.Get(context.Background(), tun, url)
	}), Now: func() time.Time { return now }}

	c.Check(context.Background(), tun)
	c.Check(context.Background(), tun)
	if asked != 1 {
		t.Fatalf("второй источник спрошен %d раз про один адрес", asked)
	}
	now = now.Add(confirmTTL + time.Minute)
	c.Check(context.Background(), tun)
	if asked != 2 {
		t.Fatal("через час второй источник не спрошен снова")
	}
}

type fetchFunc func(url string) ([]byte, error)

func (f fetchFunc) Get(_ context.Context, _ core.Tunnel, url string) ([]byte, error) { return f(url) }
