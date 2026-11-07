// Package resolver — резолвер защищённых доменов. Система направляет к нему
// имена защищённых сервисов (на macOS — файлами /etc/resolver). Он спрашивает
// шифрованный DNS и параллельно российский, кладёт все адреса из ответов в
// таблицы файрвола и только после этого отвечает программе.
package resolver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Upstream — вышестоящий DNS.
type Upstream interface {
	Name() string
	Exchange(ctx context.Context, q *dns.Msg) (*dns.Msg, error)
}

// Upstreams — откуда брать ответы.
type Upstreams struct {
	// Primary — шифрованный DNS, по очереди до первого ответа. Его ответ уходит
	// программе.
	Primary []Upstream
	// Russian — российский DNS. Его адреса только кладутся в таблицы: так
	// известны узлы сервиса внутри России, к которым VPN-клиент с правилом
	// «Россия напрямую» пошёл бы мимо туннеля.
	Russian []Upstream
}

// Resolver спрашивает вышестоящие и собирает адреса из ответов.
type Resolver struct {
	Up Upstreams
	// RussianWait — сколько ждать российский DNS. Не ответил — ответ программе
	// уходит с адресами шифрованного.
	RussianWait time.Duration

	mu       sync.Mutex
	ruPaused time.Time // до этого момента российский DNS не спрашивается
}

// russianPause — сколько не спрашивать российский DNS после отказа. Если VPN-
// клиент режет трафик мимо туннеля, иначе каждый запрос ждал бы RussianWait.
const russianPause = 30 * time.Second

// Resolve отвечает на запрос q ответом шифрованного DNS и возвращает все
// адреса из него и из ответа российского DNS.
func (r *Resolver) Resolve(ctx context.Context, q *dns.Msg) (*dns.Msg, []netip.Addr, error) {
	ru := make(chan *dns.Msg, 1)
	if len(r.Up.Russian) > 0 && wantsAddrs(q) && r.russianOn() {
		go func() {
			rctx, cancel := context.WithTimeout(ctx, r.RussianWait)
			defer cancel()
			m, err := first(rctx, r.Up.Russian, withoutClientSubnet(q))
			if err != nil {
				r.pauseRussian()
			}
			ru <- m
		}()
	} else {
		ru <- nil
	}
	ans, err := first(ctx, r.Up.Primary, q)
	if err != nil {
		return nil, nil, err
	}
	addrs := Addrs(ans)
	if m := <-ru; m != nil {
		addrs = append(addrs, Addrs(m)...)
	}
	return ans, dedupe(addrs), nil
}

func (r *Resolver) russianOn() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return time.Now().After(r.ruPaused)
}

func (r *Resolver) pauseRussian() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ruPaused = time.Now().Add(russianPause)
}

// Lookup — адреса домена (A и AAAA) из тех же источников, что у Resolve.
func (r *Resolver) Lookup(ctx context.Context, domain string) ([]netip.Addr, error) {
	var all []netip.Addr
	var errs []error
	for _, t := range []uint16{dns.TypeA, dns.TypeAAAA} {
		q := new(dns.Msg)
		q.SetQuestion(dns.Fqdn(domain), t)
		ans, addrs, err := r.Resolve(ctx, q)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if ans.Rcode == dns.RcodeNameError {
			return nil, fmt.Errorf("домена %s нет (NXDOMAIN)", domain)
		}
		all = append(all, addrs...)
	}
	if len(all) == 0 && len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return dedupe(all), nil
}

// first спрашивает вышестоящие по очереди, пока один не ответит.
func first(ctx context.Context, ups []Upstream, q *dns.Msg) (*dns.Msg, error) {
	var errs []error
	for _, u := range ups {
		m, err := u.Exchange(ctx, q)
		if err == nil && m != nil && m.Rcode != dns.RcodeServerFailure && m.Rcode != dns.RcodeRefused {
			return m, nil
		}
		if err == nil {
			err = fmt.Errorf("ответ %s", dns.RcodeToString[m.Rcode])
		}
		errs = append(errs, fmt.Errorf("%s: %w", u.Name(), err))
		if ctx.Err() != nil {
			break
		}
	}
	if len(errs) == 0 {
		return nil, errors.New("вышестоящих DNS нет")
	}
	return nil, errors.Join(errs...)
}

// wantsAddrs — по ответу на такой запрос программа узнаёт адреса: A, AAAA или
// HTTPS/SVCB с подсказками адресов.
func wantsAddrs(q *dns.Msg) bool {
	if len(q.Question) != 1 {
		return false
	}
	switch q.Question[0].Qtype {
	case dns.TypeA, dns.TypeAAAA, dns.TypeHTTPS, dns.TypeSVCB:
		return true
	}
	return false
}

// withoutClientSubnet — копия запроса с ECS /0: российский DNS спрашивается с
// домашнего адреса, и подсеть не должна уйти авторитетным серверам сервиса.
func withoutClientSubnet(q *dns.Msg) *dns.Msg {
	m := q.Copy()
	opt := m.IsEdns0()
	if opt == nil {
		m.SetEdns0(dns.DefaultMsgSize, false)
		opt = m.IsEdns0()
	}
	opt.Option = slices.DeleteFunc(opt.Option, func(o dns.EDNS0) bool { return o.Option() == dns.EDNS0SUBNET })
	opt.Option = append(opt.Option, &dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET, Family: 1, SourceNetmask: 0, Address: net.IPv4zero.To4()})
	return m
}

// Addrs — все адреса, которые программа может взять из ответа: A, AAAA и
// подсказки адресов в записях HTTPS/SVCB.
func Addrs(m *dns.Msg) []netip.Addr {
	if m == nil {
		return nil
	}
	var out []netip.Addr
	add := func(ip net.IP) {
		if a, ok := netip.AddrFromSlice(ip); ok {
			out = append(out, a.Unmap())
		}
	}
	for _, rr := range m.Answer {
		switch v := rr.(type) {
		case *dns.A:
			add(v.A)
		case *dns.AAAA:
			add(v.AAAA)
		case *dns.HTTPS:
			out = append(out, hints(v.Value)...)
		case *dns.SVCB:
			out = append(out, hints(v.Value)...)
		}
	}
	return out
}

func hints(kv []dns.SVCBKeyValue) []netip.Addr {
	var out []netip.Addr
	for _, p := range kv {
		var ips []net.IP
		switch h := p.(type) {
		case *dns.SVCBIPv4Hint:
			ips = h.Hint
		case *dns.SVCBIPv6Hint:
			ips = h.Hint
		}
		for _, ip := range ips {
			if a, ok := netip.AddrFromSlice(ip); ok {
				out = append(out, a.Unmap())
			}
		}
	}
	return out
}

func dedupe(addrs []netip.Addr) []netip.Addr {
	slices.SortFunc(addrs, netip.Addr.Compare)
	return slices.Compact(addrs)
}

// Normalize — имя без точки на конце и в нижнем регистре.
func Normalize(name string) string { return strings.ToLower(strings.TrimSuffix(name, ".")) }

// ValidDomain — годится ли domain в защищённые: обычное имя хоста из букв,
// цифр, дефисов и точек. Из него делается имя файла в /etc/resolver, так что
// ничего постороннего в нём быть не должно.
func ValidDomain(domain string) bool {
	if len(domain) == 0 || len(domain) > 253 || !strings.Contains(domain, ".") || strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
		return false
	}
	for _, label := range strings.Split(domain, ".") {
		if len(label) == 0 || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}
