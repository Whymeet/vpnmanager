// Package exitcheck — проверка выхода: откуда на самом деле выходит трафик
// туннеля. Адрес и страну сообщают два независимых источника — Cloudflare trace
// и первый ответивший из запасного списка; их ответы сводит core.Judge.
package exitcheck

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"vpnlock/internal/core"
)

// Fetcher достаёт страницу запросом, который уходит только через интерфейс
// туннеля.
type Fetcher interface {
	Get(ctx context.Context, t core.Tunnel, url string) ([]byte, error)
}

type source struct {
	name  string
	url   string
	parse func([]byte) (netip.Addr, string, error)
}

// Cloudflare trace — по адресам, без DNS.
var cloudflare = []source{
	{"Cloudflare", "https://1.1.1.1/cdn-cgi/trace", parseTrace},
	{"Cloudflare", "https://1.0.0.1/cdn-cgi/trace", parseTrace},
}

// Запасной список второго источника: у каждого своя база адресов.
var second = []source{
	{"ipinfo", "https://ipinfo.io/json", parseJSON("ip", "country")},
	{"country.is", "https://api.country.is/", parseJSON("ip", "country")},
	{"ipwho.is", "https://ipwho.is/", parseJSON("ip", "country_code")},
}

// FixedAddrs — адреса, к которым проверка ходит напрямую по IP, без DNS.
func FixedAddrs() []netip.Addr {
	var out []netip.Addr
	urls := russian
	for _, s := range append(slices.Clone(cloudflare), second...) {
		urls = append(slices.Clone(urls), s.url)
	}
	for _, raw := range urls {
		if u, err := url.Parse(raw); err == nil {
			if a, err := netip.ParseAddr(u.Hostname()); err == nil {
				out = append(out, a)
			}
		}
	}
	return out
}

// FixedNames — имена, к которым проверка ходит сама: запасные источники и зонд
// «Россия напрямую».
func FixedNames() []string {
	var out []string
	urls := slices.Clone(russian)
	for _, s := range second {
		urls = append(urls, s.url)
	}
	for _, raw := range urls {
		if u, err := url.Parse(raw); err == nil {
			if _, err := netip.ParseAddr(u.Hostname()); err != nil {
				out = append(out, u.Hostname())
			}
		}
	}
	return out
}

// confirmTTL — сколько помнить ответ второго источника об адресе. Пока адрес
// выхода тот же, страна у него та же, и спрашивать второй источник каждые
// несколько секунд незачем: у бесплатных сервисов есть лимиты.
const confirmTTL = time.Hour

// Checker проверяет выходы туннелей.
type Checker struct {
	Fetch Fetcher
	Now   func() time.Time

	mu        sync.Mutex
	confirmed map[netip.Addr]confirmation
}

type confirmation struct {
	answer core.Answer
	at     time.Time
}

// Check проверяет выход туннеля t. Пока оба источника не ответили и не
// сошлись, выход не проверен.
func (c *Checker) Check(ctx context.Context, t core.Tunnel) core.Check {
	a, err := c.ask(ctx, t, cloudflare)
	if err != nil {
		return core.Failed("Cloudflare не ответил")
	}
	b, ok := c.recall(a.IP)
	if !ok {
		if b, err = c.ask(ctx, t, second); err != nil {
			return core.Failed("второй источник не ответил")
		}
		c.remember(a.IP, b)
	}
	return core.Judge(a, b)
}

// ask спрашивает источники по очереди, пока один не ответит.
func (c *Checker) ask(ctx context.Context, t core.Tunnel, sources []source) (core.Answer, error) {
	var errs []error
	for _, s := range sources {
		body, err := c.Fetch.Get(ctx, t, s.url)
		if err == nil {
			var ip netip.Addr
			var country string
			if ip, country, err = s.parse(body); err == nil {
				return core.Answer{Source: s.name, IP: ip, Country: country}, nil
			}
		}
		errs = append(errs, fmt.Errorf("%s: %w", s.name, err))
		if ctx.Err() != nil {
			break
		}
	}
	return core.Answer{}, errors.Join(errs...)
}

func (c *Checker) recall(ip netip.Addr) (core.Answer, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	conf, ok := c.confirmed[ip]
	if !ok || c.Now().Sub(conf.at) > confirmTTL {
		return core.Answer{}, false
	}
	return conf.answer, true
}

func (c *Checker) remember(ip netip.Addr, a core.Answer) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.confirmed == nil {
		c.confirmed = map[netip.Addr]confirmation{}
	}
	now := c.Now()
	for k, v := range c.confirmed {
		if now.Sub(v.at) > confirmTTL {
			delete(c.confirmed, k)
		}
	}
	c.confirmed[ip] = confirmation{answer: a, at: now}
}

// parseTrace разбирает ответ Cloudflare trace: строки key=value, нужны ip и loc.
func parseTrace(body []byte) (netip.Addr, string, error) {
	var ip, loc string
	sc := bufio.NewScanner(bytes.NewReader(body))
	for sc.Scan() {
		k, v, _ := strings.Cut(sc.Text(), "=")
		switch k {
		case "ip":
			ip = v
		case "loc":
			loc = v
		}
	}
	return parsed(ip, loc)
}

// parseJSON — разбор JSON-ответа с адресом в поле ipKey и кодом страны в countryKey.
func parseJSON(ipKey, countryKey string) func([]byte) (netip.Addr, string, error) {
	return func(body []byte) (netip.Addr, string, error) {
		var m map[string]any
		if err := json.Unmarshal(body, &m); err != nil {
			return netip.Addr{}, "", err
		}
		ip, _ := m[ipKey].(string)
		country, _ := m[countryKey].(string)
		return parsed(ip, country)
	}
}

func parsed(ip, country string) (netip.Addr, string, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return netip.Addr{}, "", fmt.Errorf("нет адреса в ответе: %q", ip)
	}
	country = strings.ToUpper(strings.TrimSpace(country))
	if len(country) != 2 {
		return netip.Addr{}, "", fmt.Errorf("нет страны в ответе: %q", country)
	}
	return addr.Unmap(), country, nil
}

// russian — российские сервисы определения адреса для зонда «Россия напрямую».
// Их серверы в России: клиент VPN с таким правилом отправит запрос к ним мимо
// туннеля, и сервис увидит домашний адрес.
var russian = []string{
	"https://ipv4-internet.yandex.net/api/v0/ip",
	"https://yandex.ru/internet/api/v0/ip",
}

// Probe — зонд «Россия напрямую» туннеля t с проверенным выходом exit. Тем же
// путём, что проверка выхода, спрашивается российский сервис: видит адрес
// выхода — правила нет. Видит что-то другое — тот же сервис спрашивается через
// физический интерфейс (physical; ok=false — его нет), и если он видит там то
// же самое, значит, клиент VPN отправил запрос мимо туннеля.
func (c *Checker) Probe(ctx context.Context, t core.Tunnel, exit core.Exit, physical core.Tunnel, ok bool) core.Probe {
	seen, err := c.askIP(ctx, t)
	if err != nil {
		return core.Probe{State: core.ProbeUnavailable}
	}
	if seen == exit.IP {
		return core.Probe{State: core.ProbeThrough, Seen: seen}
	}
	if !ok {
		return core.Probe{State: core.ProbeUnavailable, Seen: seen}
	}
	home, err := c.askIP(ctx, physical)
	if err != nil {
		return core.Probe{State: core.ProbeUnavailable, Seen: seen}
	}
	if seen == home {
		return core.Probe{State: core.ProbeDirect, Seen: seen, Home: home}
	}
	// Третий адрес — у VPN бывает несколько выходов; домашнего российский
	// сервис не видел, значит, правила «Россия напрямую» нет.
	return core.Probe{State: core.ProbeThrough, Seen: seen, Home: home}
}

// askIP спрашивает российские сервисы по очереди, пока один не ответит адресом.
func (c *Checker) askIP(ctx context.Context, t core.Tunnel) (netip.Addr, error) {
	var errs []error
	for _, url := range russian {
		body, err := c.Fetch.Get(ctx, t, url)
		if err == nil {
			var s string
			if err = json.Unmarshal(body, &s); err == nil {
				var ip netip.Addr
				if ip, err = netip.ParseAddr(strings.TrimSpace(s)); err == nil {
					return ip.Unmap(), nil
				}
			}
		}
		errs = append(errs, err)
		if ctx.Err() != nil {
			break
		}
	}
	return netip.Addr{}, errors.Join(errs...)
}
