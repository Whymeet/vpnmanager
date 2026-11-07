package resolver

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/miekg/dns"

	"vpnlock/internal/bind"
)

// DoH — DNS поверх HTTPS (RFC 8484). Адрес — по IP, чтобы самому DoH не
// нужен был DNS.
type DoH struct {
	Label  string
	URL    string // https://1.1.1.1/dns-query
	Client *http.Client
}

// NewDoH — DoH со своим клиентом: соединение переиспользуется между запросами,
// системный прокси не используется.
func NewDoH(label, url string, timeout time.Duration) *DoH {
	return &DoH{Label: label, URL: url, Client: &http.Client{
		Timeout:   timeout,
		Transport: &http.Transport{Proxy: nil, ForceAttemptHTTP2: true, TLSHandshakeTimeout: timeout, IdleConnTimeout: time.Minute},
	}}
}

func (d *DoH) Name() string { return d.Label }

func (d *DoH) Exchange(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	m := q.Copy()
	m.Id = 0 // RFC 8484: так ответы кэшируются
	body, err := m.Pack()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.URL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := d.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ответ %s", resp.Status)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, dns.MaxMsgSize))
	if err != nil {
		return nil, err
	}
	ans := new(dns.Msg)
	if err := ans.Unpack(raw); err != nil {
		return nil, err
	}
	return ans, nil
}

// Plain — обычный DNS по UDP (TCP, если ответ не влез), с запросом через
// интерфейс, который назовёт Iface. Так российский DNS спрашивается из России,
// мимо VPN: иначе он ответил бы узлами у выхода VPN.
type Plain struct {
	Label string
	Addr  string // 77.88.8.8:53
	// Iface — индекс физического интерфейса сейчас; ok=false — его нет.
	Iface   func() (index int, ok bool)
	Timeout time.Duration
}

func (p *Plain) Name() string { return p.Label }

func (p *Plain) Exchange(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	index, ok := p.Iface()
	if !ok {
		return nil, errors.New("нет физического интерфейса")
	}
	c := &dns.Client{Net: "udp", Timeout: p.Timeout, Dialer: &net.Dialer{Timeout: p.Timeout, Control: bind.Control(index)}}
	ans, _, err := c.ExchangeContext(ctx, q, p.Addr)
	if err == nil && ans.Truncated {
		c.Net = "tcp"
		ans, _, err = c.ExchangeContext(ctx, q, p.Addr)
	}
	return ans, err
}
