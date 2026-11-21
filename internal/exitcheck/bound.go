package exitcheck

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"time"

	"appguard/internal/bind"
	"appguard/internal/core"
)

// Bound — запросы через интерфейс туннеля. Привязка сокета к интерфейсу
// (IP_BOUND_IF на macOS, IP_UNICAST_IF на Windows) не даёт ядру увести
// соединение в физический интерфейс, даже если туннель не работает: тогда
// запрос просто не проходит. Имена разрешаются тоже через туннель — у DNS
// Cloudflare, а не у системного резолвера. Путь через системный прокси
// проверяется через сам прокси.
type Bound struct {
	Timeout time.Duration
}

func (b Bound) Get(ctx context.Context, t core.Tunnel, url string) ([]byte, error) {
	if t.Proxy != nil {
		return viaProxy(ctx, *t.Proxy, b.Timeout, url)
	}
	network, dns := "tcp6", "[2606:4700:4700::1111]:53"
	for _, a := range t.Addrs {
		if a.Is4() {
			network, dns = "tcp4", "1.1.1.1:53"
			break
		}
	}
	d := &net.Dialer{Timeout: b.Timeout, Control: bind.Control(t.Index)}
	d.Resolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, proto, _ string) (net.Conn, error) {
			return d.DialContext(ctx, proto, dns)
		},
	}
	tr := &http.Transport{
		Proxy: nil, // проверяется сам туннель: системный прокси — отдельный путь
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			return d.DialContext(ctx, network, addr)
		},
		DisableKeepAlives:     true, // каждое соединение — через туннель, каким он стал сейчас
		TLSHandshakeTimeout:   b.Timeout,
		ResponseHeaderTimeout: b.Timeout,
	}
	defer tr.CloseIdleConnections()
	return get(ctx, tr, url)
}

// Reach соединяется с to только через интерфейс via и сразу закрывает
// соединение. Отказ (RST) — тоже ответ: пакет дошёл до узла, значит, мимо via
// ничего не держит. Файрвол отбрасывает молча, и закрытый адрес — это тишина до
// таймаута контекста.
func Reach(ctx context.Context, via core.Tunnel, to netip.AddrPort) error {
	network := "tcp4"
	if to.Addr().Is6() {
		network = "tcp6"
	}
	d := &net.Dialer{Control: bind.Control(via.Index)}
	c, err := d.DialContext(ctx, network, to.String())
	if refused(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer c.Close()
	// macOS сообщает об успешном соединении и тогда, когда pf отбросил первый
	// же пакет (замечено на IPv6 без глобального адреса): у такого сокета нет
	// собеседника, и в сеть ничего не ушло.
	if !connected(c) {
		return errNotConnected
	}
	return nil
}

var errNotConnected = errors.New("соединение не установлено: собеседника у сокета нет")
