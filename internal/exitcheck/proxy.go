package exitcheck

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"appguard/internal/core"
)

// viaProxy достаёт страницу через системный прокси p, как её достала бы
// программа, которая прокси слушается: HTTP-прокси получает CONNECT, SOCKS5 —
// имя узла, так что и имена разрешаются на его стороне. Служба работает от
// root, поэтому порт прокси, закрытый файрволом для всех программ, для неё
// открыт: выход проверяется, пока остальным он закрыт.
func viaProxy(ctx context.Context, p core.Proxy, timeout time.Duration, raw string) ([]byte, error) {
	d := &net.Dialer{Timeout: timeout}
	tr := &http.Transport{
		Proxy:                 http.ProxyURL(&url.URL{Scheme: p.Scheme, Host: p.Endpoint()}),
		DialContext:           d.DialContext,
		DisableKeepAlives:     true, // каждый запрос — через прокси, каким он стал сейчас
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
	}
	defer tr.CloseIdleConnections()
	return get(ctx, tr, raw)
}

// get — запрос GET через транспорт tr: тело ответа 200, не больше maxBody.
func get(ctx context.Context, tr *http.Transport, raw string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json, text/plain")
	resp, err := (&http.Client{Transport: tr}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ответ %s", resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxBody))
}

const maxBody = 16 << 10
