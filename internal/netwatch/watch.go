// Package netwatch — наблюдатель сети: какие туннели VPN есть сейчас, через
// какой интерфейс идёт маршрут по умолчанию и какой системный прокси включён. О
// переменах в туннелях и маршрутах узнаёт сразу — от ядра (routing-сокет на
// macOS, уведомления IP Helper на Windows), о прокси — опросом раз в proxyPoll.
package netwatch

import (
	"context"
	"slices"
	"time"

	"appguard/internal/core"
)

// Сообщения ядра идут пачками: снимок снимается, когда пачка затихла.
const (
	settle = 100 * time.Millisecond
	// Подстраховка на случай, если сообщение ядра о перемене потерялось.
	repoll = 10 * time.Second
)

// Observer — наблюдатель сети системы.
type Observer struct{}

// Watch шлёт снимок сразу, а затем — при каждой перемене, пока не отменён ctx.
func (Observer) Watch(ctx context.Context) <-chan core.Snapshot {
	out := make(chan core.Snapshot, 1)
	changed := make(chan struct{}, 1)
	go listen(ctx, changed)
	go func() {
		defer close(out)
		var last core.Snapshot
		have := false
		who := &listeners{look: listenerOf, now: time.Now}
		emit := func() {
			snap, err := take(who.of)
			if err != nil || (have && equal(last, snap)) {
				return
			}
			last, have = snap, true
			select {
			case out <- snap:
			case <-ctx.Done():
			}
		}
		emit()
		settled := time.NewTimer(time.Hour)
		settled.Stop()
		poll := time.NewTicker(repoll)
		defer poll.Stop()
		proxyTick := time.NewTicker(proxyPoll)
		defer proxyTick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-changed:
				settled.Reset(settle)
			case <-settled.C:
				emit()
			case <-poll.C:
				emit()
			case <-proxyTick.C:
				emit()
			}
		}
	}()
	return out
}

func equal(a, b core.Snapshot) bool {
	return a.DefaultIface == b.DefaultIface && slices.EqualFunc(a.Tunnels, b.Tunnels, func(x, y core.Tunnel) bool {
		return x.Name == y.Name && x.Index == y.Index && slices.Equal(x.Addrs, y.Addrs)
	}) && slices.EqualFunc(a.Proxies, b.Proxies, func(x, y core.Proxy) bool {
		return x.Same(y) && x.Process == y.Process
	})
}

// listenerTTL — сколько помнить, кто слушает порт прокси: lsof дороже scutil,
// а процесс нужен только для людей.
const listenerTTL = 30 * time.Second

// listeners помнит, кто слушает порт, listenerTTL.
type listeners struct {
	seen map[uint16]listener
	look func(port uint16) string
	now  func() time.Time
}

type listener struct {
	name string
	at   time.Time
}

func (l *listeners) of(port uint16) string {
	if v, ok := l.seen[port]; ok && l.now().Sub(v.at) < listenerTTL {
		return v.name
	}
	if l.seen == nil {
		l.seen = map[uint16]listener{}
	}
	name := l.look(port)
	l.seen[port] = listener{name, l.now()}
	return name
}
