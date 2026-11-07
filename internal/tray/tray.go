// Package tray — значок службы рядом с часами: есть значок — служба отвечает, нет
// значка — не отвечает. Только индикатор: без меню, без действий по щелчку и без
// других состояний, выключенный VPN значок не меняет.
//
// Цикл (Loop) обращений к ОС не делает. Показ — шов Icon: icon_darwin.go,
// icon_windows.go, icon_linux.go.
package tray

import (
	"context"
	"errors"
	"time"
)

// hideAfter — после скольких неудач подряд значок скрывается: один таймаут под
// нагрузкой не значит, что служба упала.
const hideAfter = 3

var (
	// ErrBusy — в этом сеансе значок уже показывает другой экземпляр.
	ErrBusy = errors.New("значок уже показан")
	// ErrNoSession — значок показывать негде и незачем ждать: нет шины сеанса
	// (сервер, вход по SSH) или сеанс закончился.
	ErrNoSession = errors.New("нет шины сеанса")
)

// Icon — показ значка.
type Icon interface {
	// Show показывает значок и сразу возвращается. Канал получает причину, если
	// показ сломался сам; следующий Show поднимает его заново.
	Show() (died <-chan error, err error)
	// Hide убирает значок и дожидается этого.
	Hide()
}

// Loop — значок, который следует за службой.
type Loop struct {
	Icon      Icon
	Alive     func() bool   // служба ответила
	Installed func() bool   // vpnlock ещё установлен
	Every     time.Duration // как часто спрашивать службу и не чаще чего поднимать показ
	Logf      func(format string, args ...any)
}

// Run работает, пока контекст не отменён, vpnlock не удалён или сеанс не кончился.
// На выходе значок скрыт.
func (l Loop) Run(ctx context.Context) {
	tick := time.NewTicker(l.Every)
	defer tick.Stop()
	var (
		died  <-chan error
		shown bool
		last  string
		fails = hideAfter // до первого ответа значка нет
	)
	defer func() {
		if shown {
			l.Icon.Hide()
		}
	}()
	// Показ, который ломается раз за разом, пишет причину один раз, а не каждые 5 с.
	report := func(err error) {
		if err != nil && err.Error() != last {
			last = err.Error()
			l.Logf("значок: %v", err)
		}
	}
	for {
		if l.Alive() {
			fails = 0
		} else {
			fails++
			if !l.Installed() {
				return
			}
		}
		switch up := fails < hideAfter; {
		case up && !shown:
			d, err := l.Icon.Show()
			report(err)
			if errors.Is(err, ErrNoSession) {
				return
			}
			if err == nil {
				died, shown = d, true
			}
		case !up && shown:
			l.Icon.Hide()
			died, shown = nil, false
		}
		// Сломанный показ поднимается на следующем тике, а не сразу: цикла без пауз
		// быть не должно.
		for waiting := true; waiting; {
			select {
			case <-ctx.Done():
				return
			case err := <-died:
				died, shown = nil, false
				report(err)
				if errors.Is(err, ErrNoSession) {
					return
				}
			case <-tick.C:
				waiting = false
			}
		}
	}
}
