// Package tray — значок службы рядом с часами: есть значок — служба отвечает, нет
// значка — не отвечает. Картинка говорит, открыта ли защита: щит с замком —
// защищённые приложения в сети, перечёркнутый щит — без сети. По щелчку — меню:
// короткий заголовок, под ним выход или причина закрытия, и пункт «Уведомления»,
// который их включает и выключает (на macOS — переключатель, на Windows и Linux —
// отметка: переключателя в их меню значков нет).
//
// Цикл (Loop) обращений к ОС не делает. Показ — шов Icon: icon_darwin.go,
// icon_windows.go, icon_linux.go.
package tray

import (
	"context"
	"errors"
	"fmt"
	"time"
	"unicode"
	"unicode/utf8"

	"appguard/internal/core"
	"appguard/internal/ipc"
)

// hideAfter — после скольких неудач подряд значок скрывается: один таймаут под
// нагрузкой не значит, что служба упала.
const hideAfter = 3

// NotifyItem — пункт меню, который включает и выключает уведомления.
const NotifyItem = "Уведомления"

// VPNItem — пункт меню, который открывает окно «Мои VPN». Показывается, если
// задан OpenVPN (сейчас — только на Windows).
const VPNItem = "Мои VPN…"

// OpenVPN открывает окно «Мои VPN». Вызывается из потока окна значка, поэтому
// не должен ждать: запустил окно и вернулся.
var OpenVPN func()

var (
	// ErrBusy — в этом сеансе значок уже показывает другой экземпляр.
	ErrBusy = errors.New("значок уже показан")
	// ErrNoSession — значок показывать негде и незачем ждать: нет шины сеанса
	// (сервер, вход по SSH) или сеанс закончился.
	ErrNoSession = errors.New("нет шины сеанса")
)

// View — что показывает значок. Меню короткое: заголовок и строка под ним.
type View struct {
	Open   bool   // защищённые приложения в сети: щит с замком; нет — перечёркнутый
	Title  string // «Приложения в сети» или «Приложения без сети»
	Detail string // выход с адресом и страной или причина закрытия
	Notify bool   // уведомления включены: пункт «Уведомления» включён
}

// Tip — подсказка при наведении.
func (v View) Tip() string {
	tip := "appguard\n" + v.Title
	if v.Detail != "" {
		tip += "\n" + v.Detail
	}
	return tip
}

// view — что показать по ответу службы.
func view(p ipc.Protection) View {
	v := View{Open: p.Open, Notify: !p.NotifyOff}
	switch {
	case p.Open && p.IP == "":
		v.Title = "appguard работает" // служба старше значка: защиту не называет
	case p.Open:
		v.Title, v.Detail = "Приложения в сети", "Выход "+p.IP+", "+core.CountryName(p.Country)
	case p.Reason != "":
		v.Title, v.Detail = "Приложения без сети", capital(p.Reason)
	default:
		v.Title, v.Detail = "Приложения без сети", "Проверяю выход…"
	}
	return v
}

// capital — причина с большой буквы: в журнале она идёт после двоеточия, в меню —
// отдельной строкой.
func capital(s string) string {
	r, n := utf8.DecodeRuneInString(s)
	return string(unicode.ToUpper(r)) + s[n:]
}

// Icon — показ значка.
type Icon interface {
	// Show показывает значок с v и сразу возвращается. toggle вызывается из потока
	// показа, когда человек выбрал в меню «Уведомления»; он не блокирует. Канал
	// получает причину, если показ сломался сам; следующий Show поднимает его заново.
	Show(v View, toggle func()) (died <-chan error, err error)
	// Update меняет картинку, строку состояния и отметку показанного значка.
	Update(v View)
	// Hide убирает значок и дожидается этого.
	Hide()
}

// Loop — значок, который следует за службой.
type Loop struct {
	Icon Icon
	// State — защита сейчас; ошибка — служба не ответила.
	State func() (ipc.Protection, error)
	// SetNotify включает или выключает уведомления: пункт меню.
	SetNotify func(on bool) error
	Installed func() bool   // appguard ещё установлен
	Every     time.Duration // как часто спрашивать службу и не чаще чего поднимать показ
	Logf      func(format string, args ...any)
}

// Run работает, пока контекст не отменён, appguard не удалён или сеанс не кончился.
// На выходе значок скрыт.
func (l Loop) Run(ctx context.Context) {
	tick := time.NewTicker(l.Every)
	defer tick.Stop()
	// Выбор в меню ждёт цикла в канале на одно место: второй щелчок, пока первый не
	// обработан, ничего не добавляет.
	toggles := make(chan struct{}, 1)
	toggle := func() {
		select {
		case toggles <- struct{}{}:
		default:
		}
	}
	var (
		died   <-chan error
		shown  bool
		now    View // что служба сказала последним
		on     View // что показано
		resend bool // после выбора в меню вид отдаётся, даже если не изменился
		last   string
		fails  = hideAfter // до первого ответа значка нет
	)
	defer func() {
		if shown {
			l.Icon.Hide()
		}
	}()
	// Показ, который ломается раз за разом, пишет причину один раз, а не каждый тик.
	report := func(err error) {
		if err != nil && err.Error() != last {
			last = err.Error()
			l.Logf("значок: %v", err)
		}
	}
	for {
		if p, err := l.State(); err == nil {
			fails, now = 0, view(p)
		} else {
			fails++
			if !l.Installed() {
				return
			}
		}
		switch up := fails < hideAfter; {
		case up && !shown:
			d, err := l.Icon.Show(now, toggle)
			report(err)
			if errors.Is(err, ErrNoSession) {
				return
			}
			if err == nil {
				died, shown, on = d, true, now
			}
		case up && (now != on || resend):
			// Переключатель на macOS перещёлкивается сам; служба отказала — вид тот же,
			// а переключатель надо вернуть.
			l.Icon.Update(now)
			on, resend = now, false
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
			case <-toggles:
				// Сразу спросить службу снова: отметка в меню — то, что она запомнила.
				if err := l.SetNotify(!now.Notify); err != nil {
					report(fmt.Errorf("уведомления: %w", err))
				}
				resend, waiting = shown, false
			case <-tick.C:
				waiting = false
			}
		}
	}
}
