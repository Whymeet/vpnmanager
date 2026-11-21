// Package sysdns направляет имена защищённых доменов на резолвер службы. На
// Linux это systemd-resolved: у него домены назначаются интерфейсу, поэтому
// appguard заводит свой пустой интерфейс и вешает на него резолвер службы и
// домены маршрутизации (~домен). Остальные имена система резолвит как раньше, а
// настройки чужих интерфейсов и файлы системы остаются нетронутыми.
//
// Без systemd-resolved направить домены некуда: приложения закрыты всё равно (их
// сеть держит файрвол), а сайт в браузере закрывается только по адресам из
// каталога и `appguard protect <адрес>`.
package sysdns

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	// Iface — первый интерфейс appguard: через него никто никуда не ходит, это
	// только место для настроек systemd-resolved.
	Iface = "appguard0"
	// perLink — сколько доменов resolved принимает на интерфейс. На 257-м он
	// отказывает всей команде, поэтому большой список раскладывается по нескольким.
	perLink = 256
	// ifaceAddr — адрес интерфейса: без адреса resolved считает его неработающим и
	// не спрашивает его резолвер. /32 и вне частных сетей: маршрутов не появится.
	ifaceAddr = "169.254.53.53/32"
)

// Сразу после появления интерфейса resolved его ещё не знает: ждём несколько раз.
const (
	linkTries = 20
	linkWait  = 100 * time.Millisecond
)

// Resolved — домены appguard в systemd-resolved.
type Resolved struct {
	Addr netip.AddrPort // где слушает резолвер службы
	// Run выполняет программу; ошибка содержит её вывод.
	Run func(name string, args ...string) error
	// Active — resolved работает. Enabled — он должен запуститься с системой.
	// Link — интерфейс есть.
	Active  func() bool
	Enabled func() bool
	Link    func(name string) bool
	Sleep   func(time.Duration)
}

// System — resolved на живой системе.
func System(addr netip.AddrPort) Resolved {
	return Resolved{Addr: addr, Run: run, Active: Active, Enabled: enabled, Sleep: time.Sleep, Link: func(name string) bool {
		_, err := net.InterfaceByName(name)
		return err == nil
	}}
}

// linkName — имя интерфейса номер i: appguard0, appguard1…
func linkName(i int) string { return "appguard" + strconv.Itoa(i) }

// Active — systemd-resolved работает на этом компьютере.
func Active() bool {
	return exec.Command("systemctl", "is-active", "--quiet", "systemd-resolved").Run() == nil
}

func enabled() bool {
	return exec.Command("systemctl", "is-enabled", "--quiet", "systemd-resolved").Run() == nil
}

func run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, bytes.TrimSpace(out))
	}
	return nil
}

// Set направляет на службу ровно эти домены. Чужих резолверов для домена resolved
// не запрещает, поэтому skipped всегда пуст: самый длинный совпавший домен
// выигрывает, и у своего домена это домен appguard.
func (r Resolved) Set(domains []string) (skipped []string, err error) {
	if len(domains) == 0 {
		return nil, r.Clear()
	}
	if !r.Active() {
		// Служба стартует раньше resolved: ошибка заставит её повторить.
		if r.Enabled() {
			return nil, errors.New("systemd-resolved ещё не запустился")
		}
		return nil, nil
	}
	routes := make([]string, len(domains))
	for i, d := range domains {
		routes[i] = "~" + d
	}
	slices.Sort(routes)
	n := 0
	for part := range slices.Chunk(routes, perLink) {
		if err := r.setLink(linkName(n), part); err != nil {
			return nil, err
		}
		n++
	}
	if err := r.dropFrom(n); err != nil {
		return nil, err
	}
	// Ответы, полученные до защиты, не должны жить мимо таблиц.
	return nil, r.Run("resolvectl", "flush-caches")
}

// setLink вешает на интерфейс name резолвер службы и домены routes.
func (r Resolved) setLink(name string, routes []string) error {
	if err := r.ensureLink(name); err != nil {
		return err
	}
	// Интерфейс только что завёлся и resolved о нём ещё не слышал — первый вызов
	// откажет; остальные после него уже проходят.
	setDNS := func() error { return r.Run("resolvectl", "dns", name, r.Addr.String()) }
	err := setDNS()
	for i := 0; err != nil && i < linkTries; i++ {
		r.Sleep(linkWait)
		err = setDNS()
	}
	if err != nil {
		return err
	}
	if err := r.Run("resolvectl", append([]string{"domain", name}, routes...)...); err != nil {
		return err
	}
	return r.Run("resolvectl", "default-route", name, "false")
}

func (r Resolved) ensureLink(name string) error {
	if r.Link(name) {
		return nil
	}
	for _, args := range [][]string{
		{"link", "add", name, "type", "dummy"},
		{"addr", "add", ifaceAddr, "dev", name, "scope", "global"},
		{"link", "set", name, "up"},
	} {
		if err := r.Run("ip", args...); err != nil {
			return err
		}
	}
	return nil
}

// Clear удаляет интерфейсы: resolved забывает их настройки вместе с ними.
func (r Resolved) Clear() error { return r.dropFrom(0) }

// dropFrom удаляет интерфейсы начиная с номера i: список мог сократиться.
func (r Resolved) dropFrom(i int) error {
	for ; r.Link(linkName(i)); i++ {
		if err := r.Run("ip", "link", "del", linkName(i)); err != nil {
			return err
		}
	}
	return nil
}

// Stub — программы спрашивают заглушку resolved: только тогда домены доходят до
// службы.
func Stub() bool {
	data, err := os.ReadFile("/etc/resolv.conf")
	return err == nil && bytes.Contains(data, []byte("127.0.0.53"))
}
