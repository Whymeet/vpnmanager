package service

import (
	"cmp"
	"context"
	"fmt"
	"net/netip"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"appguard/internal/core"
	"appguard/internal/ipc"
)

// reachTimeout — сколько проверка ждёт соединения с сервисом мимо VPN. pf
// отбрасывает пакеты молча, поэтому закрытый адрес — это тишина до таймаута.
const reachTimeout = 2 * time.Second

// reachPerService — сколько адресов сервиса пробовать: все — долго и лишне,
// таблица у них одна.
const reachPerService = 3

// check — пункты проверки, которые видит служба: правила, выход, «Россия
// напрямую» и каждый защищённый сервис мимо VPN.
func (e *engine) check(ctx context.Context) []ipc.CheckItem {
	items := []ipc.CheckItem{e.checkRules()}
	items = append(items, e.checkExit()...)
	return append(items, e.checkReach(ctx)...)
}

// checkRules — на месте ли правила файрвола и целы ли они.
func (e *engine) checkRules() ipc.CheckItem {
	it := ipc.CheckItem{Name: "Правила файрвола"}
	e.applyMu.Lock()
	defer e.applyMu.Unlock()
	e.mu.Lock()
	have, failed, r := e.haveRules, e.failed, e.applied
	e.mu.Unlock()
	switch {
	case failed != "":
		it.Result, it.Detail = ipc.CheckFail, "не применились: "+failed
	case !have:
		it.Result, it.Detail = ipc.CheckFail, "ещё не поставлены"
	default:
		if err := e.d.Enforce.Verify(r); err != nil {
			it.Result, it.Detail = ipc.CheckFail, "сброшены: "+err.Error()
			it.Hint = "сторож службы возвращает их за секунду — запусти проверку ещё раз; если пункт не проходит снова, причина в appguard log"
			return it
		}
		n := len(r.V4) + len(r.V6)
		it.Result, it.Detail = ipc.CheckOK, fmt.Sprintf("на месте: в таблицах %d %s", n, core.Plural(n, "адрес", "адреса", "адресов"))
		return it
	}
	it.Hint = "причина — в appguard log"
	return it
}

// checkExit — выход и «Россия напрямую» по тому, что служба уже знает.
func (e *engine) checkExit() []ipc.CheckItem {
	e.mu.Lock()
	defer e.mu.Unlock()
	exit := ipc.CheckItem{Name: "Выход"}
	direct := ipc.CheckItem{Name: "«Россия напрямую»"}
	paths := e.state.Paths()
	switch {
	case e.prot.Open:
		exit.Result = ipc.CheckOK
		exit.Detail = fmt.Sprintf("%s, %s — проверен, сервисы открыты", e.prot.Exit.IP, core.CountryName(e.prot.Exit.Country))
	case len(paths) == 0:
		exit.Result, exit.Detail = ipc.CheckWarn, "VPN выключен — защищённые сервисы закрыты, пока его нет"
	case e.prot.Reason == "":
		exit.Result, exit.Detail = ipc.CheckWarn, "выход ещё проверяется — повтори через пару секунд"
	default:
		exit.Result, exit.Detail = ipc.CheckWarn, "сервисы закрыты: "+e.prot.Reason
	}
	var verified, through, silent []string
	for _, p := range paths {
		if p.Check.Outcome != core.Verified {
			continue
		}
		verified = append(verified, p.Tunnel.Name)
		switch p.Probe.State {
		case core.ProbeDirect:
			direct.Result = ipc.CheckFail
			direct.Detail = p.Tunnel.Name + ": клиент VPN отправляет российские адреса мимо туннеля"
			direct.Hint = "выключи в клиенте VPN правило, которое шлёт российские адреса напрямую: защищённые сервисы от прямых соединений закрыты, но правило выдаёт домашний адрес"
		case core.ProbeThrough:
			through = append(through, p.Tunnel.Name)
		default:
			silent = append(silent, p.Tunnel.Name)
		}
	}
	switch {
	case direct.Result == ipc.CheckFail:
	case len(verified) == 0:
		direct.Result, direct.Detail = ipc.CheckWarn, "проверить не на чем: нет проверенного выхода"
	case len(silent) > 0:
		direct.Result, direct.Detail = ipc.CheckWarn, "ещё не проверено или российский сервис не ответил ("+strings.Join(silent, ", ")+")"
	default:
		direct.Result, direct.Detail = ipc.CheckOK, "российские адреса идут через туннель"
	}
	return []ipc.CheckItem{exit, direct}
}

// target — защищённый сервис для проверки: имя и его адреса.
type target struct {
	name  string
	addrs []netip.Addr
}

// checkReach пытается соединиться с каждым защищённым сервисом через
// физический интерфейс — мимо VPN. Достучался — правила не держат.
func (e *engine) checkReach(ctx context.Context) []ipc.CheckItem {
	phys, ok := e.d.Physical()
	if !ok || e.d.Reach == nil {
		return []ipc.CheckItem{{Name: "Сервисы мимо VPN", Result: ipc.CheckWarn, Detail: "нет физического интерфейса — проверять мимо VPN нечем"}}
	}
	list, servers := e.services()
	if len(list) == 0 {
		return []ipc.CheckItem{{Name: "Сервисы мимо VPN", Result: ipc.CheckWarn, Detail: "защищённых сервисов пока нет", Hint: "добавь приложение: appguard add"}}
	}
	ctx, cancel := context.WithTimeout(ctx, reachTimeout)
	defer cancel()
	reached := make([][]netip.Addr, len(list))
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i, svc := range list {
		for _, a := range svc.tryAddrs(servers) {
			wg.Go(func() {
				if e.d.Reach(ctx, phys, netip.AddrPortFrom(a, 443)) == nil {
					mu.Lock()
					reached[i] = append(reached[i], a)
					mu.Unlock()
				}
			})
		}
	}
	wg.Wait()

	items := make([]ipc.CheckItem, len(list))
	for i, svc := range list {
		it := ipc.CheckItem{Name: "Мимо VPN: " + svc.name}
		tried := svc.tryAddrs(servers)
		switch {
		case len(reached[i]) > 0:
			slices.SortFunc(reached[i], netip.Addr.Compare)
			it.Result = ipc.CheckFail
			it.Detail = fmt.Sprintf("достижим через %s: %s", phys.Name, core.JoinAddrs(reached[i]))
			it.Hint = "правила не держат этот адрес — что с файрволом, видно в appguard log"
		case len(tried) == 0 && len(svc.addrs) == 0 && runtime.GOOS != "darwin":
			// На Windows и Linux приложение закрыто по своим программам сразу, а
			// адреса сервиса появятся, когда оно поработает через проверенный VPN.
			it.Result, it.Detail = ipc.CheckWarn, "приложение закрыто по своим программам, а адресов его сервиса пока нет — до тех пор сайт в браузере без VPN откроется"
			it.Hint = "открой приложение при включённом VPN — адреса и домены сервиса запомнятся; закрыть сайт сразу: appguard protect <домен сервиса>"
			if runtime.GOOS == "linux" { // здесь адреса приложений не учатся
				it.Hint = "закрыть и сайт сервиса: appguard protect <домен сервиса>"
			}
		case len(tried) == 0 && len(svc.addrs) == 0:
			it.Result, it.Detail = ipc.CheckWarn, "адресов пока нет — они появятся, когда приложение выйдет в сеть через VPN"
		case len(tried) == 0:
			it.Result, it.Detail = ipc.CheckWarn, "все известные адреса — серверы VPN (VPN через CDN), на физическом интерфейсе они разрешены"
		default:
			it.Result = ipc.CheckOK
			it.Detail = fmt.Sprintf("не достучаться через %s (%d %s)", phys.Name, len(tried), core.Plural(len(tried), "адрес", "адреса", "адресов"))
		}
		items[i] = it
	}
	return items
}

// services — защищённые сервисы: приложения с адресами их доменов и
// выученными, затем домены, которые защищены сами по себе. servers — серверы
// VPN: их адреса на физическом интерфейсе разрешены, пробовать их незачем.
func (e *engine) services() ([]target, map[netip.Addr]bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []target
	for id, a := range e.apps {
		svc := target{name: a.cfg.Name}
		var strs []string
		for _, d := range e.protected {
			if d.apps[id] {
				strs = append(strs, d.addrs...)
			}
		}
		svc.addrs = parseAddrs(append(strs, a.cfg.Addrs...))
		out = append(out, svc)
	}
	for name, d := range e.protected {
		if d.manual {
			out = append(out, target{name: name, addrs: parseAddrs(d.addrs)})
		}
	}
	if len(e.manual) > 0 {
		out = append(out, target{name: "адреса вручную", addrs: slices.Clone(e.manual)})
	}
	slices.SortFunc(out, func(a, b target) int { return cmp.Compare(a.name, b.name) })
	servers := map[netip.Addr]bool{}
	for _, a := range e.applied.Servers {
		servers[a] = true
	}
	return out, servers
}

// tryAddrs — какие адреса сервиса пробовать: до reachPerService, сначала IPv4,
// кроме разрешённых серверов VPN.
func (s target) tryAddrs(servers map[netip.Addr]bool) []netip.Addr {
	var out []netip.Addr
	for _, a := range s.addrs {
		if !servers[a] {
			out = append(out, a)
		}
	}
	slices.SortStableFunc(out, func(a, b netip.Addr) int {
		return cmp.Compare(a.BitLen(), b.BitLen()) // IPv4 вперёд
	})
	return out[:min(len(out), reachPerService)]
}

func parseAddrs(strs []string) []netip.Addr {
	var out []netip.Addr
	for _, s := range strs {
		if a, err := netip.ParseAddr(s); err == nil && !slices.Contains(out, a) {
			out = append(out, a)
		}
	}
	return out
}
