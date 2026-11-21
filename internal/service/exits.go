package service

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"appguard/internal/config"
	"appguard/internal/core"
	"appguard/internal/ipc"
	"appguard/internal/learn"
)

// loadPolicy берёт правило и мои выходы из настроек.
func (e *engine) loadPolicy(st config.Settings) {
	pol := core.Policy{Rule: core.RuleAny, Exits: map[netip.Addr]string{}}
	if st.Rule == core.RuleMine {
		pol.Rule = core.RuleMine
	}
	for _, x := range st.Exits {
		if ip, err := netip.ParseAddr(x.IP); err == nil {
			pol.Exits[ip] = x.Name
		}
	}
	e.policy = pol
	e.exits = slices.Clone(st.Exits)
}

// setRule меняет правило на лету: правила файрвола пересчитываются сразу.
func (e *engine) setRule(rule string) error {
	if rule != core.RuleAny && rule != core.RuleMine {
		return fmt.Errorf("нет правила %q: есть «любой выход не из России» и «только мои выходы»", rule)
	}
	if err := e.cfg.Update(func(s *config.Settings) { s.Rule = rule }); err != nil {
		return err
	}
	e.mu.Lock()
	e.policy.Rule = rule
	e.mu.Unlock()
	e.record([]core.Event{{Time: e.d.Now(), Kind: core.KindService, Text: "правило: " + core.RuleText(rule)}})
	return e.reapply()
}

var (
	errNoExit      = errors.New("сейчас нет проверенного выхода — включи VPN и дождись в статусе строки «проверен»")
	errManyExits   = errors.New("проверенных выходов несколько, а маршрут по умолчанию идёт мимо них — оставь включённым один VPN")
	errRussianExit = errors.New("российский выход не сохраняется: с ним сервисы увидят российский адрес — ровно то, от чего защищает appguard")
)

// remember запоминает выход под именем name. Без ip — текущий проверенный
// выход: запоминается адрес выхода, а не адрес сервера VPN (у цепочки «сервер в
// России → выход за границей» они разные, и сервисы видят именно выход). С ip —
// этот адрес, без подключения: страну служба узнает, когда впервые выйдет
// через него (confirmExit). Сервисы такой адрес не открывает сам: выход через
// него всё равно проверяется, и российский проверку не пройдёт.
func (e *engine) remember(name, ip string) (ipc.ExitStatus, error) {
	if name == "" {
		return ipc.ExitStatus{}, errors.New("у выхода должно быть имя, например «Server 1»")
	}
	x := config.Exit{Name: name, Saved: e.d.Now()}
	if ip == "" {
		exit, err := e.currentExit()
		if err != nil {
			return ipc.ExitStatus{}, err
		}
		x.IP, x.Country = exit.IP.String(), exit.Country
	} else {
		addr, err := netip.ParseAddr(ip)
		if err != nil || !learn.Acceptable(addr, 443) {
			return ipc.ExitStatus{}, fmt.Errorf("%s — не адрес выхода: нужен публичный адрес в интернете, например 203.0.113.5", ip)
		}
		x.IP, x.Unverified = addr.Unmap().String(), true
		if exit, err := e.currentExit(); err == nil && exit.IP == addr.Unmap() {
			x.Country, x.Unverified = exit.Country, false
		}
	}
	e.mu.Lock()
	exits := slices.DeleteFunc(slices.Clone(e.exits), func(old config.Exit) bool {
		if old.IP == x.IP && x.Unverified && !old.Unverified {
			x.Country, x.Unverified = old.Country, false // этот выход служба уже проверяла
		}
		return old.IP == x.IP
	})
	exits = append(exits, x)
	e.mu.Unlock()
	if err := e.cfg.Update(func(s *config.Settings) { s.Exits = exits }); err != nil {
		return ipc.ExitStatus{}, err
	}
	addr := netip.MustParseAddr(x.IP)
	e.mu.Lock()
	e.exits = exits
	e.policy.Exits[addr] = name
	e.mu.Unlock()
	text := fmt.Sprintf("запомнен выход «%s» — %s, %s", name, x.IP, core.CountryName(x.Country))
	if x.Unverified {
		text = fmt.Sprintf("запомнен выход «%s» — %s, введён вручную: страна станет известна, когда служба выйдет через него", name, x.IP)
	}
	e.record([]core.Event{{Time: e.d.Now(), Kind: core.KindService, IP: x.IP, Country: x.Country, Text: text}})
	return exitStatus(x), e.reapply()
}

// forgetExit убирает из моих выходов те, что названы which или имеют адрес
// which. При правиле «только мои выходы» через них сервисы больше не
// откроются.
func (e *engine) forgetExit(which string) ([]ipc.ExitStatus, error) {
	byIP, ipErr := netip.ParseAddr(which)
	e.mu.Lock()
	var gone []config.Exit
	exits := slices.DeleteFunc(slices.Clone(e.exits), func(x config.Exit) bool {
		hit := strings.EqualFold(x.Name, which) || (ipErr == nil && x.IP == byIP.Unmap().String())
		if hit {
			gone = append(gone, x)
		}
		return hit
	})
	e.mu.Unlock()
	if len(gone) == 0 {
		return nil, fmt.Errorf("выхода «%s» в списке нет", which)
	}
	if err := e.cfg.Update(func(s *config.Settings) { s.Exits = exits }); err != nil {
		return nil, err
	}
	var out []ipc.ExitStatus
	var events []core.Event
	e.mu.Lock()
	e.exits = exits
	for _, x := range gone {
		if ip, err := netip.ParseAddr(x.IP); err == nil {
			delete(e.policy.Exits, ip)
		}
		out = append(out, exitStatus(x))
		events = append(events, core.Event{Time: e.d.Now(), Kind: core.KindService, IP: x.IP, Country: x.Country,
			Text: fmt.Sprintf("забыт выход «%s» — %s", x.Name, x.IP)})
	}
	e.mu.Unlock()
	e.record(events)
	return out, e.reapply()
}

// confirmExit — служба вышла через проверенный выход exit. Если он среди моих
// и был введён вручную, теперь известна его страна.
func (e *engine) confirmExit(exit core.Exit) {
	e.mu.Lock()
	i := slices.IndexFunc(e.exits, func(x config.Exit) bool { return x.Unverified && x.IP == exit.IP.String() })
	if i < 0 {
		e.mu.Unlock()
		return
	}
	exits := slices.Clone(e.exits)
	exits[i].Country, exits[i].Unverified = exit.Country, false
	e.mu.Unlock()
	if err := e.cfg.Update(func(s *config.Settings) { s.Exits = exits }); err != nil {
		e.d.Logf("выход %s не отмечен проверенным: %v", exit.IP, err)
		return
	}
	e.mu.Lock()
	e.exits = exits
	e.mu.Unlock()
	x := exits[i]
	e.record([]core.Event{{Time: e.d.Now(), Kind: core.KindService, IP: x.IP, Country: x.Country,
		Text: fmt.Sprintf("выход «%s» подтверждён: служба вышла через него — %s, %s", x.Name, x.IP, core.CountryName(x.Country))}})
}

func exitStatus(x config.Exit) ipc.ExitStatus {
	return ipc.ExitStatus{Name: x.Name, IP: x.IP, Country: x.Country, Unverified: x.Unverified}
}

// currentExit — проверенный выход, через который идёт маршрут по умолчанию, а
// если по умолчанию идёт не туннель — единственный проверенный.
func (e *engine) currentExit() (core.Exit, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	var verified []core.Path
	for _, p := range e.state.Paths() {
		switch {
		case p.Tunnel.Name == e.def && p.Check.Outcome == core.Russian:
			return core.Exit{}, errRussianExit
		case p.Tunnel.Name == e.def && p.Check.Outcome == core.Verified:
			return p.Check.Exit, nil
		case p.Check.Outcome == core.Verified:
			verified = append(verified, p)
		}
	}
	switch len(verified) {
	case 0:
		for _, p := range e.state.Paths() {
			if p.Check.Outcome == core.Russian {
				return core.Exit{}, errRussianExit
			}
		}
		return core.Exit{}, errNoExit
	case 1:
		return verified[0].Check.Exit, nil
	}
	return core.Exit{}, errManyExits
}

// exitsStatus — мои выходы для статуса.
func (e *engine) exitsStatus() []ipc.ExitStatus {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []ipc.ExitStatus
	for _, x := range e.exits {
		out = append(out, exitStatus(x))
	}
	return out
}

// ruleNow — действующее правило.
func (e *engine) ruleNow() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.policy.Rule
}
