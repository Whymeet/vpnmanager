package service

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"appguard/internal/core"
	"appguard/internal/resolver"
)

// forget убирает у приложения id выученные адреса и домены из items: человек
// решил, что они не его — например, сайт, который Claude Code открыл во время
// обучения. Забытое уходит из таблиц, если его не держит кто-то ещё, приложение
// его больше не выучит, и каталог его не вернёт — пока приложение не снимут с
// защиты. Чего у приложения нет, возвращается в warnings с подсказкой.
func (e *engine) forget(id string, items []string) (forgot, warnings []string, err error) {
	e.mu.Lock()
	a, ok := e.apps[id]
	if !ok {
		e.mu.Unlock()
		return nil, nil, errNoApp
	}
	name := a.cfg.Name
	addrs := slices.Clone(a.cfg.Addrs)
	var domains []string
	for _, item := range items {
		if addr, perr := netip.ParseAddr(item); perr == nil {
			s := addr.Unmap().String()
			if i := slices.Index(addrs, s); i >= 0 {
				addrs = slices.Delete(addrs, i, i+1)
				forgot = append(forgot, s)
			} else if d := e.domainWith(id, s); d != "" {
				warnings = append(warnings, fmt.Sprintf("%s — адрес домена %s, его закрывает домен: appguard forget %s %s", s, d, name, d))
			} else {
				warnings = append(warnings, fmt.Sprintf("%s у %s не выучен", s, name))
			}
			continue
		}
		domain := resolver.Normalize(item)
		switch d, ok := e.protected[domain]; {
		case ok && d.apps[id]:
			if !slices.Contains(domains, domain) {
				domains = append(domains, domain)
				forgot = append(forgot, domain)
			}
		case !resolver.ValidDomain(domain):
			warnings = append(warnings, fmt.Sprintf("%q — не адрес и не домен", item))
		default:
			if parent := e.parentOf(id, domain); parent != "" {
				warnings = append(warnings, fmt.Sprintf("%s входит в домен %s — забудь его: appguard forget %s %s", domain, parent, name, parent))
			} else {
				warnings = append(warnings, fmt.Sprintf("домена %s у %s нет", domain, name))
			}
		}
	}
	if len(forgot) == 0 {
		e.mu.Unlock()
		return nil, warnings, nil
	}
	a.cfg.Addrs = addrs
	for _, f := range forgot {
		if !slices.Contains(a.cfg.Forgotten, f) {
			a.cfg.Forgotten = append(a.cfg.Forgotten, f)
		}
	}
	for _, domain := range domains {
		d := e.protected[domain]
		delete(d.apps, id)
		if !d.owned() {
			delete(e.protected, domain)
		}
	}
	e.mu.Unlock()

	if err := e.saveApps(); err != nil {
		return nil, warnings, err
	}
	if len(domains) > 0 {
		if err := e.saveDomains(); err != nil {
			return nil, warnings, err
		}
		e.syncDNS()
	}
	warnings = append(warnings, e.stillHeld(forgot)...)
	e.record([]core.Event{{Time: e.d.Now(), Kind: core.KindApp,
		Text: fmt.Sprintf("%s: забыто %s — приложение их больше не выучит", name, strings.Join(forgot, ", "))}})
	return forgot, warnings, e.reapply()
}

// stillHeld — что из только что забытого всё равно закрыто вне VPN: адрес есть
// у другого приложения или домена, домен защищён вручную или другим
// приложением.
func (e *engine) stillHeld(forgot []string) []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	held := map[netip.Addr]bool{}
	for _, a := range append(e.addrs(false), e.addrs(true)...) {
		held[a] = true
	}
	var out []string
	for _, f := range forgot {
		if addr, err := netip.ParseAddr(f); err == nil {
			if held[addr] {
				out = append(out, fmt.Sprintf("%s остаётся закрытым вне VPN: его держит другое приложение, домен или защита вручную", f))
			}
		} else if _, ok := e.protected[f]; ok {
			out = append(out, fmt.Sprintf("%s остаётся защищённым: он есть у другого приложения или защищён вручную", f))
		}
	}
	return out
}

// domainWith — домен приложения id, за которым стоит адрес addr. Вызывать
// под e.mu.
func (e *engine) domainWith(id, addr string) string {
	for name, d := range e.protected {
		if d.apps[id] && slices.Contains(d.addrs, addr) {
			return name
		}
	}
	return ""
}

// parentOf — домен приложения id, поддомен которого name. Вызывать под e.mu.
func (e *engine) parentOf(id, name string) string {
	for parent, d := range e.protected {
		if d.apps[id] && strings.HasSuffix(name, "."+parent) {
			return parent
		}
	}
	return ""
}

// forgotten — человек убрал item у приложения (forget): адрес — точно, домен —
// вместе с поддоменами.
func forgotten(list []string, item string) bool {
	for _, f := range list {
		if item == f || strings.HasSuffix(item, "."+f) {
			return true
		}
	}
	return false
}

// without — список без забытого у приложения.
func without(list, forgot []string) []string {
	return slices.DeleteFunc(slices.Clone(list), func(item string) bool { return forgotten(forgot, item) })
}
