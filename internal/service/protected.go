package service

import (
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"

	"appguard/internal/config"
	"appguard/internal/ipc"
	"appguard/internal/learn"
	"appguard/internal/resolver"
)

// domainState — защищённый домен в памяти службы. Он держится, пока у него
// есть владелец: команда protect или приложение из каталога.
type domainState struct {
	addrs  []string
	manual bool
	apps   map[string]bool // идентификаторы приложений
}

func (d *domainState) owned() bool { return d.manual || len(d.apps) > 0 }

func domainsFromConfig(ps []config.Protected) map[string]*domainState {
	out := map[string]*domainState{}
	for _, p := range ps {
		d := &domainState{addrs: slices.Clone(p.Addrs), manual: p.Manual, apps: map[string]bool{}}
		for _, id := range p.Apps {
			d.apps[id] = true
		}
		out[p.Domain] = d
	}
	return out
}

// saveDomains пишет защищённые домены в настройки целиком. Вызывать без e.mu.
func (e *engine) saveDomains() error {
	e.mu.Lock()
	list := make([]config.Protected, 0, len(e.protected))
	for name, d := range e.protected {
		list = append(list, config.Protected{Domain: name, Addrs: slices.Clone(d.addrs), Manual: d.manual,
			Apps: slices.Sorted(maps.Keys(d.apps))})
	}
	e.mu.Unlock()
	slices.SortFunc(list, func(a, b config.Protected) int { return strings.Compare(a.Domain, b.Domain) })
	return e.cfg.Update(func(s *config.Settings) { s.Protected = list })
}

// saveManual пишет адреса, защищённые вручную, в настройки. Вызывать без e.mu.
func (e *engine) saveManual() error {
	e.mu.Lock()
	list := make([]string, 0, len(e.manual))
	for _, a := range e.manual {
		list = append(list, a.String())
	}
	e.mu.Unlock()
	slices.Sort(list)
	return e.cfg.Update(func(s *config.Settings) { s.Addrs = list })
}

// importList защищает вручную сразу все домены и адреса из файла: адреса —
// в таблицы, домены — на резолвер службы, их адреса узнаются фоном. Что
// закрывать нельзя (не имя, служебное, локальное), отбрасывается с причиной.
func (e *engine) importList(domains, addrs []string) (ipc.Imported, []string, error) {
	var got ipc.Imported
	var dropped, fresh []string
	e.mu.Lock()
	for _, s := range addrs {
		a, err := netip.ParseAddr(s)
		switch {
		case err != nil:
			dropped = append(dropped, fmt.Sprintf("%q — не адрес", s))
		case !learn.Acceptable(a, 443):
			dropped = append(dropped, fmt.Sprintf("%s — адрес, который нельзя закрывать: локальный, служебный или нужен самой службе", a))
		case !slices.Contains(e.manual, a.Unmap()):
			e.manual = append(e.manual, a.Unmap())
			got.Addrs++
		}
	}
	for _, s := range domains {
		name := resolver.Normalize(s)
		switch {
		case !resolver.ValidDomain(name):
			dropped = append(dropped, fmt.Sprintf("%q — не имя домена", s))
		case !learn.Domain(name):
			dropped = append(dropped, fmt.Sprintf("%s — служебное или локальное имя: его закрывать нельзя", name))
		default:
			d, existed := e.protected[name]
			if !existed {
				d = e.domain(name)
				fresh = append(fresh, name)
			}
			if !d.manual {
				d.manual = true
				got.Domains++
			}
		}
	}
	e.mu.Unlock()
	if err := e.saveManual(); err != nil {
		return got, dropped, err
	}
	if err := e.saveDomains(); err != nil {
		return got, dropped, err
	}
	e.syncDNS()
	e.resolveLater(fresh)
	return got, dropped, e.reapply()
}

// manualStatus — домены и сколько адресов защищено вручную, для статуса.
func (e *engine) manualStatus() ([]string, int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	var names []string
	for name, d := range e.protected {
		if d.manual {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return names, len(e.manual)
}
