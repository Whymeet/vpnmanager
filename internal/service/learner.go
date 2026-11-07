package service

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"
	"unicode"

	"vpnlock/internal/config"
	"vpnlock/internal/core"
	"vpnlock/internal/ipc"
	"vpnlock/internal/learn"
	"vpnlock/internal/procs"
)

// Scanner — процессы и соединения приложений.
type Scanner interface {
	Scan(ctx context.Context, apps []procs.AppRef) (map[string]procs.Activity, error)
	// Peers — соединения всех процессов с локального адреса local.
	Peers(ctx context.Context, local netip.Addr) ([]procs.Conn, error)
	// TunnelOwners — какие из процессов pids держат интерфейс туннеля iface:
	// так опознаётся клиент VPN.
	TunnelOwners(ctx context.Context, iface string, pids []int) ([]int, error)
	// ProxyOwners — какие из процессов pids слушают один из адресов at: так
	// опознаётся клиент VPN в режиме системного прокси.
	ProxyOwners(ctx context.Context, at []netip.AddrPort, pids []int) ([]int, error)
}

// appState — защищённое приложение в памяти службы.
type appState struct {
	cfg        config.App
	remotes    map[procs.Remote]bool // соединения прошлого прохода: новые — те, которых тут нет
	work       time.Duration         // сколько проработало при проверенном выходе — точно, в настройки идут секунды
	running    bool
	lastRemind time.Time
}

func newAppState(c config.App) *appState {
	return &appState{cfg: c, work: time.Duration(c.WorkSecs) * time.Second}
}

// learnLoop раз в ScanEvery смотрит сокеты процессов приложений. Пока выход
// проверен, их удалённые адреса запоминаются и закрываются, а время работы
// копится: через LearnFor приложение считается обученным.
func (e *engine) learnLoop(ctx context.Context) {
	tick := time.NewTicker(e.d.ScanEvery)
	defer tick.Stop()
	last := e.d.Now()
	failing := ""
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		now := e.d.Now()
		// После сна компьютера тик приходит один раз за всё время: столько не
		// проработано.
		elapsed := min(now.Sub(last), 2*e.d.ScanEvery)
		last = now
		if err := e.learnServers(ctx); err != nil {
			e.d.Logf("серверы VPN: %v", err)
		}
		if err := e.learnOnce(ctx, now, elapsed); err != nil {
			if msg := err.Error(); msg != failing {
				failing = msg
				e.d.Logf("обучение: %v", err)
				e.record([]core.Event{{Time: now, Kind: core.KindError, Text: "не удалось посмотреть соединения приложений: " + msg}})
			}
		} else {
			failing = ""
		}
	}
}

// learnOnce — один проход обучения.
func (e *engine) learnOnce(ctx context.Context, now time.Time, elapsed time.Duration) error {
	e.mu.Lock()
	refs := make([]procs.AppRef, 0, len(e.apps))
	for _, a := range e.apps {
		refs = append(refs, procs.AppRef{ID: a.cfg.ID, Path: a.cfg.Path, Command: a.cfg.Command})
	}
	e.mu.Unlock()
	if len(refs) == 0 {
		return nil
	}
	act, err := e.d.Apps.Scan(ctx, refs)
	if err != nil {
		return err
	}

	var events []core.Event
	var fresh []string // домены, которых служба ещё не защищала: узнать их адреса
	newAddrs, newDomains, changed := false, false, false
	e.mu.Lock()
	// Учимся только через проверенный туннель: через прокси соединения
	// приложения ведут на петлю, а мимо прокси уходят с домашнего адреса.
	open := len(e.prot.OpenIfaces) > 0
	for id, a := range e.apps {
		got := act[id]
		a.running = got.Running
		prev := a.remotes
		a.remotes = map[procs.Remote]bool{}
		for _, r := range got.Remotes {
			a.remotes[r] = true
		}
		if open {
			// Обученная консольная программа учит только новые имена своих
			// зарегистрированных доменов. Остальное — сайты, которые она
			// открывает по просьбе человека: закрылись бы вне VPN для всех.
			settled := a.cfg.Command && a.cfg.Learned
			for _, r := range got.Remotes {
				if !learn.Acceptable(r.Addr, r.Port) {
					continue
				}
				// Имена, которые стоят за адресом нового соединения, — домены
				// приложения: новые адреса сервиса закроются по ним, а не по
				// одному обучению.
				if !prev[r] {
					names := e.learnNames(id, r.Addr, now)
					if settled {
						names = e.ownSites(id, names)
					}
					if len(names) > 0 {
						fresh = append(fresh, e.ownDomains(id, names)...)
						newDomains = true
					}
				}
				if settled {
					continue
				}
				s := r.Addr.String()
				if slices.Contains(a.cfg.Addrs, s) || forgotten(a.cfg.Forgotten, s) {
					continue
				}
				a.cfg.Addrs = append(a.cfg.Addrs, s)
				newAddrs, changed = true, true
			}
		}
		if a.cfg.Learned {
			continue
		}
		switch {
		case open && a.running:
			a.work += elapsed
			a.cfg.WorkSecs = int(a.work / time.Second)
			changed = true
			if a.work >= e.d.LearnFor && len(a.cfg.Addrs) > 0 {
				a.cfg.Learned, a.cfg.LearnedAt = true, now
				n := e.appDomains(id)
				events = append(events, core.Event{Time: now, Kind: core.KindApp,
					Text: fmt.Sprintf("%s защищено: обучение закончено, %d %s, %d %s", a.cfg.Name,
						len(a.cfg.Addrs), core.Plural(len(a.cfg.Addrs), "адрес", "адреса", "адресов"),
						n, core.Plural(n, "домен", "домена", "доменов"))})
			}
		case !open && a.running && now.Sub(a.lastRemind) >= e.d.RemindEvery:
			a.lastRemind = now
			events = append(events, core.Event{Time: now, Kind: core.KindApp, Text: notYet(a.cfg)})
		}
	}
	e.mu.Unlock()

	if changed {
		if err := e.saveApps(); err != nil {
			return err
		}
	}
	if newDomains {
		if err := e.saveDomains(); err != nil {
			return err
		}
		e.syncDNS()
		e.resolveLater(fresh)
	}
	e.record(events)
	if newAddrs || newDomains {
		return e.reapply()
	}
	return nil
}

func notYet(a config.App) string {
	if a.Command {
		return a.Name + " ещё не защищено — включи VPN и запусти программу"
	}
	return a.Name + " ещё не защищено — включи VPN и открой его"
}

// addApp добавляет приложение по пути: на macOS — пакет или консольную
// программу, они «ждут обучения», если их нет в каталоге; на Windows — exe
// или пакет Store, защищён сразу.
func (e *engine) addApp(path, name string) (ipc.AppStatus, error) {
	a, err := e.d.ReadApp(path)
	if err != nil {
		return ipc.AppStatus{}, err
	}
	// На Windows имя для людей — из ярлыка «Пуска»: у exe и папки установки
	// оно бывает неузнаваемым (Update.exe, Application). Что защищается, решает
	// путь, а не имя.
	if n := displayName(name); a.Instant && n != "" {
		a.Name = n
	}
	e.mu.Lock()
	if cur, ok := e.apps[a.ID]; ok {
		e.mu.Unlock()
		return e.appStatus(cur), fmt.Errorf("%s уже в списке (%s)", cur.cfg.Name, appWord(cur.cfg.Learned))
	}
	st := newAppState(config.App{ID: a.ID, Name: a.Name, Path: a.Path, Exe: a.Exe, Command: a.Command, Added: e.d.Now()})
	st.lastRemind = e.d.Now()
	// Приложение из каталога защищено сразу: домены и адреса известны заранее.
	entry, known := e.catalogEntry(st.cfg)
	var lookups []string
	switch {
	case known:
		st.cfg.Learned, st.cfg.Catalog, st.cfg.LearnedAt = true, true, e.d.Now()
		st.cfg.Addrs = mergeStrings(nil, entry.Addrs)
		lookups = e.ownDomains(a.ID, entry.Domains)
		// Имени из ярлыка нет (добавили по пути или пакету) — каталог знает,
		// как приложение называется.
		if a.Instant && displayName(name) == "" {
			st.cfg.Name = entry.Name
		}
	case a.Instant:
		// Фильтры стоят на сам исполняемый файл: учить нечего.
		st.cfg.Learned, st.cfg.LearnedAt = true, e.d.Now()
	}
	e.apps[a.ID] = st
	e.mu.Unlock()
	if err := e.saveApps(); err != nil {
		e.mu.Lock()
		delete(e.apps, a.ID)
		e.disown(a.ID)
		e.mu.Unlock()
		return ipc.AppStatus{}, err
	}
	if !known && a.Instant {
		e.record([]core.Event{{Time: e.d.Now(), Kind: core.KindApp,
			Text: a.Name + " защищено: сеть у него только через проверенный VPN"}})
		return e.appStatus(st), e.reapply()
	}
	if !known {
		text := a.Name + " добавлено и ждёт обучения: включи VPN и поработай в нём пару минут"
		if a.Command {
			text = a.Name + " добавлено и ждёт обучения: включи VPN и поработай в программе пару минут. Адреса учатся только в эти минуты — не открывай через неё посторонние сайты"
		}
		e.record([]core.Event{{Time: e.d.Now(), Kind: core.KindApp, Text: text}})
		return e.appStatus(st), nil
	}
	if err := e.saveDomains(); err != nil {
		return e.appStatus(st), err
	}
	e.record([]core.Event{{Time: e.d.Now(), Kind: core.KindApp, Text: byCatalog(st.cfg.Name, entry)}})
	e.syncDNS()
	e.resolveLater(lookups)
	return e.appStatus(st), e.reapply()
}

// removeApp снимает защиту с приложения: его адреса уходят из таблиц, если их
// не держит другое приложение или защищённый домен.
func (e *engine) removeApp(id string) (ipc.AppStatus, error) {
	e.mu.Lock()
	st, ok := e.apps[id]
	if !ok {
		e.mu.Unlock()
		return ipc.AppStatus{}, errNoApp
	}
	delete(e.apps, id)
	e.mu.Unlock()
	if err := e.saveApps(); err != nil {
		e.mu.Lock()
		e.apps[id] = st
		e.mu.Unlock()
		return ipc.AppStatus{}, err
	}
	e.mu.Lock()
	e.disown(id)
	e.mu.Unlock()
	if err := e.saveDomains(); err != nil {
		return e.appStatus(st), err
	}
	e.syncDNS()
	e.record([]core.Event{{Time: e.d.Now(), Kind: core.KindApp,
		Text: st.cfg.Name + ": защита снята — приложение выходит в сеть с домашнего адреса, если VPN выключен"}})
	return e.appStatus(st), e.reapply()
}

var errNoApp = errors.New("такого приложения в списке нет")

// displayName — имя от клиента, пригодное для журнала: без управляющих
// символов и не длиннее 80 знаков.
func displayName(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, strings.TrimSpace(s))
	if r := []rune(s); len(r) > 80 {
		s = string(r[:80])
	}
	return s
}

// saveApps пишет список приложений в настройки (по порядку добавления).
func (e *engine) saveApps() error {
	e.mu.Lock()
	list := make([]config.App, 0, len(e.apps))
	for _, a := range e.apps {
		c := a.cfg
		c.Addrs = slices.Clone(c.Addrs)
		c.Forgotten = slices.Clone(c.Forgotten)
		list = append(list, c)
	}
	e.mu.Unlock()
	slices.SortFunc(list, func(a, b config.App) int { return a.Added.Compare(b.Added) })
	return e.cfg.Update(func(s *config.Settings) { s.Apps = list })
}

// appsStatus — приложения для статуса, по порядку добавления.
func (e *engine) appsStatus() []ipc.AppStatus {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := []ipc.AppStatus{}
	for _, a := range e.apps {
		out = append(out, e.appStatusLocked(a))
	}
	slices.SortFunc(out, func(a, b ipc.AppStatus) int { return e.apps[a.ID].cfg.Added.Compare(e.apps[b.ID].cfg.Added) })
	return out
}

func (e *engine) appStatus(a *appState) ipc.AppStatus {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.appStatusLocked(a)
}

func (e *engine) appStatusLocked(a *appState) ipc.AppStatus {
	return ipc.AppStatus{
		ID: a.cfg.ID, Name: a.cfg.Name, Path: a.cfg.Path, Learned: a.cfg.Learned, Catalog: a.cfg.Catalog, Running: a.running,
		Addrs: len(a.cfg.Addrs), Domains: e.appDomains(a.cfg.ID), WorkSecs: a.cfg.WorkSecs, NeedSecs: int(e.d.LearnFor / time.Second), Open: len(e.prot.OpenIfaces) > 0,
		Command: a.cfg.Command,
	}
}

// appDetail — адреса и домены приложения id и что человек у него убрал.
func (e *engine) appDetail(id string) (ipc.AppStatus, ipc.AppDetail, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	a, ok := e.apps[id]
	if !ok {
		return ipc.AppStatus{}, ipc.AppDetail{}, errNoApp
	}
	d := ipc.AppDetail{Addrs: slices.Clone(a.cfg.Addrs), Forgotten: slices.Clone(a.cfg.Forgotten)}
	slices.SortFunc(d.Addrs, func(x, y string) int {
		ax, _ := netip.ParseAddr(x)
		ay, _ := netip.ParseAddr(y)
		return ax.Compare(ay)
	})
	for name, dom := range e.protected {
		if dom.apps[id] {
			d.Domains = append(d.Domains, name)
		}
	}
	slices.Sort(d.Domains)
	return e.appStatusLocked(a), d, nil
}

func appWord(learned bool) string {
	if learned {
		return "защищено"
	}
	return "ждёт обучения"
}

// appAddrs — адреса всех приложений нужного семейства. Вызывать под e.mu.
func (e *engine) appAddrs(v6 bool, seen map[netip.Addr]bool) []netip.Addr {
	var out []netip.Addr
	for _, a := range e.apps {
		for _, s := range a.cfg.Addrs {
			addr, err := netip.ParseAddr(s)
			if err != nil || addr.Is6() != v6 || seen[addr] {
				continue
			}
			seen[addr] = true
			out = append(out, addr)
		}
	}
	return out
}
