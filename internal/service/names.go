package service

import (
	"context"
	"net/netip"
	"slices"
	"sync"
	"time"

	"golang.org/x/net/publicsuffix"

	"appguard/internal/dnswatch"
	"appguard/internal/learn"
	"appguard/internal/resolver"
)

// Answers — ответы DNS на интерфейсе: какие имена стоят за адресами
// приложений. nil — домены не учатся, только адреса.
type Answers interface {
	// Listen слушает ответы DNS на интерфейсе iface и отдаёт каждый в got,
	// пока не отменён ctx.
	Listen(ctx context.Context, iface string, got func(dnswatch.Answer)) error
}

const (
	// nameTTL — сколько помнить имя адреса: имя идёт в дело, только если ответ
	// пришёл перед новым соединением приложения (answerLead), дольше незачем.
	nameTTL = 2 * time.Minute
	// maxNamedAddrs — больше адресов кэш не держит: при переполнении забывает
	// старое.
	maxNamedAddrs = 20000
	// maxAddrNames — больше имён у одного адреса кэш не держит: новое вытесняет
	// самое старое. Ответы с разными именами на один адрес может слать и
	// программа на этом компьютере.
	maxAddrNames = 16
	// maxAppDomains — больше доменов одно приложение не выучит: имена приходят
	// из сети, и бесконечно расти /etc/resolver и таблицы не должны.
	maxAppDomains = 200
	// answerLead — насколько ответ DNS может опередить проход сканера, который
	// увидел новое соединение: соединение открывается сразу после ответа, а
	// кэш Windows опрашивается раз в 10 секунд.
	answerLead = 15 * time.Second
)

// nameCache — какие имена стоят за адресами: ответы DNS на интерфейсе
// проверенного туннеля за последние минуты. Своя блокировка: зовут и под e.mu.
type nameCache struct {
	mu     sync.Mutex
	by     map[netip.Addr]map[string]time.Time
	pruned time.Time // когда кэш последний раз чистился от старого
}

func (c *nameCache) add(a dnswatch.Answer, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.by == nil || len(c.by) > maxNamedAddrs || now.Sub(c.pruned) > nameTTL {
		c.forget(now)
		c.pruned = now
	}
	for _, addr := range a.Addrs {
		names := c.by[addr]
		if names == nil {
			names = map[string]time.Time{}
			c.by[addr] = names
		}
		if _, ok := names[a.Name]; !ok && len(names) >= maxAddrNames {
			oldest := ""
			for n, at := range names {
				if oldest == "" || at.Before(names[oldest]) {
					oldest = n
				}
			}
			delete(names, oldest)
		}
		names[a.Name] = now
	}
}

// forget убирает имена старше nameTTL; если и так тесно — всё. Вызывать под
// c.mu.
func (c *nameCache) forget(now time.Time) {
	for addr, names := range c.by {
		for n, at := range names {
			if now.Sub(at) > nameTTL {
				delete(names, n)
			}
		}
		if len(names) == 0 {
			delete(c.by, addr)
		}
	}
	if c.by == nil || len(c.by) > maxNamedAddrs {
		c.by = map[netip.Addr]map[string]time.Time{}
	}
}

// of — имена адреса addr, ответы о которых пришли не раньше since, по порядку.
func (c *nameCache) of(addr netip.Addr, since time.Time) []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []string
	for n, at := range c.by[addr.Unmap()] {
		if !at.Before(since) {
			out = append(out, n)
		}
	}
	slices.Sort(out)
	return out
}

// listenLoop держит слушателя ответов DNS на интерфейсе, через который идёт
// обучение, — проверенном туннеле маршрута по умолчанию, — пока есть
// приложения. Только туннель: ответы, пришедшие мимо него, мог подделать
// кто угодно в локальной сети. Туннель сменился — слушатель тоже; слушатель
// упал — новая попытка не чаще раза в минуту.
func (e *engine) listenLoop(ctx context.Context) {
	if e.d.Answers == nil {
		return
	}
	tick := time.NewTicker(e.d.ScanEvery)
	defer tick.Stop()
	var (
		cur    string
		stop   = func() {}
		failed = make(chan time.Time, 1)
		retry  time.Time
	)
	defer func() { stop() }()
	for {
		select {
		case at := <-failed:
			cur, retry = "", at.Add(time.Minute)
		default:
		}
		if want := e.listenIface(); want != cur && e.d.Now().After(retry) {
			stop()
			cur, stop = want, func() {}
			if want != "" {
				lctx, cancel := context.WithCancel(ctx)
				stop = cancel
				go func() {
					err := e.d.Answers.Listen(lctx, want, func(a dnswatch.Answer) { e.names.add(a, e.d.Now()) })
					if err != nil && lctx.Err() == nil {
						e.d.Logf("ответы DNS на %s: %v", want, err)
						select {
						case failed <- e.d.Now():
						default:
						}
					}
				}()
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// listenIface — где слушать ответы DNS: туннель маршрута по умолчанию, если
// его выход проверен и есть приложения; пусто — нигде.
func (e *engine) listenIface() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.apps) == 0 || !slices.Contains(e.prot.OpenIfaces, e.def) {
		return ""
	}
	return e.def
}

// learnNames — имена, которые стоят за адресом addr нового соединения
// приложения id и которые оно ещё не держит. Имя — приложению, только если
// ответ пришёл перед этим соединением: на общем адресе CDN иначе к нему
// приписались бы сайты, открытые в браузере. Забытое человеком не учится.
// Вызывать под e.mu.
func (e *engine) learnNames(id string, addr netip.Addr, now time.Time) []string {
	var out []string
	for _, name := range e.names.of(addr, now.Add(-e.d.ScanEvery-answerLead)) {
		if d, ok := e.protected[name]; ok && d.apps[id] {
			continue
		}
		if a := e.apps[id]; a != nil && forgotten(a.cfg.Forgotten, name) {
			continue
		}
		if learn.Domain(name) && resolver.ValidDomain(name) && e.appDomains(id)+len(out) < maxAppDomains {
			out = append(out, name)
		}
	}
	return out
}

// ownSites оставляет из names имена тех зарегистрированных доменов, что у
// приложения id уже есть (api.anthropic.com → statsig.anthropic.com). Так
// учится обученная консольная программа. Вызывать под e.mu.
func (e *engine) ownSites(id string, names []string) []string {
	sites := map[string]bool{}
	for name, d := range e.protected {
		if site, err := publicsuffix.EffectiveTLDPlusOne(name); err == nil && d.apps[id] {
			sites[site] = true
		}
	}
	return slices.DeleteFunc(names, func(name string) bool {
		site, err := publicsuffix.EffectiveTLDPlusOne(name)
		return err != nil || !sites[site]
	})
}

// appDomains — сколько доменов держит приложение id. Вызывать под e.mu.
func (e *engine) appDomains(id string) int {
	n := 0
	for _, d := range e.protected {
		if d.apps[id] {
			n++
		}
	}
	return n
}
