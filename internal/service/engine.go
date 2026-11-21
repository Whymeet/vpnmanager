package service

import (
	"context"
	"fmt"
	"net/netip"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"appguard/internal/catalog"
	"appguard/internal/config"
	"appguard/internal/core"
	"appguard/internal/enforce"
	"appguard/internal/exitcheck"
	"appguard/internal/ipc"
	"appguard/internal/journal"
	"appguard/internal/learn"
	"appguard/internal/resolver"
)

// checkTimeout — сколько ждать одну проверку выхода: оба источника с запасным.
const checkTimeout = 6 * time.Second

// engine ведёт пути и правила файрвола: применяет снимки сети, проверяет выход
// каждого туннеля — при любой перемене в сети и раз в CheckEvery, — держит
// файрвол в согласии с решением ядра и пишет переходы в журнал.
type engine struct {
	d       Deps
	journal *journal.Journal
	checker *exitcheck.Checker
	results chan checked
	probes  chan probed

	cfg    configStore
	lookup func(ctx context.Context, domain string) ([]netip.Addr, error)

	// applyMu держит reapply целиком: правила, вычисленные позже, и применяются
	// позже, даже когда reapply зовут цикл движка и команды клиента одновременно.
	applyMu sync.Mutex

	mu        sync.Mutex
	state     *core.State
	def       string                  // интерфейс маршрута по умолчанию (для статуса)
	protected map[string]*domainState // домен → адреса и владельцы
	manual    []netip.Addr            // адреса, защищённые вручную без домена: protect, import
	inflight  map[pathKey]bool
	probing   map[pathKey]bool
	apps      map[string]*appState // идентификатор пакета → приложение
	catalog   catalog.Catalog      // по нему приложения защищаются сразу
	policy    core.Policy          // правило и мои выходы
	exits     []config.Exit        // мои выходы с именами, как в настройках
	prot      core.Protection
	haveProt  bool
	applied   enforce.Rules // что исполнитель применил последним успешно
	haveRules bool
	failed    string // ошибка последнего применения; пусто — применено
	dnsFailed bool   // домены не направились на службу: повторяет retryFailed
	cleared   bool   // правила сняты удалением: больше их не ставить
	// servers — серверы VPN: к ним клиент ходил мимо туннеля при проверенном
	// выходе. Сервер на адресе защищённого сервиса разрешён на физическом
	// интерфейсе.
	servers map[netip.Addr]bool
	names   nameCache   // какие имена стоят за адресами: ответы DNS туннеля
	bg      *background // фоновые запросы (resolveLater): остановка их ждёт
	// notifyOff — уведомления выключены; notified — текст последнего события
	// для уведомления (открыто с выходом или закрыто с причиной); closedSince —
	// с какого времени сервисы закрыты (нулевое — открыты).
	notifyOff   bool
	notified    string
	closedSince time.Time
	hub         hub       // подписчики на уведомления по каналу службы
	sync        syncState // ежедневное обновление каталога
}

// configStore — то, что движку нужно от настроек: изменить и записать.
type configStore interface {
	Update(mutate func(*config.Settings)) error
}

// pathKey — путь конкретного поколения: проверка прежнего туннеля с тем же
// именем к новому не относится.
type pathKey struct {
	name string
	gen  int
}

type checked struct {
	key   pathKey
	check core.Check
}

type probed struct {
	key   pathKey
	probe core.Probe
}

func newEngine(d Deps, j *journal.Journal, protected []config.Protected, manual []string, list []config.App) *engine {
	e := &engine{
		d:         d,
		journal:   j,
		checker:   &exitcheck.Checker{Fetch: d.Fetch, Now: d.Now},
		results:   make(chan checked),
		probes:    make(chan probed),
		probing:   map[pathKey]bool{},
		state:     core.NewState(),
		protected: domainsFromConfig(protected),
		inflight:  map[pathKey]bool{},
		apps:      map[string]*appState{},
		servers:   map[netip.Addr]bool{},
		policy:    core.Policy{Rule: core.RuleAny, Exits: map[netip.Addr]string{}},
	}
	for _, a := range list {
		e.apps[a.ID] = newAppState(a)
	}
	e.manual = parseAddrs(manual)
	e.bg = newBackground()
	return e
}

func (e *engine) run(ctx context.Context) {
	// Фоновые запросы пишут настройки: остановка прерывает их и ждёт — после
	// циклов движка, которые сами могут их запустить.
	defer e.bg.Stop()
	e.loadCatalog()
	e.remindStale()
	snaps := e.d.Network.Watch(ctx)
	// Первые правила ставятся по первому снимку сети, если он пришёл быстро:
	// порт системного прокси, закрытый прошлым запуском, не должен открыться
	// до первой проверки выхода. Правила по сохранённым адресам ставятся сразу
	// после этого: до первой проверки всё закрыто, но таблицы уже наполнены.
	select {
	case snap, ok := <-snaps:
		if ok {
			e.observe(snap)
		} else {
			snaps = nil
		}
	case <-time.After(firstSnapshotWait):
	case <-ctx.Done():
	}
	e.reapply()
	e.syncDNS()
	if e.d.Ready != nil {
		e.d.Ready()
	}
	e.checkAll(ctx) // пути из первого снимка проверяются сразу, не ждут первого тика
	// Обучение пишет настройки: остановка ждёт его, иначе запись легла бы уже
	// после выхода службы, поверх настроек следующего её запуска.
	var wg sync.WaitGroup
	defer wg.Wait()
	wg.Go(func() { e.learnLoop(ctx) })
	wg.Go(func() { e.listenLoop(ctx) })
	tick := time.NewTicker(e.d.CheckEvery)
	defer tick.Stop()
	prune := time.NewTicker(time.Hour)
	defer prune.Stop()
	probeTick := time.NewTicker(e.d.ProbeEvery)
	defer probeTick.Stop()
	guard := time.NewTicker(e.d.GuardEvery)
	defer guard.Stop()
	for {
		select {
		case <-ctx.Done():
			e.closeAll()
			return
		case <-guard.C:
			e.guard()
			if e.d.Alive != nil {
				e.d.Alive()
			}
		case snap, ok := <-snaps:
			if !ok {
				e.d.Logf("наблюдатель сети остановился")
				snaps = nil
				continue
			}
			e.observe(snap)
			e.reapply()
			e.checkAll(ctx)
			e.probeAll(ctx, false) // зонд — при каждом событии сети
		case <-tick.C:
			e.retryFailed()
			e.checkAll(ctx)
			e.notifyDue()
		case r := <-e.results:
			e.mu.Lock()
			delete(e.inflight, r.key)
			events := e.state.Checked(r.key.name, r.key.gen, r.check, e.d.Now())
			e.mu.Unlock()
			e.record(events)
			if r.check.Outcome == core.Verified {
				e.confirmExit(r.check.Exit)
			}
			e.reapply()
			e.probeAll(ctx, true) // и сразу, как только выход пути проверен
		case <-probeTick.C:
			e.probeAll(ctx, false) // и раз в ProbeEvery
		case r := <-e.probes:
			e.mu.Lock()
			delete(e.probing, r.key)
			events := e.state.Probed(r.key.name, r.key.gen, r.probe, e.d.Now())
			e.mu.Unlock()
			e.record(events)
		case <-prune.C:
			e.journal.Prune()
			e.remindStale()
		}
	}
}

// firstSnapshotWait — сколько при старте ждать первый снимок сети, прежде чем
// поставить правила без него.
const firstSnapshotWait = time.Second

// observe применяет снимок сети к путям и журналит перемены.
func (e *engine) observe(snap core.Snapshot) {
	e.mu.Lock()
	events := e.state.Observe(snap, e.d.Now())
	e.def = snap.DefaultIface
	e.mu.Unlock()
	e.record(events)
}

// checkAll запускает проверку каждого пути, если она ещё не идёт.
func (e *engine) checkAll(ctx context.Context) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, p := range e.state.Paths() {
		key := pathKey{p.Tunnel.Name, p.Gen}
		if e.inflight[key] {
			continue
		}
		e.inflight[key] = true
		go func(t core.Tunnel) {
			cctx, cancel := context.WithTimeout(ctx, checkTimeout)
			defer cancel()
			c := e.checker.Check(cctx, t)
			select {
			case e.results <- checked{key, c}:
			case <-ctx.Done():
			}
		}(p.Tunnel)
	}
}

// probeAll запускает зонд «Россия напрямую» на путях с проверенным выходом.
// onlyNew — только на тех, где зонда ещё не было.
func (e *engine) probeAll(ctx context.Context, onlyNew bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, p := range e.state.Paths() {
		key := pathKey{p.Tunnel.Name, p.Gen}
		if p.Check.Outcome != core.Verified || e.probing[key] || (onlyNew && p.Probe.State != core.ProbeUnknown) {
			continue
		}
		e.probing[key] = true
		go func(t core.Tunnel, exit core.Exit) {
			cctx, cancel := context.WithTimeout(ctx, checkTimeout)
			defer cancel()
			phys, ok := e.d.Physical()
			pr := e.checker.Probe(cctx, t, exit, phys, ok)
			select {
			case e.probes <- probed{key, pr}:
			case <-ctx.Done():
			}
		}(p.Tunnel, p.Check.Exit)
	}
}

// reapply сводит решение ядра и защищённые адреса в правила файрвола, журналит
// смену состояния защиты и, если правила изменились, отдаёт их исполнителю.
// Ошибка — правила не применились (её же видно в журнале).
func (e *engine) reapply() error {
	e.applyMu.Lock()
	defer e.applyMu.Unlock()
	phys, physOK := e.d.Physical()

	e.mu.Lock()
	if e.cleared {
		e.mu.Unlock()
		return nil
	}
	prot := e.state.Protect(e.policy)
	rules := enforce.Rules{OpenIfaces: prot.OpenIfaces, V4: e.addrs(false), V6: e.addrs(true), ClosedProxies: proxyPorts(prot, false),
		Apps: e.appPaths(), OpenAddrs: e.openAddrs(prot), OpenProxies: openProxies(prot)}
	if physOK {
		rules.Servers = e.cdnServers(rules)
		if len(rules.Servers) > 0 {
			rules.Physical = phys.Name
		}
	}
	events := e.proxyEvents(prot)
	if transition := e.protectionEvent(prot); transition != nil {
		events = append(events, *transition)
	}
	note := e.notification(prot)
	for _, a := range rules.Servers {
		if !slices.Contains(e.applied.Servers, a) {
			events = append(events, core.Event{Time: e.d.Now(), Kind: core.KindService, IP: a.String(),
				Text: fmt.Sprintf("сервер VPN %s — на том же адресе, что и защищённый сервис (VPN через CDN): на физическом интерфейсе он разрешён, иначе клиент VPN не переподключится", a)})
		}
	}
	e.prot, e.haveProt = prot, true
	need := !e.haveRules || e.failed != "" || !rules.Equal(e.applied)
	e.mu.Unlock()

	e.record(events)
	e.notify(note)
	if !need {
		return nil
	}
	err := e.d.Enforce.Apply(rules)

	e.mu.Lock()
	prev := e.failed
	if err == nil {
		e.applied, e.haveRules, e.failed = rules, true, ""
	} else {
		e.failed = err.Error()
	}
	now := e.failed
	e.mu.Unlock()

	switch {
	case err != nil && now != prev:
		e.d.Logf("файрвол: %v", err)
		e.record([]core.Event{{Time: e.d.Now(), Kind: core.KindError, Text: "файрвол: не удалось применить правила — " + now}})
	case err == nil && prev != "":
		e.record([]core.Event{{Time: e.d.Now(), Kind: core.KindError, Text: "файрвол: правила снова применены"}})
	}
	return err
}

// retryFailed повторяет применение правил и домены, если прошлый раз не удался.
func (e *engine) retryFailed() {
	e.mu.Lock()
	failed, dns := e.failed != "", e.dnsFailed
	e.mu.Unlock()
	if failed {
		e.reapply()
	}
	if dns {
		e.syncDNS()
	}
}

// protectionEvent возвращает строку журнала, если защита перешла из открытого в
// закрытое или наоборот (или сменился выход, которым открыто). Пока идёт первая
// проверка (Reason пуст, закрыто), событие не пишется — о проверке уже сказал
// туннель. Возвращает nil, если писать нечего. Вызывать под e.mu.
func (e *engine) protectionEvent(prot core.Protection) *core.Event {
	if e.haveProt && prot.Open == e.prot.Open && prot.Exit == e.prot.Exit && prot.Reason == e.prot.Reason {
		return nil
	}
	now := e.d.Now()
	if prot.Open {
		return &core.Event{Time: now, Kind: core.KindOpen, IP: prot.Exit.IP.String(), Country: prot.Exit.Country,
			Text: fmt.Sprintf("сервисы открыты: выход %s, %s", prot.Exit.IP, core.CountryName(prot.Exit.Country))}
	}
	if prot.Reason == "" {
		return nil
	}
	return &core.Event{Time: now, Kind: core.KindClosed, Text: "сервисы закрыты: " + prot.Reason}
}

// notification — уведомление о смене защиты: сервисы открылись или сменили
// выход (адрес и страна выхода) либо закрылись (причина). Пустой текст —
// уведомлять не о чем. Одно уведомление на событие: тот же текст подряд не
// повторяется, а пока идёт проверка (закрыто без причины), молчим.
//
// О закрытии — только если оно длится дольше NotifyAfter: VPN, который
// переподключается, не дёргает человека. Сервисы при этом закрыты сразу,
// задерживается одно уведомление; дождалось — его отдаёт notifyDue. После
// такого обрыва открытие тем же выходом — то же событие, что и до него.
//
// Последнее событие помнится и при выключенных уведомлениях: включили —
// уведомление придёт о следующем событии, а не о том, что случилось без них.
// Вызывать под e.mu.
func (e *engine) notification(prot core.Protection) core.Event {
	now := e.d.Now()
	if prot.Open {
		e.closedSince = time.Time{}
	} else if e.closedSince.IsZero() {
		e.closedSince = now
	}
	text := prot.AppsText()
	if text == "" || text == e.notified || !prot.Open && now.Sub(e.closedSince) < e.d.NotifyAfter {
		return core.Event{}
	}
	e.notified = text
	if e.notifyOff {
		return core.Event{}
	}
	note := core.Event{Time: now, Kind: prot.Kind, Text: text}
	if prot.Open {
		note.IP, note.Country = prot.Exit.IP.String(), prot.Exit.Country
	}
	return note
}

// notifyDue отдаёт уведомление о закрытии, которое дождалось NotifyAfter: пока
// оно длилось, правила могли больше не пересчитываться — сеть не менялась.
func (e *engine) notifyDue() {
	e.mu.Lock()
	var note core.Event
	if e.haveProt && !e.cleared {
		note = e.notification(e.prot)
	}
	e.mu.Unlock()
	e.notify(note)
}

// notify показывает уведомление (пустой текст — нечего) и раздаёт его
// подписчикам канала службы.
func (e *engine) notify(note core.Event) {
	if note.Text == "" {
		return
	}
	e.hub.publish(note)
	if e.d.Notify != nil {
		go func() {
			if err := e.d.Notify.Notify(note.Text); err != nil {
				e.d.Logf("%v", err)
			}
		}()
	}
}

// protectionNow — защита сейчас: её показывает значок у часов.
func (e *engine) protectionNow() ipc.Protection {
	e.mu.Lock()
	defer e.mu.Unlock()
	p := ipc.Protection{NotifyOff: e.notifyOff}
	switch {
	case !e.haveProt:
	case e.prot.Open:
		p.Open, p.IP, p.Country = true, e.prot.Exit.IP.String(), e.prot.Exit.Country
	default:
		p.Reason = e.prot.Reason
	}
	return p
}

// setNotify включает или выключает уведомления. Журнал пишется всегда.
func (e *engine) setNotify(on bool) error {
	if err := e.cfg.Update(func(s *config.Settings) { s.NotifyOff = !on }); err != nil {
		return err
	}
	e.mu.Lock()
	e.notifyOff = !on
	e.mu.Unlock()
	text := "уведомления выключены — журнал пишется, как прежде"
	if on {
		text = "уведомления включены"
	}
	e.record([]core.Event{{Time: e.d.Now(), Kind: core.KindService, Text: text}})
	return nil
}

func (e *engine) notifyIsOff() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.notifyOff
}

// proxyEvents — строки журнала о портах системного прокси, которые открылись
// или закрылись с новой причиной. Закрытие, пока выход проверяется, не
// пишется: о нём сказал сам прокси, когда появился. Вызывать под e.mu.
func (e *engine) proxyEvents(prot core.Protection) []core.Event {
	var events []core.Event
	now := e.d.Now()
	for _, g := range prot.Proxies {
		i := slices.IndexFunc(e.prot.Proxies, func(old core.ProxyGate) bool { return old.Name == g.Name })
		if i >= 0 {
			if old := e.prot.Proxies[i]; old.Open == g.Open && old.Exit == g.Exit && old.Reason == g.Reason {
				continue
			}
		}
		switch {
		case g.Open:
			events = append(events, core.Event{Time: now, Kind: core.KindProxy, Iface: g.Name, IP: g.Exit.IP.String(), Country: g.Exit.Country,
				Text: fmt.Sprintf("%s: порт открыт — выход %s, %s", g.Name, g.Exit.IP, core.CountryName(g.Exit.Country))})
		case g.Reason != "":
			events = append(events, core.Event{Time: now, Kind: core.KindProxy, Iface: g.Name,
				Text: fmt.Sprintf("%s: %s — %s", g.Name, g.Reason, core.PortClosed)})
		}
	}
	return events
}

// openProxies — порты прокси с проверенным выходом.
func openProxies(prot core.Protection) []netip.AddrPort {
	var out []netip.AddrPort
	for _, g := range prot.Proxies {
		if g.Open {
			for _, a := range g.Proxy.Addrs {
				out = append(out, netip.AddrPortFrom(a, g.Proxy.Port))
			}
		}
	}
	slices.SortFunc(out, netip.AddrPort.Compare)
	return slices.Compact(out)
}

// proxyPorts — порты прокси, которые файрвол закрывает: у каждого закрытого
// прокси (all — у каждого вообще) на каждом его адресе.
func proxyPorts(prot core.Protection, all bool) []netip.AddrPort {
	var out []netip.AddrPort
	for _, g := range prot.Proxies {
		if g.Open && !all {
			continue
		}
		for _, a := range g.Proxy.Addrs {
			out = append(out, netip.AddrPortFrom(a, g.Proxy.Port))
		}
	}
	slices.SortFunc(out, netip.AddrPort.Compare)
	return slices.Compact(out)
}

// loadServers берёт запомненные серверы VPN из настроек.
func (e *engine) loadServers(list []string) {
	for _, s := range list {
		if a, err := netip.ParseAddr(s); err == nil {
			e.servers[a] = true
		}
	}
}

// cdnServers — серверы VPN на адресах защищённых сервисов из r. Вызывать под
// e.mu.
func (e *engine) cdnServers(r enforce.Rules) []netip.Addr {
	var out []netip.Addr
	for _, a := range slices.Concat(r.V4, r.V6) {
		if e.servers[a] {
			out = append(out, a)
		}
	}
	return out
}

// guard — сторож: сверяет правила файрвола с применёнными и, если другая
// программа их сбросила (перезагрузила основной набор, очистила якорь,
// выключила pf), восстанавливает и пишет об этом в журнал.
func (e *engine) guard() {
	e.applyMu.Lock()
	defer e.applyMu.Unlock()
	e.mu.Lock()
	ok := e.haveRules && e.failed == "" && !e.cleared
	r := e.applied
	e.mu.Unlock()
	if !ok {
		return // правил ещё нет или они не применились — их повторяет retryFailed
	}
	drift := e.d.Enforce.Verify(r)
	if drift == nil {
		return
	}
	e.record([]core.Event{{Time: e.d.Now(), Kind: core.KindGuard, Text: "правила файрвола сброшены другой программой (" + drift.Error() + ") — восстанавливаю"}})
	if err := e.d.Enforce.Apply(r); err != nil {
		e.mu.Lock()
		e.failed = err.Error()
		e.mu.Unlock()
		e.d.Logf("сторож: %v", err)
		e.record([]core.Event{{Time: e.d.Now(), Kind: core.KindError, Text: "файрвол: не удалось восстановить правила — " + err.Error()}})
		return
	}
	e.record([]core.Event{{Time: e.d.Now(), Kind: core.KindGuard, Text: "правила файрвола восстановлены"}})
}

// closeAll закрывает все пути перед остановкой службы: без неё выход никто не
// перепроверяет, и открытым не должен остаться ни один туннель и ни один порт
// прокси. Таблицы и серверы VPN остаются, как были.
func (e *engine) closeAll() {
	e.applyMu.Lock()
	defer e.applyMu.Unlock()
	e.mu.Lock()
	if e.cleared || !e.haveRules {
		e.mu.Unlock()
		return
	}
	r := e.applied
	r.OpenIfaces, r.OpenAddrs, r.OpenProxies, r.ClosedProxies = nil, nil, nil, proxyPorts(e.prot, true)
	e.mu.Unlock()
	if err := e.d.Enforce.Apply(r); err != nil {
		e.d.Logf("не удалось закрыть пути перед остановкой: %v", err)
		return
	}
	e.record([]core.Event{{Time: e.d.Now(), Kind: core.KindClosed, Text: "служба останавливается — сервисы закрыты до её запуска"}})
}

// clear снимает правила файрвола при удалении. После него движок правил больше
// не ставит: ни сторож, ни остановка не вернут их назад. Не вышло — правила
// ставятся заново, как после любой ошибки.
func (e *engine) clear() error {
	e.applyMu.Lock()
	defer e.applyMu.Unlock()
	e.mu.Lock()
	e.cleared = true
	e.mu.Unlock()
	err := e.d.Enforce.Clear()
	if err != nil {
		e.mu.Lock()
		e.cleared, e.failed = false, err.Error()
		e.mu.Unlock()
	}
	return err
}

// learnServers запоминает серверы VPN: удалённые адреса установленных
// соединений самого клиента VPN с адреса физического интерфейса. Клиент —
// процесс, который держит туннель маршрута по умолчанию или слушает порт
// системного прокси. Соединения других программ в счёт не идут: иначе любая из
// них, привязав сокет к физическому интерфейсу, открыла бы себе защищённый
// адрес — lsof показывает и попытку, которую pf отбросил, — а в режиме прокси
// с физического адреса ходят все. Запоминается, только пока выход пути
// проверен, а зонд видит, что «Россию напрямую» клиент не отправляет: иначе
// мимо туннеля уходят и российские узлы сервисов.
func (e *engine) learnServers(ctx context.Context) error {
	e.mu.Lock()
	tunnel := ""
	var proxies []netip.AddrPort
	for _, p := range e.state.Paths() {
		if p.Check.Outcome != core.Verified || p.Probe.State != core.ProbeThrough {
			continue
		}
		if px := p.Tunnel.Proxy; px != nil {
			for _, a := range px.Addrs {
				proxies = append(proxies, netip.AddrPortFrom(a, px.Port))
			}
		} else if p.Tunnel.Name == e.def {
			tunnel = e.def
		}
	}
	e.mu.Unlock()
	local, ok := e.d.PhysicalAddr()
	if tunnel == "" && len(proxies) == 0 || !ok {
		return nil
	}
	conns, err := e.d.Apps.Peers(ctx, local)
	if err != nil {
		return err
	}
	var pids []int
	for _, c := range conns {
		if c.Established() && !slices.Contains(pids, c.PID) {
			pids = append(pids, c.PID)
		}
	}
	var clients []int
	if tunnel != "" {
		owners, err := e.d.Apps.TunnelOwners(ctx, tunnel, pids)
		if err != nil {
			return err
		}
		clients = append(clients, owners...)
	}
	if len(proxies) > 0 {
		owners, err := e.d.Apps.ProxyOwners(ctx, proxies, pids)
		if err != nil {
			return err
		}
		clients = append(clients, owners...)
	}
	e.mu.Lock()
	var added []netip.Addr
	for _, c := range conns {
		a := c.Remote.Addr().Unmap()
		if c.Established() && slices.Contains(clients, c.PID) && a.IsGlobalUnicast() && !a.IsPrivate() && !e.servers[a] {
			e.servers[a] = true
			added = append(added, a)
		}
	}
	list := make([]string, 0, len(e.servers))
	for a := range e.servers {
		list = append(list, a.String())
	}
	e.mu.Unlock()
	if len(added) == 0 {
		return nil
	}
	slices.Sort(list)
	if err := e.cfg.Update(func(s *config.Settings) { s.VPNClientServers = list }); err != nil {
		return err
	}
	return e.reapply()
}

// addrs — защищённые адреса нужного семейства (v6=true — IPv6): адреса
// защищённых доменов и выученные адреса приложений. Вызывать под e.mu.
func (e *engine) addrs(v6 bool) []netip.Addr {
	seen := map[netip.Addr]bool{}
	var out []netip.Addr
	for _, d := range e.protected {
		for _, s := range d.addrs {
			a, err := netip.ParseAddr(s)
			if err != nil || a.Is6() != v6 || seen[a] {
				continue
			}
			seen[a] = true
			out = append(out, a)
		}
	}
	out = append(out, e.appAddrs(v6, seen)...)
	for _, a := range e.manual {
		if a.Is6() == v6 && !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	slices.SortFunc(out, netip.Addr.Compare)
	return out
}

// appPaths — пути защищённых приложений: на Windows фильтры ставятся на них.
func (e *engine) appPaths() []string {
	out := make([]string, 0, len(e.apps))
	for _, a := range e.apps {
		out = append(out, a.cfg.Path)
	}
	slices.Sort(out)
	return out
}

// openAddrs — локальные адреса открытых туннелей: на Windows приложениям сеть
// открыта только с них.
func (e *engine) openAddrs(prot core.Protection) []netip.Addr {
	var out []netip.Addr
	for _, p := range e.state.Paths() {
		if p.Tunnel.Proxy == nil && slices.Contains(prot.OpenIfaces, p.Tunnel.Name) {
			out = append(out, p.Tunnel.Addrs...)
		}
	}
	slices.SortFunc(out, netip.Addr.Compare)
	return slices.Compact(out)
}

// protect закрывает адреса домена и направляет его имена на резолвер службы.
// Адреса для старта даёт тот же резолвер; пустой ответ — ошибка, иначе защита
// оказалась бы пустой. Вместо домена можно дать адрес: он закрывается сам по
// себе.
func (e *engine) protect(ctx context.Context, domain string) ([]netip.Addr, error) {
	if addr, err := netip.ParseAddr(domain); err == nil {
		if !learn.Acceptable(addr, 443) {
			return nil, fmt.Errorf("%s — адрес, который нельзя закрывать: локальный, служебный или нужен самой службе", addr)
		}
		addr = addr.Unmap()
		e.mu.Lock()
		if !slices.Contains(e.manual, addr) {
			e.manual = append(e.manual, addr)
		}
		e.mu.Unlock()
		if err := e.saveManual(); err != nil {
			return nil, err
		}
		return []netip.Addr{addr}, e.reapply()
	}
	domain = resolver.Normalize(domain)
	if !resolver.ValidDomain(domain) {
		return nil, fmt.Errorf("%q — не имя домена: нужно вроде notion.so", domain)
	}
	addrs, err := e.lookup(ctx, domain)
	if err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("у домена %s не нашлось адресов", domain)
	}
	e.mu.Lock()
	d := e.domain(domain)
	d.manual = true
	d.addrs = union(d.addrs, addrs)
	e.mu.Unlock()
	if err := e.saveDomains(); err != nil {
		return nil, err
	}
	if err := e.reapply(); err != nil {
		return nil, err
	}
	e.syncDNS()
	return addrs, nil
}

// domain — защищённый домен, заводится при первом обращении. Вызывать под e.mu.
func (e *engine) domain(name string) *domainState {
	d, ok := e.protected[name]
	if !ok {
		d = &domainState{apps: map[string]bool{}}
		e.protected[name] = d
	}
	return d
}

// unprotect снимает защиту, поставленную командой protect или import. Домен
// остаётся, если он принадлежит ещё и приложению из каталога; адрес остаётся
// в таблицах, если он выучен приложением или принадлежит защищённому домену.
func (e *engine) unprotect(domain string) (bool, error) {
	if addr, err := netip.ParseAddr(domain); err == nil {
		e.mu.Lock()
		i := slices.Index(e.manual, addr.Unmap())
		if i >= 0 {
			e.manual = slices.Delete(e.manual, i, i+1)
		}
		e.mu.Unlock()
		if i < 0 {
			return false, nil
		}
		if err := e.saveManual(); err != nil {
			return false, err
		}
		return true, e.reapply()
	}
	domain = resolver.Normalize(domain)
	e.mu.Lock()
	d, ok := e.protected[domain]
	had := ok && d.manual
	if had {
		d.manual = false
		if !d.owned() {
			delete(e.protected, domain)
		}
	}
	e.mu.Unlock()
	if !had {
		return false, nil
	}
	if err := e.saveDomains(); err != nil {
		return false, err
	}
	e.syncDNS()
	return true, e.reapply()
}

// learn добавляет адреса, которые резолвер узнал для домена. Новые адреса
// записываются в настройки и в таблицы файрвола; вернуть управление резолверу,
// а значит и ответить программе, можно только после этого.
func (e *engine) learn(_ context.Context, domain string, addrs []netip.Addr) error {
	e.mu.Lock()
	d, ok := e.protected[domain]
	if !ok {
		e.mu.Unlock()
		return fmt.Errorf("домен %s не защищён", domain)
	}
	merged := union(d.addrs, addrs)
	if len(merged) == len(d.addrs) {
		e.mu.Unlock()
		return nil // все адреса уже в таблицах
	}
	d.addrs = merged
	e.mu.Unlock()
	if err := e.saveDomains(); err != nil {
		return err
	}
	return e.reapply()
}

// match — защищённый домен, к которому относится имя: сам домен или его
// поддомен. Из нескольких подходящих берётся самый длинный.
func (e *engine) match(name string) (string, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	best := ""
	for d := range e.protected {
		if (name == d || strings.HasSuffix(name, "."+d)) && len(d) > len(best) {
			best = d
		}
	}
	return best, best != ""
}

// syncDNS направляет на резолвер службы ровно защищённые домены. Домен, для
// которого в системе уже есть чужой резолвер, журналится: его имена мимо
// службы, и новые адреса не попадут в таблицы.
func (e *engine) syncDNS() {
	skipped, err := e.d.SystemDNS.Set(e.protectedList())
	e.mu.Lock()
	again := e.dnsFailed
	e.dnsFailed = err != nil
	e.mu.Unlock()
	if err != nil && !again { // повторы журнал не засоряют
		e.d.Logf("резолверы системы: %v", err)
		e.record([]core.Event{{Time: e.d.Now(), Kind: core.KindError, Text: "не удалось направить защищённые домены на службу: " + err.Error()}})
	}
	where := "в /etc/resolver уже есть чужой файл"
	if runtime.GOOS == "windows" {
		where = "в таблице NRPT уже есть чужое правило"
	}
	for _, d := range skipped {
		e.record([]core.Event{{Time: e.d.Now(), Kind: core.KindError,
			Text: fmt.Sprintf("для %s %s — имена этого домена идут мимо службы", d, where)}})
	}
}

// union — адреса cur и новые из add строками, без повторов.
func union(cur []string, add []netip.Addr) []string {
	seen := map[string]bool{}
	for _, a := range cur {
		seen[a] = true
	}
	out := append([]string(nil), cur...)
	for _, a := range add {
		if s := a.String(); !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// protectedList — защищённые домены для ответа клиенту.
func (e *engine) protectedList() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]string, 0, len(e.protected))
	for d := range e.protected {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

func (e *engine) record(events []core.Event) {
	for _, ev := range events {
		if err := e.journal.Add(ev); err != nil {
			e.d.Logf("журнал: %v", err)
		}
	}
}

// paths — пути для статуса. Пустой список, а не nil: так клиент отличает «VPN
// нет» от службы старой версии, которая о путях не сообщает.
func (e *engine) paths() []ipc.PathStatus {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := []ipc.PathStatus{}
	for _, p := range e.state.Paths() {
		ps := ipc.PathStatus{
			Iface:   p.Tunnel.Name,
			State:   p.Check.Outcome.String(),
			Summary: p.Summary(),
			Default: p.Tunnel.Name == e.def,
		}
		if o := p.Check.Outcome; o == core.Verified || o == core.Russian {
			ps.IP, ps.Country = p.Check.Exit.IP.String(), p.Check.Exit.Country
		}
		ps.Direct = p.Probe.State == core.ProbeDirect
		if px := p.Tunnel.Proxy; px != nil {
			ps.Proxy, ps.Listener = true, px.Process
			if !slices.ContainsFunc(e.prot.Proxies, func(g core.ProxyGate) bool { return g.Name == p.Tunnel.Name && g.Open }) {
				ps.Summary += "; " + core.PortClosed
			}
		}
		out = append(out, ps)
	}
	return out
}
