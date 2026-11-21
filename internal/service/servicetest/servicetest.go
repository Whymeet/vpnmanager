// Package servicetest поднимает службу целиком с подменёнными адаптерами ОС —
// это шов, на котором тесты проверяют поведение: запросы идут через настоящий
// локальный канал, а система и сеть не трогаются.
package servicetest

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"appguard/internal/apps"
	"appguard/internal/core"
	"appguard/internal/dnswatch"
	"appguard/internal/enforce"
	"appguard/internal/ipc"
	"appguard/internal/paths"
	"appguard/internal/procs"
	"appguard/internal/resolver"
	"appguard/internal/service"

	"github.com/miekg/dns"
)

// Version — версия, под которой тестовая служба отвечает на статус.
const Version = "9.9.9"

// CheckEvery — как часто тестовая служба перепроверяет выход.
const CheckEvery = 50 * time.Millisecond

// GuardEvery — как часто сторож тестовой службы сверяет правила.
const GuardEvery = 20 * time.Millisecond

// Accounts — учётные записи с одним решением на всех.
type Accounts struct {
	Admin bool
	Owner bool // владеет любым путём: клоном, из которого поставлен appguard

	mu    sync.Mutex
	asked []int
}

func (a *Accounts) IsAdmin(p ipc.Peer) (bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.asked = append(a.asked, p.UID)
	return a.Admin, nil
}

func (a *Accounts) Name(ipc.Peer) string { return "student" }

func (a *Accounts) Owns(ipc.Peer, string) (bool, error) { return a.Owner, nil }

// Asked — о каких uid служба спрашивала права.
func (a *Accounts) Asked() []int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]int(nil), a.asked...)
}

// Installation — установка, которая только запоминает, что её сняли.
type Installation struct {
	Removed, Stopped atomic.Bool
	stop             func()
}

func (i *Installation) Remove() error {
	i.Removed.Store(true)
	return nil
}

// Stop ведёт себя как launchd после bootout: останавливает службу.
func (i *Installation) Stop() error {
	i.Stopped.Store(true)
	i.stop()
	return nil
}

// Network — сеть, которую тест меняет сам.
type Network struct {
	ch    chan core.Snapshot
	First core.Snapshot // с какого снимка начинает Watch; по умолчанию — пустая сеть
}

func NewNetwork() *Network { return &Network{ch: make(chan core.Snapshot, 16)} }

// Watch — как у настоящего наблюдателя: первым идёт текущий снимок.
func (n *Network) Watch(context.Context) <-chan core.Snapshot {
	n.ch <- n.First
	return n.ch
}

// Set — в сети теперь эти туннели.
func (n *Network) Set(tunnels ...core.Tunnel) {
	snap := core.Snapshot{Tunnels: tunnels}
	if len(tunnels) > 0 {
		snap.DefaultIface = tunnels[0].Name
	}
	n.ch <- snap
}

// SetProxy — в системе включён прокси px, а в сети эти туннели. Маршрут по
// умолчанию — первый туннель, без туннелей — физический интерфейс.
func (n *Network) SetProxy(px core.Proxy, tunnels ...core.Tunnel) {
	snap := core.Snapshot{Tunnels: tunnels, Proxies: []core.Proxy{px}, DefaultIface: PhysicalIface.Name}
	if len(tunnels) > 0 {
		snap.DefaultIface = tunnels[0].Name
	}
	n.ch <- snap
}

// Tunnel — туннель с именем name и адресом addr.
func Tunnel(name, addr string) core.Tunnel {
	return core.Tunnel{Name: name, Index: 40, Addrs: []netip.Addr{netip.MustParseAddr(addr)}}
}

// Proxy — системный HTTP-прокси на 127.0.0.1:port, порт слушает process.
func Proxy(port uint16, process string) core.Proxy {
	return core.Proxy{Scheme: "http", Host: "127.0.0.1", Port: port, Addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, Process: process}
}

// Web — внешние источники проверки выхода. Cloudflare и второй источник
// называют адрес IP и свои страны; пустая страна — источник не отвечает.
type Web struct {
	mu                 sync.Mutex
	ip                 string
	cloudflare, second string
	via                map[string]exitAnswer // ответы для отдельных путей
	secondHits         int
	gate               chan struct{} // пока открыт Hold, источники не отвечают
	direct, ruDown     bool          // «Россия напрямую» у клиента; российский сервис не отвечает
}

type exitAnswer struct{ ip, cloudflare, second string }

// Via — что источники отвечают на запросы через путь path (имя туннеля или
// «прокси адрес:порт»); остальным путям — как задал Set.
func (w *Web) Via(path, ip, cloudflare, second string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.via == nil {
		w.via = map[string]exitAnswer{}
	}
	w.via[path] = exitAnswer{ip, cloudflare, second}
}

// HomeIP — домашний адрес тестовой системы: его видит российский сервис через
// физический интерфейс.
const HomeIP = "95.24.0.1"

// PhysicalIface — физический интерфейс тестовой системы.
var PhysicalIface = core.Tunnel{Name: "en0", Index: 14, Addrs: []netip.Addr{PhysicalAddr}}

// RussiaDirect — клиент VPN отправляет российские адреса мимо туннеля: российский
// сервис и через туннель видит домашний адрес.
func (w *Web) RussiaDirect(on bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.direct = on
}

// RussianDown — российский сервис определения адреса не отвечает.
func (w *Web) RussianDown(down bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.ruDown = down
}

// Hold задерживает ответы источников до Release: так видно, что творится, пока
// проверка ещё идёт.
func (w *Web) Hold() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.gate = make(chan struct{})
}

// Release отпускает задержанные ответы.
func (w *Web) Release() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.gate != nil {
		close(w.gate)
		w.gate = nil
	}
}

// Set — что источники отвечают теперь.
func (w *Web) Set(ip, cloudflare, second string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.ip, w.cloudflare, w.second = ip, cloudflare, second
}

// SecondHits — сколько раз спрашивали второй источник.
func (w *Web) SecondHits() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.secondHits
}

func (w *Web) Get(ctx context.Context, t core.Tunnel, url string) ([]byte, error) {
	w.mu.Lock()
	gate := w.gate
	w.mu.Unlock()
	if gate != nil {
		select {
		case <-gate:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	a, ok := w.via[t.Name]
	if !ok {
		a = exitAnswer{w.ip, w.cloudflare, w.second}
	}
	if strings.Contains(url, "yandex") {
		if w.ruDown {
			return nil, errors.New("российский сервис молчит")
		}
		if t.Name == PhysicalIface.Name || w.direct {
			return fmt.Appendf(nil, "%q", HomeIP), nil
		}
		return fmt.Appendf(nil, "%q", a.ip), nil
	}
	if strings.Contains(url, "/cdn-cgi/trace") {
		if a.cloudflare == "" {
			return nil, errors.New("Cloudflare молчит")
		}
		return fmt.Appendf(nil, "fl=1\nh=1.1.1.1\nip=%s\nloc=%s\nwarp=off\n", a.ip, a.cloudflare), nil
	}
	w.secondHits++
	if a.second == "" {
		return nil, errors.New("второй источник молчит")
	}
	return fmt.Appendf(nil, `{"ip":%q,"country":%q,"country_code":%q}`, a.ip, a.second, a.second), nil
}

// Enforcer — исполнитель правил, который только запоминает последнее состояние.
type Enforcer struct {
	mu      sync.Mutex
	rules   enforce.Rules
	history []enforce.Rules
	cleared bool
	fail    error
	reset   string // правила сбросила чужая программа: что именно
}

func (e *Enforcer) Apply(r enforce.Rules) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.fail != nil {
		return e.fail
	}
	e.rules, e.reset = r, ""
	e.history = append(e.history, r)
	return nil
}

// Reset — чужая программа сбросила правила файрвола; how — как (для журнала).
func (e *Enforcer) Reset(how string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules, e.reset = enforce.Rules{}, how
}

func (e *Enforcer) Verify(r enforce.Rules) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.reset != "" {
		return errors.New(e.reset)
	}
	if !e.rules.Equal(r) {
		return fmt.Errorf("стоят другие правила: %+v", e.rules)
	}
	return nil
}

// Fail заставляет Apply возвращать err (nil — снова работать).
func (e *Enforcer) Fail(err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.fail = err
}

// History — все применённые состояния по порядку.
func (e *Enforcer) History() []enforce.Rules {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]enforce.Rules(nil), e.history...)
}

func (e *Enforcer) Clear() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cleared = true
	e.rules = enforce.Rules{}
	return nil
}

// Reach — как pf ответил бы на соединение с to через интерфейс via: адрес из
// таблиц закрыт, если он не разрешённый сервер VPN на физическом интерфейсе.
func (e *Enforcer) Reach(ctx context.Context, via core.Tunnel, to netip.AddrPort) error {
	e.mu.Lock()
	r := e.rules
	e.mu.Unlock()
	a := to.Addr()
	blocked := slices.Contains(r.V4, a) || slices.Contains(r.V6, a)
	if blocked && !(via.Name == r.Physical && slices.Contains(r.Servers, a)) {
		return context.DeadlineExceeded // pf отбрасывает молча: ответа нет до таймаута
	}
	return nil
}

// Rules — последнее применённое состояние файрвола.
func (e *Enforcer) Rules() enforce.Rules {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.rules
}

// Cleared — снимали ли правила (удаление).
func (e *Enforcer) Cleared() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.cleared
}

// Notifier — уведомления, которые только запоминаются.
type Notifier struct {
	mu    sync.Mutex
	texts []string
}

func (n *Notifier) Notify(text string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.texts = append(n.texts, text)
	return nil
}

// Texts — показанные уведомления по порядку.
func (n *Notifier) Texts() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]string(nil), n.texts...)
}

// DNS — вышестоящий DNS из таблицы: имя → адреса. Неизвестное имя — NXDOMAIN.
type DNS struct {
	mu    sync.Mutex
	label string
	table map[string][]netip.Addr
	down  bool
}

// NewDNS — пустой вышестоящий DNS с именем label.
func NewDNS(label string) *DNS { return &DNS{label: label, table: map[string][]netip.Addr{}} }

// Maps задаёт, в какие адреса разрешается имя.
func (d *DNS) Maps(name string, addrs ...string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	var parsed []netip.Addr
	for _, a := range addrs {
		parsed = append(parsed, netip.MustParseAddr(a))
	}
	d.table[name] = parsed
}

// Down — DNS перестаёт (или снова начинает) отвечать.
func (d *DNS) Down(down bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.down = down
}

func (d *DNS) Name() string { return d.label }

func (d *DNS) Exchange(_ context.Context, q *dns.Msg) (*dns.Msg, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.down {
		return nil, fmt.Errorf("%s молчит", d.label)
	}
	m := new(dns.Msg)
	m.SetReply(q)
	qq := q.Question[0]
	addrs, ok := d.table[strings.ToLower(strings.TrimSuffix(qq.Name, "."))]
	if !ok {
		m.Rcode = dns.RcodeNameError
		return m, nil
	}
	hdr := dns.RR_Header{Name: qq.Name, Class: dns.ClassINET, Ttl: 60}
	for _, a := range addrs {
		switch {
		case qq.Qtype == dns.TypeA && a.Is4():
			hdr.Rrtype = dns.TypeA
			m.Answer = append(m.Answer, &dns.A{Hdr: hdr, A: a.AsSlice()})
		case qq.Qtype == dns.TypeAAAA && a.Is6():
			hdr.Rrtype = dns.TypeAAAA
			m.Answer = append(m.Answer, &dns.AAAA{Hdr: hdr, AAAA: a.AsSlice()})
		}
	}
	return m, nil
}

// SystemDNS — доменные резолверы системы, которые только запоминают домены.
type SystemDNS struct {
	mu      sync.Mutex
	domains []string
	foreign map[string]bool
	cleared bool
}

func (r *SystemDNS) Set(domains []string) ([]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var skipped []string
	r.domains = nil
	for _, d := range domains {
		if r.foreign[d] {
			skipped = append(skipped, d)
			continue
		}
		r.domains = append(r.domains, d)
	}
	return skipped, nil
}

func (r *SystemDNS) Clear() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.domains, r.cleared = nil, true
	return nil
}

// Foreign — у домена уже есть чужой резолвер.
func (r *SystemDNS) Foreign(domain string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.foreign == nil {
		r.foreign = map[string]bool{}
	}
	r.foreign[domain] = true
}

// Domains — домены, направленные на службу сейчас.
func (r *SystemDNS) Domains() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.domains...)
}

// Cleared — убирали ли резолверы (удаление).
func (r *SystemDNS) Cleared() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cleared
}

// Scanner — процессы и соединения приложений, которые задаёт тест.
type Scanner struct {
	mu    sync.Mutex
	acts  map[string]procs.Activity
	err   error
	seen  []procs.AppRef
	peers []procs.Conn
}

// VPNClientPID — процесс клиента VPN: он держит туннели тестовой системы.
const VPNClientPID = 4242

// VPNServer — клиент VPN держит соединение с addr мимо туннеля.
func (sc *Scanner) VPNServer(addr string) { sc.Bypass(VPNClientPID, "tcp", "ESTABLISHED", addr) }

// Bypass — у процесса pid есть сокет с адреса физического интерфейса на addr:
// протокол proto, состояние TCP state.
func (sc *Scanner) Bypass(pid int, proto, state, addr string) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.peers = append(sc.peers, procs.Conn{PID: pid, Proto: proto, State: state,
		Local: netip.AddrPortFrom(PhysicalAddr, 50000+uint16(len(sc.peers))), Remote: netip.AddrPortFrom(netip.MustParseAddr(addr), 443)})
}

func (sc *Scanner) Peers(_ context.Context, local netip.Addr) ([]procs.Conn, error) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	if local != PhysicalAddr {
		return nil, nil
	}
	return append([]procs.Conn(nil), sc.peers...), nil
}

// ProxyOwners: порт системного прокси слушает клиент VPN.
func (sc *Scanner) ProxyOwners(_ context.Context, at []netip.AddrPort, pids []int) ([]int, error) {
	if len(at) > 0 && slices.Contains(pids, VPNClientPID) {
		return []int{VPNClientPID}, nil
	}
	return nil, nil
}

func (sc *Scanner) TunnelOwners(_ context.Context, iface string, pids []int) ([]int, error) {
	if iface != "" && slices.Contains(pids, VPNClientPID) {
		return []int{VPNClientPID}, nil
	}
	return nil, nil
}

// Answers — ответы DNS на туннеле, которые задаёт тест.
type Answers struct {
	mu        sync.Mutex
	listeners map[string]func(dnswatch.Answer)
}

func (a *Answers) Listen(ctx context.Context, iface string, got func(dnswatch.Answer)) error {
	a.mu.Lock()
	if a.listeners == nil {
		a.listeners = map[string]func(dnswatch.Answer){}
	}
	a.listeners[iface] = got
	a.mu.Unlock()
	<-ctx.Done()
	a.mu.Lock()
	delete(a.listeners, iface)
	a.mu.Unlock()
	return nil
}

// Listening — интерфейсы, на которых служба слушает ответы DNS.
func (a *Answers) Listening() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Sorted(maps.Keys(a.listeners))
}

// Say — на интерфейсе iface пришёл ответ: имя name — адреса addrs. false —
// там никто не слушает.
func (a *Answers) Say(iface, name string, addrs ...string) bool {
	ans := dnswatch.Answer{Name: name}
	for _, s := range addrs {
		ans.Addrs = append(ans.Addrs, netip.MustParseAddr(s))
	}
	a.mu.Lock()
	got := a.listeners[iface]
	a.mu.Unlock()
	if got != nil {
		got(ans)
	}
	return got != nil
}

// PhysicalAddr — адрес физического интерфейса тестовой системы.
var PhysicalAddr = netip.MustParseAddr("192.168.68.124")

// Run — приложение id запущено и подключено к remotes («адрес:порт»).
func (sc *Scanner) Run(id string, remotes ...string) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	if sc.acts == nil {
		sc.acts = map[string]procs.Activity{}
	}
	act := procs.Activity{Running: true}
	for _, r := range remotes {
		ap := netip.MustParseAddrPort(r)
		act.Remotes = append(act.Remotes, procs.Remote{Addr: ap.Addr(), Port: ap.Port(), Proto: "tcp"})
	}
	sc.acts[id] = act
}

// Quit — приложение id закрыто.
func (sc *Scanner) Quit(id string) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	delete(sc.acts, id)
}

// Fail — сканер ломается (nil — снова работает).
func (sc *Scanner) Fail(err error) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.err = err
}

// Seen — какие приложения служба просила найти в последний раз.
func (sc *Scanner) Seen() []procs.AppRef {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	return append([]procs.AppRef(nil), sc.seen...)
}

func (sc *Scanner) Scan(_ context.Context, apps []procs.AppRef) (map[string]procs.Activity, error) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.seen = append([]procs.AppRef(nil), apps...)
	if sc.err != nil {
		return nil, sc.err
	}
	out := map[string]procs.Activity{}
	for _, a := range apps {
		out[a.ID] = sc.acts[a.ID]
	}
	return out, nil
}

// LearnFor — сколько тестовое приложение учится; ScanEvery — как часто служба
// смотрит его соединения.
const (
	LearnFor    = 200 * time.Millisecond
	ScanEvery   = 20 * time.Millisecond
	RemindEvery = 100 * time.Millisecond
)

// App создаёт пакет приложения с идентификатором id в каталоге dir и
// возвращает путь к нему.
func App(t *testing.T, dir, name, id string) string {
	t.Helper()
	path := filepath.Join(dir, name+".app")
	if err := os.MkdirAll(filepath.Join(path, "Contents", "MacOS"), 0o755); err != nil {
		t.Fatal(err)
	}
	plist := `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>CFBundleIdentifier</key><string>` + id + `</string></dict></plist>`
	if err := os.WriteFile(filepath.Join(path, "Contents", "Info.plist"), []byte(plist), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// Fakes — подменённые адаптеры. Пустые поля Start заполняет сам.
type Fakes struct {
	Accounts     *Accounts
	Installation *Installation
	Network      *Network
	Web          *Web
	Enforce      *Enforcer
	DNS          *DNS // шифрованный DNS
	RussianDNS   *DNS // российский DNS
	SystemDNS    *SystemDNS
	Apps         *Scanner
	Answers      *Answers
	Notify       *Notifier
	// NotifyAfter — сколько закрытие длится до уведомления; по умолчанию сразу.
	NotifyAfter time.Duration
	// ReadApp — как служба узнаёт приложение по пути; по умолчанию — пакет .app.
	ReadApp func(path string) (apps.App, error)
}

// Service — запущенная тестовая служба.
type Service struct {
	Layout  paths.Layout
	DNSAddr string // где слушает резолвер службы
	Fakes
	Done   <-chan struct{} // закрывается, когда служба остановилась
	err    error
	cancel context.CancelFunc
	ready  chan struct{} // закрывается, когда служба ответила
}

// Stop останавливает службу, как SIGTERM, и ждёт этого.
func (s *Service) Stop() {
	s.cancel()
	<-s.Done
}

// Err — с чем завершился Run. Читать после Done.
func (s *Service) Err() error { return s.err }

// Start поднимает службу в каталоге root (пустой — свой временный) и ждёт,
// пока она ответит. Остановится служба сама в конце теста.
func Start(t *testing.T, root string, f Fakes) *Service {
	t.Helper()
	if root == "" {
		root = t.TempDir()
	}
	if f.Accounts == nil {
		f.Accounts = &Accounts{}
	}
	if f.Installation == nil {
		f.Installation = &Installation{}
	}
	if f.Network == nil {
		f.Network = NewNetwork()
	}
	if f.Web == nil {
		f.Web = &Web{}
	}
	if f.Enforce == nil {
		f.Enforce = &Enforcer{}
	}
	if f.DNS == nil {
		f.DNS = NewDNS("Cloudflare")
	}
	if f.RussianDNS == nil {
		f.RussianDNS = NewDNS("Яндекс")
	}
	if f.SystemDNS == nil {
		f.SystemDNS = &SystemDNS{}
	}
	if f.ReadApp == nil {
		f.ReadApp = apps.ReadBundle
	}
	if f.Apps == nil {
		f.Apps = &Scanner{}
	}
	if f.Answers == nil {
		f.Answers = &Answers{}
	}
	if f.Notify == nil {
		f.Notify = &Notifier{}
	}
	L := paths.Under(root)
	L.Socket = Socket(t)
	// Порт резолвера freeUDP только что был свободен, но параллельный тест
	// может занять его раньше службы — тогда запуск повторяется на другом.
	for attempt := 1; ; attempt++ {
		s := launch(L, f)
		select {
		case <-s.ready:
			t.Cleanup(func() {
				s.cancel()
				<-s.Done
			})
			return s
		case <-s.Done:
			if attempt < 5 && s.err != nil && strings.Contains(s.err.Error(), "резолвер") {
				continue
			}
			t.Fatalf("служба не запустилась: %v", s.err)
		case <-time.After(5 * time.Second):
			s.cancel()
			<-s.Done
			t.Fatal("служба не ответила за 5 секунд")
		}
	}
}

// launch запускает службу и ждёт в фоне, когда она ответит: тогда закрывается
// s.ready.
func launch(L paths.Layout, f Fakes) *Service {
	ctx, cancel := context.WithCancel(context.Background())
	f.Installation.stop = cancel
	done := make(chan struct{})
	s := &Service{Layout: L, Fakes: f, Done: done, cancel: cancel, DNSAddr: freeUDPAddr(), ready: make(chan struct{})}
	go func() {
		defer close(done)
		s.err = service.Run(ctx, service.Deps{
			Layout: L, Version: Version, Accounts: f.Accounts, Installation: f.Installation,
			Network: f.Network, Fetch: f.Web, Enforce: f.Enforce,
			Upstreams: resolver.Upstreams{Primary: []resolver.Upstream{f.DNS}, Russian: []resolver.Upstream{f.RussianDNS}},
			SystemDNS: f.SystemDNS, DNSAddr: s.DNSAddr, Notify: f.Notify, Reach: f.Enforce.Reach,
			Apps: f.Apps, Answers: f.Answers, ReadApp: f.ReadApp, ScanEvery: ScanEvery, LearnFor: LearnFor, RemindEvery: RemindEvery,
			PhysicalAddr: func() (netip.Addr, bool) { return PhysicalAddr, true },
			CheckEvery:   CheckEvery, ProbeEvery: CheckEvery, GuardEvery: GuardEvery, Now: time.Now, NotifyAfter: f.NotifyAfter,
			Physical: func() (core.Tunnel, bool) { return PhysicalIface, true },
			Logf:     func(string, ...any) {},
		})
	}()
	go func() {
		for {
			select {
			case <-done:
				return
			default:
			}
			if _, err := ipc.Call(L.Socket, ipc.Request{Cmd: ipc.CmdStatus}); err == nil {
				close(s.ready)
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
	}()
	return s
}

// Status — статус службы.
func (s *Service) Status(t *testing.T) ipc.Status {
	t.Helper()
	resp, err := ipc.Call(s.Layout.Socket, ipc.Request{Cmd: ipc.CmdStatus})
	if err != nil || resp.Status == nil {
		t.Fatalf("статус: %v %+v", err, resp)
	}
	return *resp.Status
}

// WaitStatus ждёт, пока статус станет таким, как требует ok, не дольше within.
func (s *Service) WaitStatus(t *testing.T, within time.Duration, ok func(ipc.Status) bool) ipc.Status {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		st := s.Status(t)
		if ok(st) {
			return st
		}
		if time.Now().After(deadline) {
			t.Fatalf("за %v статус не дошёл до нужного: %+v", within, st)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Protect просит службу защитить домен (от администратора). Домен должен быть
// в таблице резолвера.
func (s *Service) Protect(t *testing.T, domain string) {
	t.Helper()
	resp, err := ipc.Call(s.Layout.Socket, ipc.Request{Cmd: ipc.CmdProtect, Domain: domain})
	if err != nil || !resp.OK {
		t.Fatalf("защитить %s: %v %+v", domain, err, resp)
	}
}

// Journal — строки журнала службы на сейчас.
func (s *Service) Journal(t *testing.T) []string {
	t.Helper()
	var lines []string
	err := ipc.Stream(s.Layout.Socket, ipc.Request{Cmd: ipc.CmdJournal, Tail: 1000}, func(r ipc.Response) error {
		if r.Event != nil {
			lines = append(lines, r.Event.Text)
		}
		return nil
	})
	if !errors.Is(err, ipc.ErrEnded) {
		t.Fatalf("журнал: %v", err)
	}
	return lines
}

// freeUDP — свободный адрес на 127.0.0.1 для резолвера тестовой службы.
// freeUDPAddr — свободный сейчас порт UDP на петле.
func freeUDPAddr() string {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return "127.0.0.1:0"
	}
	defer pc.Close()
	return pc.LocalAddr().String()
}

// Ask спрашивает резолвер службы, как спросила бы программа.
func (s *Service) Ask(t *testing.T, name string, qtype uint16) *dns.Msg {
	t.Helper()
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), qtype)
	ans, _, err := (&dns.Client{Timeout: 3 * time.Second}).Exchange(q, s.DNSAddr)
	if err != nil {
		t.Fatalf("запрос %s: %v", name, err)
	}
	return ans
}

// Socket — путь для сокета в коротком каталоге: у unix-сокета путь не длиннее
// 104 байт, а временные каталоги тестов на macOS длиннее.
func Socket(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "vl")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, "s.sock")
}

// LoadCatalog загружает каталог в службу (от администратора).
func (s *Service) LoadCatalog(t *testing.T, data string) ipc.Response {
	t.Helper()
	resp, err := ipc.Call(s.Layout.Socket, ipc.Request{Cmd: ipc.CmdCatalog, Catalog: []byte(data)})
	if err != nil {
		t.Fatal(err)
	}
	return resp
}
