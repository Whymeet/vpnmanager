// Package core — ядро решений: чистая логика без обращений к ОС. На входе —
// наблюдения (туннели и результаты проверок выхода), на выходе — состояние
// путей и события журнала. «Не проверено» всегда означает «закрыто».
package core

import (
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Tunnel — путь VPN: виртуальный интерфейс с рабочим (не link-local) адресом
// или системный прокси. У прокси (Proxy не nil) интерфейса нет: проверка выхода
// идёт через сам прокси, а Name — «прокси адрес:порт».
type Tunnel struct {
	Name  string       `json:"name"`
	Index int          `json:"index"`
	Addrs []netip.Addr `json:"addrs"`
	Proxy *Proxy       `json:"proxy,omitempty"`
}

// Proxy — системный прокси: куда программы отправляют трафик и кто его там
// принимает.
type Proxy struct {
	Scheme  string       `json:"scheme"` // http (HTTP- и HTTPS-прокси системы) или socks5
	Host    string       `json:"host"`   // как записан в настройках системы
	Port    uint16       `json:"port"`
	Addrs   []netip.Addr `json:"addrs"`             // адреса Host: на них файрвол и закрывает порт
	Process string       `json:"process,omitempty"` // кто слушает порт; пусто — не узнать
}

// Endpoint — адрес прокси для людей: «127.0.0.1:7890».
func (p Proxy) Endpoint() string { return net.JoinHostPort(p.Host, strconv.Itoa(int(p.Port))) }

// Same — тот же прокси: схема, узел, порт и адреса узла. Процесс, который
// слушает порт, не в счёт: он только для людей.
func (p Proxy) Same(q Proxy) bool {
	return p.Scheme == q.Scheme && p.Host == q.Host && p.Port == q.Port && slices.Equal(p.Addrs, q.Addrs)
}

// ProxyName — имя пути через прокси p.
func ProxyName(p Proxy) string { return "прокси " + p.Endpoint() }

// AsPath — прокси как путь, рядом с туннелями.
func (p Proxy) AsPath() Tunnel { return Tunnel{Name: ProxyName(p), Proxy: &p} }

// Snapshot — что наблюдатель сети видит сейчас.
type Snapshot struct {
	Tunnels      []Tunnel
	Proxies      []Proxy // системный прокси: по одному на адрес с портом
	DefaultIface string  // интерфейс маршрута по умолчанию
}

// Answer — ответ одного источника проверки: адрес и страна выхода.
type Answer struct {
	Source  string
	IP      netip.Addr
	Country string // ISO 3166-1 alpha-2
}

// Exit — проверенный адрес выхода.
type Exit struct {
	IP      netip.Addr `json:"ip"`
	Country string     `json:"country"`
}

// Outcome — что известно о выходе пути.
type Outcome int

const (
	Pending    Outcome = iota // проверки ещё не было
	Verified                  // оба источника: выход не в России
	Russian                   // оба источника: выход в России
	Unverified                // источники расходятся, молчат или не знают страну
)

func (o Outcome) String() string {
	switch o {
	case Verified:
		return "verified"
	case Russian:
		return "russian"
	case Unverified:
		return "unverified"
	}
	return "pending"
}

// Check — итог проверки выхода.
type Check struct {
	Outcome Outcome
	Exit    Exit   // для Verified и Russian
	Detail  string // для Unverified — почему
}

// Failed — выход проверить не удалось.
func Failed(detail string) Check { return Check{Outcome: Unverified, Detail: detail} }

// Judge сводит ответы двух независимых источников. Выход проверен, только если
// оба назвали страну и оба — не Россию; оба назвали Россию — выход в России;
// расходятся или страна неизвестна — выход не проверен.
func Judge(a, b Answer) Check {
	if !Known(a.Country) || !Known(b.Country) {
		return Failed("источник не определил страну")
	}
	if (a.Country == "RU") != (b.Country == "RU") {
		return Failed(fmt.Sprintf("источники расходятся: %s — %s, %s — %s",
			a.Source, CountryName(a.Country), b.Source, CountryName(b.Country)))
	}
	exit := Exit{IP: a.IP, Country: a.Country}
	if a.Country == "RU" {
		return Check{Outcome: Russian, Exit: exit}
	}
	return Check{Outcome: Verified, Exit: exit}
}

// ProbeState — что показал зонд «Россия напрямую».
type ProbeState int

const (
	ProbeUnknown     ProbeState = iota // зонда ещё не было
	ProbeThrough                       // российский сервис видит адрес выхода: правила нет
	ProbeDirect                        // российский сервис видит домашний адрес: «Россия напрямую»
	ProbeUnavailable                   // российский сервис не ответил
)

// Probe — итог зонда «Россия напрямую».
type Probe struct {
	State ProbeState
	Seen  netip.Addr // что увидел российский сервис через туннель
	Home  netip.Addr // что он видит через физический интерфейс
}

// Path — путь в интернет через туннель и то, что о нём известно. Gen растёт,
// когда туннель появляется заново: результат проверки прежнего туннеля к новому
// не применяется.
type Path struct {
	Tunnel Tunnel
	Gen    int
	Check  Check
	Probe  Probe
}

// Summary — состояние пути одной строкой для статуса.
func (p Path) Summary() string {
	switch c := p.Check; c.Outcome {
	case Verified:
		s := fmt.Sprintf("выход %s, %s — проверен", c.Exit.IP, CountryName(c.Exit.Country))
		if p.Probe.State == ProbeDirect {
			s += "; клиент VPN отправляет российские адреса напрямую — выключи в нём правило «Россия напрямую»"
		}
		return s
	case Russian:
		return fmt.Sprintf("выход в России (%s)", c.Exit.IP)
	case Unverified:
		return "не проверен: не удалось проверить выход (" + c.Detail + ")"
	}
	return "проверяю выход"
}

// Виды событий журнала.
const (
	KindService    = "service"
	KindTunnelUp   = "tunnel-up"
	KindTunnelDown = "tunnel-down"
	KindVerified   = "verified"
	KindRussian    = "russian"
	KindUnverified = "unverified"
	KindOpen       = "open"    // защищённые сервисы открыты
	KindClosed     = "closed"  // защищённые сервисы закрыты
	KindError      = "error"   // служба не смогла сделать то, что должна
	KindApp        = "app"     // защищённые приложения: добавлено, обучается, обучено, убрано
	KindDirect     = "direct"  // зонд «Россия напрямую»
	KindProxy      = "proxy"   // порт системного прокси открыт или закрыт
	KindGuard      = "guard"   // сторож: правила файрвола сброшены и восстановлены
	KindCatalog    = "catalog" // ежедневное обновление каталога и напоминания
)

// Правила — одно на все защищённые приложения.
const (
	RuleAny  = "any"  // любой выход не из России (по умолчанию)
	RuleMine = "mine" // только мои выходы
)

// RuleText — название правила для человека.
func RuleText(rule string) string {
	switch rule {
	case RuleMine:
		return "только мои выходы"
	case RuleAny, "":
		return "любой выход не из России"
	}
	return rule
}

// Event — строка журнала.
type Event struct {
	Time    time.Time `json:"t"`
	Kind    string    `json:"kind"`
	Iface   string    `json:"iface,omitempty"`
	IP      string    `json:"ip,omitempty"`
	Country string    `json:"country,omitempty"`
	Text    string    `json:"text"`
}

// State — пути, которые служба видит сейчас.
type State struct {
	paths    map[string]*Path
	def      string // интерфейс маршрута по умолчанию: по нему выбирается причина закрытия
	gen      int
	observed bool // сеть уже видели хоть раз: до этого причину закрытия не назвать
}

func NewState() *State { return &State{paths: map[string]*Path{}} }

// Paths — пути по имени интерфейса.
func (s *State) Paths() []Path {
	out := make([]Path, 0, len(s.paths))
	for _, p := range s.paths {
		out = append(out, *p)
	}
	slices.SortFunc(out, func(a, b Path) int { return strings.Compare(a.Tunnel.Name, b.Tunnel.Name) })
	return out
}

// Observe применяет снимок сети. Новый путь — или прежний, но с другими
// адресами — начинает с Pending: пока результата проверки нет, путь закрыт.
func (s *State) Observe(snap Snapshot, now time.Time) []Event {
	s.def, s.observed = snap.DefaultIface, true
	var events []Event
	seen := map[string]bool{}
	all := slices.Clone(snap.Tunnels)
	for _, px := range snap.Proxies {
		all = append(all, px.AsPath())
	}
	for _, t := range all {
		seen[t.Name] = true
		if p, ok := s.paths[t.Name]; ok && sameTunnel(p.Tunnel, t) {
			p.Tunnel = t // тот же путь; у прокси мог смениться слушающий процесс
			continue
		}
		s.gen++
		s.paths[t.Name] = &Path{Tunnel: t, Gen: s.gen}
		e := Event{Time: now, Kind: KindTunnelUp, Iface: t.Name,
			Text: fmt.Sprintf("туннель %s появился (%s) — проверяю выход", t.Name, JoinAddrs(t.Addrs))}
		if px := t.Proxy; px != nil {
			e.Text = t.Name + " включён"
			if px.Process != "" {
				e.Text += " (порт слушает " + px.Process + ")"
			}
			e.Text += " — проверяю выход; пока он не проверен, " + PortClosed
		}
		events = append(events, e)
	}
	var gone []string
	for name := range s.paths {
		if !seen[name] {
			gone = append(gone, name)
		}
	}
	slices.Sort(gone)
	for _, name := range gone {
		proxy := s.paths[name].Tunnel.Proxy != nil
		delete(s.paths, name)
		text := "туннель " + name + " исчез"
		if proxy {
			text = name + " выключен — правило для его порта снято"
		}
		if len(s.paths) == 0 {
			text += " — VPN нет"
		}
		events = append(events, Event{Time: now, Kind: KindTunnelDown, Iface: name, Text: text})
	}
	return events
}

// Checked применяет результат проверки пути name поколения gen. Событие — только
// когда поменялся исход или адрес выхода: повторные проверки журнал не засоряют.
func (s *State) Checked(name string, gen int, c Check, now time.Time) []Event {
	p, ok := s.paths[name]
	if !ok || p.Gen != gen {
		return nil
	}
	prev := p.Check
	p.Check = c
	if prev.Outcome == c.Outcome && prev.Exit == c.Exit {
		return nil
	}
	e := Event{Time: now, Iface: name}
	if c.Outcome == Verified || c.Outcome == Russian {
		e.IP, e.Country = c.Exit.IP.String(), c.Exit.Country
	}
	switch c.Outcome {
	case Verified:
		e.Kind = KindVerified
		if prev.Outcome == Verified {
			e.Text = fmt.Sprintf("%s: выход сменился — %s, %s, проверен", name, c.Exit.IP, CountryName(c.Exit.Country))
		} else {
			e.Text = fmt.Sprintf("%s: выход %s, %s — проверен", name, c.Exit.IP, CountryName(c.Exit.Country))
		}
	case Russian:
		e.Kind = KindRussian
		e.Text = fmt.Sprintf("%s: выход в России (%s)", name, c.Exit.IP)
	default:
		e.Kind = KindUnverified
		e.Text = fmt.Sprintf("%s: не удалось проверить выход — %s", name, c.Detail)
	}
	return []Event{e}
}

// Probed применяет итог зонда «Россия напрямую» пути name поколения gen.
// Событие — только на переход: правило появилось, пропало, сервис перестал
// отвечать. Зонд сервисы не открывает и не закрывает: прямые соединения клиента
// к узлам защищённых сервисов в России закрывает файрвол на физическом
// интерфейсе.
func (s *State) Probed(name string, gen int, pr Probe, now time.Time) []Event {
	p, ok := s.paths[name]
	if !ok || p.Gen != gen {
		return nil
	}
	prev := p.Probe.State
	p.Probe = pr
	if prev == pr.State {
		return nil
	}
	e := Event{Time: now, Kind: KindDirect, Iface: name}
	switch {
	case pr.State == ProbeDirect:
		e.Text = name + ": клиент VPN отправляет российские адреса напрямую («Россия напрямую»): российский сервис видит домашний адрес. Выключи это правило в клиенте — защищённые сервисы закрыты от прямых соединений, но правило лучше не держать"
	case pr.State == ProbeThrough && prev == ProbeDirect:
		e.Text = name + ": «Россия напрямую» больше не замечено — российские адреса идут через туннель"
	case pr.State == ProbeUnavailable:
		e.Text = name + ": российский сервис проверки не ответил — «Россию напрямую» проверить не удалось"
	default:
		return nil
	}
	return []Event{e}
}

// Protection — решение о защищённых сервисах: их трафик проходит только через
// туннели и прокси, выход которых проверен и подходит под правило. «Не
// проверено» всегда закрыто.
type Protection struct {
	Open       bool        // можно ли защищённому трафику выходить
	OpenIfaces []string    // туннели, через которые можно
	Proxies    []ProxyGate // системные прокси: открыт ли порт
	Exit       Exit        // выход, которым сервисы открыты (для журнала)
	Reason     string      // почему закрыто — для журнала; пусто = не журналить (пока проверяю)
	Kind       string      // KindOpen или KindClosed
}

// ProxyGate — решение о порте системного прокси. Закрытый порт закрыт для всех
// программ: файрвол не различает, кто к нему подключается.
type ProxyGate struct {
	Name   string // имя пути: «прокси адрес:порт»
	Proxy  Proxy
	Open   bool
	Exit   Exit   // выход, которым порт открыт
	Reason string // почему закрыт; пусто — выход ещё проверяется
}

// Policy — правило и его данные.
type Policy struct {
	Rule  string                // RuleAny или RuleMine
	Exits map[netip.Addr]string // мои выходы: адрес → имя (для RuleMine)
}

// allows — выход подходит под правило.
func (pol Policy) allows(e Exit) bool {
	if pol.Rule != RuleMine {
		return true // «любой выход не из России»: проверенный выход уже не российский
	}
	_, ok := pol.Exits[e.IP]
	return ok
}

// Protect вычисляет решение из текущих путей. Открыты туннели и порты прокси
// с проверенным выходом, который подходит под правило, остальное закрыто;
// причина закрытия берётся по пути маршрута по умолчанию.
func (s *State) Protect(pol Policy) Protection {
	paths := s.Paths()
	var prot Protection
	for _, p := range paths {
		open := p.Check.Outcome == Verified && pol.allows(p.Check.Exit)
		if px := p.Tunnel.Proxy; px != nil {
			g := ProxyGate{Name: p.Tunnel.Name, Proxy: *px, Open: open}
			if open {
				g.Exit = p.Check.Exit
			} else {
				g.Reason = pathReason(p, pol)
			}
			prot.Proxies = append(prot.Proxies, g)
		} else if open {
			prot.OpenIfaces = append(prot.OpenIfaces, p.Tunnel.Name)
		}
		if open && (!prot.Open || p.Tunnel.Name == s.def) {
			prot.Open, prot.Exit = true, p.Check.Exit
		}
	}
	if prot.Open {
		prot.Kind = KindOpen
		return prot
	}
	prot.Kind, prot.Reason = KindClosed, s.closedReason(paths, pol)
	return prot
}

// closedReason объясняет, почему закрыто. Причину даёт путь маршрута по
// умолчанию, а если маршрут идёт мимо туннелей — прокси (им пользуются
// программы), затем первый туннель, о котором уже что-то известно.
func (s *State) closedReason(paths []Path, pol Policy) string {
	if !s.observed {
		return "" // служба только стартовала и сети ещё не видела
	}
	if len(paths) == 0 {
		return "VPN выключен"
	}
	p, ok := s.paths[s.def]
	if !ok {
		known := func(proxy bool) *Path {
			for i := range paths {
				if (paths[i].Tunnel.Proxy != nil) == proxy && paths[i].Check.Outcome != Pending {
					return &paths[i]
				}
			}
			return nil
		}
		if p = known(true); p == nil {
			p = known(false)
		}
	}
	if p == nil {
		return "" // проверка ещё идёт — путь уже дал об этом строку
	}
	r := pathReason(*p, pol)
	if r != "" && p.Tunnel.Proxy != nil {
		r = p.Tunnel.Name + " — " + r
	}
	return r
}

// pathReason — почему путь p закрыт; пусто — выход ещё проверяется.
func pathReason(p Path, pol Policy) string {
	switch p.Check.Outcome {
	case Russian:
		return fmt.Sprintf("выход в России (%s)", p.Check.Exit.IP)
	case Unverified:
		return "не удалось проверить выход"
	case Verified:
		if len(pol.Exits) == 0 {
			return fmt.Sprintf("выход %s, %s — в твоём списке пока нет ни одного выхода", p.Check.Exit.IP, CountryName(p.Check.Exit.Country))
		}
		return fmt.Sprintf("выход %s, %s — не из твоего списка", p.Check.Exit.IP, CountryName(p.Check.Exit.Country))
	}
	return ""
}

// sameTunnel — тот же путь. Процесс, который слушает порт прокси, не в счёт:
// он только для людей, а выход и так перепроверяется каждые несколько секунд.
func sameTunnel(a, b Tunnel) bool {
	if a.Name != b.Name || a.Index != b.Index || !slices.Equal(a.Addrs, b.Addrs) || (a.Proxy == nil) != (b.Proxy == nil) {
		return false
	}
	if a.Proxy == nil {
		return true
	}
	return a.Proxy.Same(*b.Proxy)
}

// Plural — форма слова для числа n: Plural(1, "адрес", "адреса", "адресов") —
// «адрес», 3 — «адреса», 5 и 11 — «адресов».
func Plural(n int, one, few, many string) string {
	n %= 100
	switch {
	case n >= 11 && n <= 14:
		return many
	case n%10 == 1:
		return one
	case n%10 >= 2 && n%10 <= 4:
		return few
	}
	return many
}

// JoinAddrs — адреса через запятую, для людей.
func JoinAddrs(addrs []netip.Addr) string {
	s := make([]string, len(addrs))
	for i, a := range addrs {
		s[i] = a.String()
	}
	return strings.Join(s, ", ")
}
