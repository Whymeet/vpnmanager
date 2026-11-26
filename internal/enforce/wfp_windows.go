package enforce

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows"

	"appguard/internal/apps"
)

// Объекты appguard в WFP: поставщик и подуровень, в котором лежат его фильтры.
var (
	providerID = guid(0x6db456db, 0x8fb4, 0x4043, 0xb5, 0x16, 0x66, 0x0a, 0xdc, 0x4f, 0x39, 0xd8)
	sublayerID = guid(0xab4f0abe, 0x0188, 0x4e7f, 0x9c, 0x4b, 0xcb, 0x27, 0x04, 0x99, 0x51, 0x2a)
)

// Уровни ALE: исходящие соединения и входящие — по IPv4 и IPv6.
var aleLayers = []struct {
	id      windows.GUID
	name    string
	v6      bool
	connect bool
}{
	{layerConnectV4, "connect-v4", false, true},
	{layerConnectV6, "connect-v6", true, true},
	{layerAcceptV4, "accept-v4", false, false},
	{layerAcceptV6, "accept-v6", true, false},
}

// Веса фильтров в подуровне appguard: побеждает больший. Закрытый прокси сильнее
// петли; петля и проверенный туннель сильнее запрета приложению; запрет
// приложению сильнее разрешения серверу VPN (защищённое приложение не ходит на
// адрес CDN мимо туннеля, даже если там сервер VPN), а оно — запрета адресу.
const (
	weightAddrBlock  = 2
	weightServer     = 5
	weightBlock      = 6
	weightPermit     = 10
	weightProxyBlock = 12
)

// Пределы раскрытия папки установки: глубже и больше программ в папках
// приложений не бывает, а системную папку туда не пустит apps.InstallTarget.
const (
	maxDepth = 8
	maxExes  = 1000
)

// settleChanges — сколько ждать, пока установщик допишет файлы, прежде чем
// ставить фильтры на новые; rescanEvery — подстраховка, если наблюдение за
// папкой не встало.
const (
	settleChanges = 300 * time.Millisecond
	rescanEvery   = 30 * time.Second
)

// Коды ошибок WFP (fwpmu.h).
const (
	fwpFilterNotFound   = windows.Errno(0x80320003)
	fwpProviderNotFound = windows.Errno(0x80320005)
	fwpSublayerNotFound = windows.Errno(0x80320007)
	fwpAlreadyExists    = windows.Errno(0x80320009)
	fwpInUse            = windows.Errno(0x8032000A)
)

// WFP — исполнитель правил на Windows Filtering Platform.
//
// Защищённое приложение — исполняемый файл, папка установки (все exe в ней,
// и новые тоже, как только появятся) или пакет Store (его контейнер и exe его
// папок в WindowsApps). Ему запрещено всё, кроме петли, соединений с
// локальных адресов проверенных туннелей и с прокси, выход которого
// проверен. Адреса защищённых сервисов закрыты для всех программ — так сайт
// сервиса не откроется и в браузере, — кроме соединений с адреса
// проверенного туннеля; сервер VPN на таком адресе (VPN через CDN) открыт.
// Запреты постоянные — переживают перезагрузку и падение службы; приложениям
// к ним загрузочные, которые действуют до старта самой WFP. Разрешения, и
// петля тоже, живут в динамической сессии: служба завершилась — Windows сама
// их снимает, и всё защищённое закрыто, пока служба не вернётся и не проверит
// выход.
type WFP struct {
	// StateFile — какие программы стоят под фильтрами у каждого приложения. По
	// нему снимаются фильтры убранных приложений и все — при удалении.
	StateFile string
	// Logf — куда писать то, что защиту не снимает (загрузочный фильтр не
	// поставился, за папкой не уследить); nil — никуда.
	Logf func(format string, args ...any)

	mu       sync.Mutex
	persist  *fwpEngine // поставщик, подуровень, запреты
	dynamic  *fwpEngine // разрешения: живут, пока жив процесс
	dyn      map[windows.GUID]bool
	last     Rules           // правила последнего Apply: по ним новые программы встают под фильтры
	cleared  bool            // после Clear фильтры не возвращаются, пока не придёт новый Apply
	addrs    map[string]bool // запреты на адреса, которые точно стоят; nil — проверить все
	watches  map[string]*dirWatch
	changed  chan struct{}
	said     map[string]bool // о чём уже сказано в Logf
	rescanOn sync.Once
}

// subject — то, на что ставится фильтр: исполняемый файл или пакет Store.
type subject struct {
	key   string // для идентификаторов фильтров: путь exe строчными или package:<семейство>
	appID []byte
	sid   []byte
}

func (s subject) on(f fwFilter) fwFilter {
	f.appID, f.sid = s.appID, s.sid
	return f
}

// Apply приводит фильтры к правилам r. Отказ самой WFP (например, её службу
// перезапустили) закрывает сессии: разрешения уходят вместе с динамической, а
// следующий Apply откроет сессии заново.
func (w *WFP) Apply(r Rules) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.open(true); err != nil {
		return err
	}
	w.last, w.cleared = r, false
	appErrs, err := w.apply(r)
	if err != nil {
		w.reset()
		return err
	}
	return errors.Join(appErrs...)
}

// reset закрывает сессии WFP.
func (w *WFP) reset() {
	if w.dynamic != nil {
		w.dynamic.close()
		w.dynamic, w.dyn = nil, nil
	}
	if w.persist != nil {
		w.persist.close()
		w.persist = nil
	}
}

// apply — Apply в открытых сессиях. appErrs — приложения, которых нет на
// диске: их прежние запреты остаются, разрешений у них нет; err — отказ самой
// WFP.
func (w *WFP) apply(r Rules) (appErrs []error, err error) {
	if err := w.base(); err != nil {
		return nil, err
	}
	state, err := w.load()
	if err != nil {
		return nil, err
	}
	targets := keys(r.Apps)
	next := wfpState{Apps: map[string][]string{}}
	var all []subject
	for _, t := range targets {
		subs, err := expand(t)
		if err != nil {
			// Приложения нет на месте (удалили, ещё ставится): что стояло под
			// фильтрами, так и стоит.
			appErrs = append(appErrs, fmt.Errorf("%s: %w", t, err))
			next.Apps[t] = state.Apps[t]
			continue
		}
		for _, s := range subs {
			if err := w.block(s); err != nil {
				return nil, err
			}
		}
		next.Apps[t] = subjectKeys(subs)
		all = append(all, subs...)
	}
	// Снять фильтры с того, что пропало: убранные приложения и удалённые
	// старые версии. Программа, которую держит и другое приложение, остаётся.
	keep := map[string]bool{}
	for _, ks := range next.Apps {
		for _, k := range ks {
			keep[k] = true
		}
	}
	for _, ks := range state.Apps {
		for _, k := range ks {
			if !keep[k] {
				if err := w.unblock(k); err != nil {
					return nil, err
				}
			}
		}
	}
	if next.Addrs, err = w.blockAddrs(r, state.Addrs); err != nil {
		return nil, err
	}
	if err := w.save(next); err != nil {
		return nil, err
	}
	w.watch(targets)
	return appErrs, w.permit(all, r)
}

// blockAddrs ставит постоянные запреты на адреса защищённых сервисов и
// снимает лишние. Адресов тысячи, а резолвер ждёт, пока новый адрес встанет в
// фильтры, поэтому ставится только разница с прошлым разом; все — после
// открытия сессии и после того, как сторож заметил расхождение.
func (w *WFP) blockAddrs(r Rules, before []string) ([]string, error) {
	want := map[string]netip.Addr{}
	for _, a := range slices.Concat(r.V4, r.V6) {
		want[a.String()] = a
	}
	for _, old := range before {
		if _, ok := want[old]; ok {
			continue
		}
		for _, l := range aleLayers[:2] {
			if err := w.persist.deleteFilter(ruleID("addr", old, l.name)); err != nil && !errors.Is(err, fwpFilterNotFound) {
				return nil, fmt.Errorf("WFP: не удалось открыть адрес %s: %w", old, err)
			}
		}
		delete(w.addrs, old)
	}
	if w.addrs == nil {
		w.addrs = map[string]bool{}
	}
	for text, a := range want {
		if w.addrs[text] {
			continue
		}
		for _, l := range aleLayers[:2] { // исходящие соединения
			if l.v6 != a.Is6() {
				continue
			}
			err := w.persist.addFilter(fwFilter{id: ruleID("addr", text, l.name), layer: l.id, sublayer: sublayerID,
				provider: providerID, name: "appguard: " + text + " только через VPN", weight: weightAddrBlock,
				persistent: true, remote: netip.AddrPortFrom(a, 0)})
			if err != nil && !errors.Is(err, fwpAlreadyExists) {
				return nil, fmt.Errorf("WFP: не удалось закрыть адрес %s: %w", text, err)
			}
		}
		w.addrs[text] = true
	}
	return slices.Sorted(maps.Keys(want)), nil
}

// permit приводит динамические фильтры к нужным: петля и соединения с
// адресов открытых туннелей — всем; серверы VPN на адресах сервисов — всем,
// кроме защищённых приложений; каждой защищённой программе — открытые прокси
// и запрет на закрытые. Лишние снимаются раньше, чем ставятся новые.
func (w *WFP) permit(subs []subject, r Rules) error {
	want := map[windows.GUID]fwFilter{}
	add := func(f fwFilter) { want[f.id] = f }
	for _, l := range aleLayers {
		add(fwFilter{id: ruleID("loopback", l.name), layer: l.id, sublayer: sublayerID, provider: providerID,
			name: "appguard: петля", weight: weightPermit, permit: true, loopback: true})
		for _, a := range r.OpenAddrs {
			if l.v6 == a.Is6() {
				add(fwFilter{id: ruleID("tunnel", a.String(), l.name), layer: l.id, sublayer: sublayerID, provider: providerID,
					name: "appguard: через проверенный туннель " + a.String(), weight: weightPermit, permit: true, local: a})
			}
		}
		for _, a := range r.Servers {
			if l.connect && l.v6 == a.Is6() {
				add(fwFilter{id: ruleID("server", a.String(), l.name), layer: l.id, sublayer: sublayerID, provider: providerID,
					name: "appguard: сервер VPN " + a.String(), weight: weightServer, permit: true, remote: netip.AddrPortFrom(a, 0)})
			}
		}
	}
	for _, s := range subs {
		name := filepath.Base(s.key)
		for _, l := range aleLayers {
			if !l.connect {
				continue
			}
			for _, p := range r.OpenProxies {
				if l.v6 == p.Addr().Is6() {
					add(s.on(fwFilter{id: ruleID("proxy-open", s.key, p.String(), l.name), layer: l.id, sublayer: sublayerID,
						provider: providerID, name: "appguard: " + name + " через прокси " + p.String(), weight: weightPermit, permit: true, remote: p}))
				}
			}
			for _, p := range r.ClosedProxies {
				if l.v6 == p.Addr().Is6() {
					add(s.on(fwFilter{id: ruleID("proxy-closed", s.key, p.String(), l.name), layer: l.id, sublayer: sublayerID,
						provider: providerID, name: "appguard: " + name + " без прокси " + p.String(), weight: weightProxyBlock, remote: p}))
				}
			}
		}
	}
	for id := range w.dyn {
		if _, ok := want[id]; ok {
			continue
		}
		if err := w.dynamic.deleteFilter(id); err != nil && !errors.Is(err, fwpFilterNotFound) {
			return fmt.Errorf("WFP: не удалось снять фильтр: %w", err)
		}
		delete(w.dyn, id)
	}
	for id, f := range want {
		if w.dyn[id] {
			continue
		}
		if err := w.dynamic.addFilter(f); err != nil && !errors.Is(err, fwpAlreadyExists) {
			return fmt.Errorf("WFP: %s: %w", f.name, err)
		}
		w.dyn[id] = true
	}
	return nil
}

// block ставит программе постоянные и загрузочные запреты. Загрузочные — сверх
// постоянных: их отказ защиту не снимает и пишется только в вывод службы.
func (w *WFP) block(s subject) error {
	name := filepath.Base(s.key)
	for _, l := range aleLayers {
		err := w.persist.addFilter(s.on(fwFilter{id: ruleID("block", s.key, l.name), layer: l.id, sublayer: sublayerID,
			provider: providerID, name: "appguard: " + name + " без VPN", weight: weightBlock, persistent: true}))
		if err != nil && !errors.Is(err, fwpAlreadyExists) {
			return fmt.Errorf("WFP: не удалось закрыть %s: %w", s.key, err)
		}
		// Загрузочный фильтр — в подуровне по умолчанию и без поставщика: до
		// старта WFP их ещё нет.
		err = w.persist.addFilter(s.on(fwFilter{id: ruleID("boot", s.key, l.name), layer: l.id,
			name: "appguard: " + name + " до старта WFP", weight: weightBlock, boot: true}))
		if err != nil && !errors.Is(err, fwpAlreadyExists) {
			w.logOnce("boot "+s.key, "WFP: загрузочный фильтр для %s не поставлен (до старта WFP он не закрыт): %v", s.key, err)
		}
	}
	return nil
}

// unblock снимает запреты программы.
func (w *WFP) unblock(key string) error {
	for _, l := range aleLayers {
		for _, kind := range []string{"block", "boot"} {
			if err := w.persist.deleteFilter(ruleID(kind, key, l.name)); err != nil && !errors.Is(err, fwpFilterNotFound) {
				return fmt.Errorf("WFP: не удалось снять фильтр %s: %w", key, err)
			}
		}
	}
	return nil
}

// base ставит поставщика и подуровень.
func (w *WFP) base() error {
	err := w.persist.addProvider(providerID, "appguard", "appguard: защищённые приложения выходят в сеть только через проверенный VPN")
	if err != nil && !errors.Is(err, fwpAlreadyExists) {
		return fmt.Errorf("WFP: поставщик: %w", err)
	}
	err = w.persist.addSublayer(sublayerID, providerID, "appguard", "фильтры защищённых приложений", 0xffff)
	if err != nil && !errors.Is(err, fwpAlreadyExists) {
		return fmt.Errorf("WFP: подуровень: %w", err)
	}
	return nil
}

// expand — программы приложения t: сам exe, все exe папки установки или
// контейнер пакета Store с exe его папок.
func expand(t string) ([]subject, error) {
	if family, ok := strings.CutPrefix(t, apps.PackagePrefix); ok {
		sid, err := packageSID(family)
		if err != nil {
			return nil, err
		}
		subs := []subject{{key: t, sid: sid}}
		for _, dir := range apps.PackageDirs(family) {
			subs = append(subs, exes(dir)...)
		}
		return subs, nil
	}
	fi, err := os.Stat(t)
	if err != nil {
		return nil, err
	}
	if fi.IsDir() {
		return exes(t), nil
	}
	appID, err := appIDOf(t)
	if err != nil {
		return nil, err
	}
	return []subject{{key: t, appID: appID}}, nil
}

// exes — исполняемые файлы папки и её вложенных папок.
func exes(dir string) []subject {
	var out []subject
	filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if rel, _ := filepath.Rel(dir, p); strings.Count(rel, `\`) >= maxDepth {
				return filepath.SkipDir
			}
			return nil
		}
		if len(out) >= maxExes || !strings.EqualFold(filepath.Ext(p), ".exe") {
			return nil
		}
		if appID, err := appIDOf(p); err == nil {
			out = append(out, subject{key: strings.ToLower(p), appID: appID})
		}
		return nil
	})
	return out
}

// watch следит за папками приложений и за WindowsApps, если есть пакеты:
// новая версия или новая программа встаёт под фильтры, как только появится.
func (w *WFP) watch(targets []string) {
	want := map[string]bool{} // папка → следить ли и за вложенными
	for _, t := range targets {
		if strings.HasPrefix(t, apps.PackagePrefix) {
			want[apps.WindowsApps()] = false
		} else if fi, err := os.Stat(t); err == nil && fi.IsDir() {
			want[t] = true
		}
	}
	for dir, dw := range w.watches {
		if _, ok := want[dir]; !ok {
			dw.close()
			delete(w.watches, dir)
		}
	}
	for dir, subtree := range want {
		if w.watches[dir] != nil {
			continue
		}
		dw, err := watchDir(dir, subtree, w.kick)
		if err != nil {
			w.logOnce("watch "+dir, "WFP: за папкой %s не уследить, новые программы в ней встанут под фильтры не сразу: %v", dir, err)
			continue
		}
		w.watches[dir] = dw
	}
	w.rescanOn.Do(func() { go w.rescan() })
}

func (w *WFP) kick() {
	select {
	case w.changed <- struct{}{}:
	default:
	}
}

// rescan ставит под фильтры новые программы: по сигналу наблюдения за
// папками, а для подстраховки — раз в rescanEvery.
func (w *WFP) rescan() {
	tick := time.NewTicker(rescanEvery)
	defer tick.Stop()
	for {
		select {
		case <-w.changed:
			time.Sleep(settleChanges)
		case <-tick.C:
		}
		w.mu.Lock()
		if w.persist != nil && w.dynamic != nil && !w.cleared {
			if _, err := w.apply(w.last); err != nil {
				w.reset()
				if w.Logf != nil {
					w.Logf("WFP: новые программы под фильтры не встали: %v", err)
				}
			}
		}
		w.mu.Unlock()
	}
}

// Clear снимает всё, что поставил исполнитель: динамические фильтры, запреты,
// подуровень и поставщика.
func (w *WFP) Clear() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.open(false); err != nil {
		return err
	}
	for dir, dw := range w.watches {
		dw.close()
		delete(w.watches, dir)
	}
	w.last, w.cleared = Rules{}, true
	var errs []error
	if w.dynamic != nil {
		for id := range w.dyn {
			if err := w.dynamic.deleteFilter(id); err != nil && !errors.Is(err, fwpFilterNotFound) {
				errs = append(errs, err)
			}
		}
		w.dyn = map[windows.GUID]bool{}
	}
	state, err := w.load()
	if err != nil {
		errs = append(errs, err)
	}
	for _, ks := range state.Apps {
		for _, k := range ks {
			if err := w.unblock(k); err != nil {
				errs = append(errs, err)
			}
		}
	}
	for _, a := range state.Addrs {
		for _, l := range aleLayers[:2] {
			if err := w.persist.deleteFilter(ruleID("addr", a, l.name)); err != nil && !errors.Is(err, fwpFilterNotFound) {
				errs = append(errs, err)
			}
		}
	}
	w.addrs = nil
	if err := w.persist.deleteSublayer(sublayerID); errors.Is(err, fwpInUse) {
		errs = append(errs, errors.New("WFP: в подуровне appguard остались фильтры, о которых служба не знает"))
	} else if err != nil && !errors.Is(err, fwpSublayerNotFound) {
		errs = append(errs, fmt.Errorf("WFP: подуровень: %w", err))
	}
	if err := w.persist.deleteProvider(providerID); err != nil && !errors.Is(err, fwpProviderNotFound) && !errors.Is(err, fwpInUse) {
		errs = append(errs, fmt.Errorf("WFP: поставщик: %w", err))
	}
	if err := os.Remove(w.StateFile); err != nil && !errors.Is(err, fs.ErrNotExist) {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// Verify сверяет фильтры с правилами r: подуровень appguard на месте, под
// фильтрами те же приложения и адреса, что в правилах, у каждой программы
// приложений есть запрет, у адресов — на выборку. Сам фильтров не меняет;
// расхождение — и следующий Apply ставит все запреты на адреса заново.
func (w *WFP) Verify(r Rules) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.persist == nil {
		return errors.New("WFP: сессия не открыта")
	}
	ok, err := w.persist.hasSublayer(sublayerID)
	if err != nil {
		return fmt.Errorf("WFP не отвечает: %w", err)
	}
	if !ok {
		return errors.New("подуровень appguard в WFP снят")
	}
	state, err := w.load()
	if err != nil {
		return err
	}
	if !slices.Equal(slices.Sorted(maps.Keys(state.Apps)), keys(r.Apps)) {
		return errors.New("под фильтрами WFP не те приложения, что в настройках")
	}
	if len(state.Addrs) != len(r.V4)+len(r.V6) {
		return errors.New("под фильтрами WFP не те адреса, что в таблицах")
	}
	for _, ks := range state.Apps {
		for _, k := range ks {
			ok, err := w.persist.hasFilter(ruleID("block", k, aleLayers[0].name))
			if err != nil {
				return fmt.Errorf("WFP не отвечает: %w", err)
			}
			if !ok {
				return fmt.Errorf("снят запрет для %s", filepath.Base(k))
			}
		}
	}
	for _, a := range sample(state.Addrs, 8) {
		layer := aleLayers[0].name
		if strings.Contains(a, ":") {
			layer = aleLayers[1].name
		}
		ok, err := w.persist.hasFilter(ruleID("addr", a, layer))
		if err != nil {
			return fmt.Errorf("WFP не отвечает: %w", err)
		}
		if !ok {
			w.addrs = nil
			return fmt.Errorf("снят запрет на адрес %s", a)
		}
	}
	return nil
}

// sample — до n элементов списка: первые и последние.
func sample(list []string, n int) []string {
	if len(list) <= n {
		return list
	}
	return slices.Concat(list[:n/2], list[len(list)-n/2:])
}

// open открывает сессии WFP: постоянную и, если нужны разрешения, динамическую.
func (w *WFP) open(dynamic bool) error {
	if w.said == nil {
		w.said, w.watches, w.changed = map[string]bool{}, map[string]*dirWatch{}, make(chan struct{}, 1)
	}
	if w.persist == nil {
		e, err := openEngine("appguard", false)
		if err != nil {
			return fmt.Errorf("WFP: %w", err)
		}
		w.persist = e
	}
	if dynamic && w.dynamic == nil {
		e, err := openEngine("appguard: сеть через проверенный VPN", true)
		if err != nil {
			return fmt.Errorf("WFP: %w", err)
		}
		w.dynamic, w.dyn = e, map[windows.GUID]bool{}
	}
	return nil
}

func (w *WFP) logOnce(key, format string, args ...any) {
	if w.said[key] || w.Logf == nil {
		return
	}
	w.said[key] = true
	w.Logf(format, args...)
}

// wfpState — что под фильтрами: приложение → его программы, и адреса сервисов.
type wfpState struct {
	Apps  map[string][]string `json:"apps"`
	Addrs []string            `json:"addrs,omitempty"`
}

func (w *WFP) load() (wfpState, error) {
	state := wfpState{Apps: map[string][]string{}}
	data, err := os.ReadFile(w.StateFile)
	if errors.Is(err, fs.ErrNotExist) {
		return state, nil
	}
	if err != nil {
		return state, err
	}
	if err := json.Unmarshal(data, &state); err != nil {
		// Файл испорчен (сбой системы посреди записи оставляет нули). Без
		// этого apply отказывал бы навсегда. Начать с пустого безопасно:
		// фильтры ставятся заново поверх тех же (ruleID — хэш смысла), а
		// испорченный файл остаётся рядом для разбора.
		bad := w.StateFile + ".bad"
		if rerr := os.Rename(w.StateFile, bad); rerr != nil {
			return state, fmt.Errorf("%s: %w (отложить не удалось: %v)", w.StateFile, err, rerr)
		}
		if w.Logf != nil {
			w.Logf("WFP: %s испорчен (%v), отложен в %s — фильтры ставятся заново", w.StateFile, err, bad)
		}
		return wfpState{Apps: map[string][]string{}}, nil
	}
	if state.Apps == nil {
		state.Apps = map[string][]string{}
	}
	return state, nil
}

func (w *WFP) save(state wfpState) error {
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	// Sync до переименования: иначе при сбое системы NTFS сохраняет
	// переименование раньше данных и файл оказывается из нулей.
	tmp := w.StateFile + ".new"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, w.StateFile)
}

func subjectKeys(subs []subject) []string {
	out := make([]string, 0, len(subs))
	for _, s := range subs {
		out = append(out, s.key)
	}
	return out
}

// keys — приложения без различий в регистре и записи: по ним считаются
// идентификаторы фильтров.
func keys(targets []string) []string {
	out := make([]string, 0, len(targets))
	for _, t := range targets {
		if family, ok := strings.CutPrefix(t, apps.PackagePrefix); ok {
			out = append(out, apps.PackagePrefix+strings.ToLower(family))
		} else {
			out = append(out, strings.ToLower(filepath.Clean(t)))
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// ruleID — постоянный идентификатор фильтра по его смыслу: так фильтры
// находятся и снимаются и после перезапуска службы.
func ruleID(parts ...string) windows.GUID {
	sum := sha256.Sum256([]byte("appguard\x00" + strings.Join(parts, "\x00")))
	g := windows.GUID{
		Data1: binary.LittleEndian.Uint32(sum[0:4]),
		Data2: binary.LittleEndian.Uint16(sum[4:6]),
		Data3: binary.LittleEndian.Uint16(sum[6:8]),
	}
	copy(g.Data4[:], sum[8:16])
	return g
}
