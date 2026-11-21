package service

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"appguard/internal/apps"
	"appguard/internal/catalog"
	"appguard/internal/config"
	"appguard/internal/core"
	"appguard/internal/learn"
)

// catalogFile — где служба хранит каталог, по которому защищает.
func (e *engine) catalogFile() string { return filepath.Join(e.d.Layout.StateDir, "catalog.json") }

// loadCatalog читает сохранённый каталог при старте. Каталога нет — служба
// работает без него: приложения учатся.
func (e *engine) loadCatalog() {
	data, err := os.ReadFile(e.catalogFile())
	if errors.Is(err, fs.ErrNotExist) {
		return
	}
	if err == nil {
		var c catalog.Catalog
		var warnings []string
		if c, warnings, err = catalog.Parse(data); err == nil {
			e.mu.Lock()
			e.catalog = c
			e.mu.Unlock()
			e.journalWarnings(warnings)
			return
		}
	}
	e.record([]core.Event{{Time: e.d.Now(), Kind: core.KindError, Text: "каталог службы не прочитан: " + err.Error()}})
}

// setCatalog принимает новый каталог: проверяет, сохраняет и применяет к уже
// добавленным приложениям. Каталог новее поддерживаемого формата не
// применяется — действует прежний.
func (e *engine) setCatalog(data []byte) ([]string, error) {
	c, warnings, err := catalog.Parse(data)
	if err != nil {
		e.record([]core.Event{{Time: e.d.Now(), Kind: core.KindError, Text: "новый каталог не применён: " + err.Error()}})
		return nil, err
	}
	if err := writeFile(e.catalogFile(), data); err != nil {
		return nil, err
	}
	e.mu.Lock()
	e.catalog = c
	e.mu.Unlock()
	e.journalWarnings(warnings)
	e.record([]core.Event{{Time: e.d.Now(), Kind: core.KindService,
		Text: fmt.Sprintf("каталог обновлён: %s, %d %s", catalogDay(c.Updated), len(c.Apps), core.Plural(len(c.Apps), "приложение", "приложения", "приложений"))}})
	return warnings, e.applyCatalog()
}

// catalogEntry — запись каталога о приложении: на macOS — по идентификатору
// пакета или имени консольной программы, на Windows — по семейству пакета
// Store или имени исполняемого файла.
func (e *engine) catalogEntry(a config.App) (catalog.App, bool) {
	if a.Command {
		return e.catalog.ForMacCommand(a.Name)
	}
	if family, ok := strings.CutPrefix(a.Path, apps.PackagePrefix); ok {
		return e.catalog.ForWindows("", family)
	}
	if a.Exe != "" {
		return e.catalog.ForWindows(a.Exe, "")
	}
	return e.catalog.ForMac(a.ID)
}

// applyCatalog защищает по каталогу уже добавленные приложения: те, что ждали
// обучения, становятся «защищено», у обученных к выученному добавляется
// известное каталогу, кроме забытого человеком. Выученное не убирается никогда.
func (e *engine) applyCatalog() error {
	var events []core.Event
	var lookups []string
	e.mu.Lock()
	for id, a := range e.apps {
		entry, ok := e.catalogEntry(a.cfg)
		if !ok {
			continue
		}
		if !a.cfg.Learned {
			a.cfg.Learned, a.cfg.Catalog, a.cfg.LearnedAt = true, true, e.d.Now()
			events = append(events, core.Event{Time: e.d.Now(), Kind: core.KindApp, Text: byCatalog(a.cfg.Name, entry)})
		}
		a.cfg.Addrs = mergeStrings(a.cfg.Addrs, without(entry.Addrs, a.cfg.Forgotten))
		lookups = append(lookups, e.ownDomains(id, without(entry.Domains, a.cfg.Forgotten))...)
	}
	e.mu.Unlock()
	if err := e.saveApps(); err != nil {
		return err
	}
	if err := e.saveDomains(); err != nil {
		return err
	}
	e.record(events)
	e.syncDNS()
	e.resolveLater(lookups)
	return e.reapply()
}

// ownDomains отдаёт домены приложению id во владение и возвращает новые
// домены — их адреса надо узнать. Вызывать под e.mu.
func (e *engine) ownDomains(id string, domains []string) (fresh []string) {
	for _, name := range domains {
		d, existed := e.protected[name]
		if !existed {
			d = e.domain(name)
			fresh = append(fresh, name)
		}
		d.apps[id] = true
	}
	return fresh
}

// disown снимает приложение id с его доменов; домены без владельцев уходят.
// Вызывать под e.mu.
func (e *engine) disown(id string) {
	for name, d := range e.protected {
		if d.apps[id] {
			delete(d.apps, id)
			if !d.owned() {
				delete(e.protected, name)
			}
		}
	}
}

// resolveLater узнаёт адреса новых доменов в фоне: ответ клиенту не ждёт сети.
// До ответа резолвера домен уже направлен на службу, так что программа его
// адреса мимо таблиц не получит. Запросы живут не дольше движка: остановка их
// прерывает и ждёт, иначе запись в настройки легла бы уже после выхода службы.
func (e *engine) resolveLater(domains []string) {
	for _, d := range domains {
		e.bg.Go(func(life context.Context) {
			ctx, cancel := context.WithTimeout(life, 10*time.Second)
			defer cancel()
			addrs, err := e.lookup(ctx, d)
			if err != nil {
				e.d.Logf("каталог: адреса %s не узнаны: %v", d, err)
				return
			}
			e.learn(ctx, d, addrs)
		})
	}
}

func (e *engine) journalWarnings(warnings []string) {
	for _, w := range warnings {
		e.record([]core.Event{{Time: e.d.Now(), Kind: core.KindError, Text: "каталог: отброшено — " + w}})
	}
}

func byCatalog(name string, a catalog.App) string {
	return fmt.Sprintf("%s защищено по каталогу: %d %s, %d %s", name,
		len(a.Domains), core.Plural(len(a.Domains), "домен", "домена", "доменов"),
		len(a.Addrs), core.Plural(len(a.Addrs), "адрес", "адреса", "адресов"))
}

func catalogDay(day string) string {
	if t, err := time.Parse("2006-01-02", day); err == nil {
		return "от " + t.Format("02.01.2006")
	}
	return "без даты"
}

// export — выученное на этом маке для каталога. Адреса VPN автора отсюда
// убираются: выходы VPN и серверы, к которым сейчас идут соединения мимо
// туннеля (так ходит только сам клиент VPN). Их не должно быть в каталоге,
// который уедет ученикам.
func (e *engine) export(ctx context.Context) ([]catalog.Learned, []catalog.Drop, error) {
	own := map[netip.Addr]string{}
	e.mu.Lock()
	paths := e.state.Paths()
	for ip, name := range e.policy.Exits {
		own[ip] = fmt.Sprintf("твой выход «%s»", name)
	}
	servers := maps.Clone(e.servers)
	e.mu.Unlock()
	for _, p := range paths {
		if o := p.Check.Outcome; o == core.Verified || o == core.Russian {
			own[p.Check.Exit.IP] = "адрес выхода VPN"
		}
	}
	if local, ok := e.d.PhysicalAddr(); ok && len(paths) > 0 {
		peers, err := e.d.Apps.Peers(ctx, local)
		if err != nil {
			return nil, nil, fmt.Errorf("не удалось узнать адреса серверов VPN: %w", err)
		}
		for _, c := range peers {
			if a := c.Remote.Addr().Unmap(); own[a] == "" {
				own[a] = "сервер VPN: к нему идёт соединение мимо туннеля"
			}
		}
	}
	for a := range servers {
		if _, ok := own[a]; !ok {
			own[a] = "сервер VPN: к нему клиент ходил мимо туннеля"
		}
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	var learned []catalog.Learned
	var drops []catalog.Drop
	for id, a := range e.apps {
		if !a.cfg.Learned {
			continue
		}
		l := catalog.Learned{Name: a.cfg.Name, ID: id}
		if a.cfg.Command {
			// Идентификатор консольной программы — путь в домашней папке автора.
			l.ID, l.Command = "", a.cfg.Name
		}
		for _, s := range a.cfg.Addrs {
			ip, err := netip.ParseAddr(s)
			if err != nil || !learn.Acceptable(ip, 443) {
				continue
			}
			if why, mine := own[ip]; mine {
				drops = append(drops, catalog.Drop{App: a.cfg.Name, Value: s, Why: why})
				continue
			}
			l.Addrs = append(l.Addrs, s)
		}
		for name, d := range e.protected {
			if d.apps[id] || slices.ContainsFunc(d.addrs, func(s string) bool { return slices.Contains(l.Addrs, s) }) {
				l.Domains = append(l.Domains, name)
			}
		}
		slices.Sort(l.Domains)
		learned = append(learned, l)
	}
	slices.SortFunc(learned, func(a, b catalog.Learned) int { return e.apps[a.ID].cfg.Added.Compare(e.apps[b.ID].cfg.Added) })
	return learned, drops, nil
}

func mergeStrings(cur, add []string) []string {
	out := slices.Clone(cur)
	for _, v := range add {
		if !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	return out
}

// writeFile пишет файл службы атомарно: временный файл рядом и переименование.
func writeFile(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// catalogInfo — день каталога и сколько в нём приложений; пусто — каталога нет.
func (e *engine) catalogInfo() (string, int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.catalog.Format == 0 {
		return "", 0
	}
	day := e.catalog.Updated
	if day == "" {
		day = "-"
	}
	return day, len(e.catalog.Apps)
}
