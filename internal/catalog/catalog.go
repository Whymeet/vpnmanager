// Package catalog — каталог приложений: что заранее известно о сервисе
// приложения, чтобы ученик получил защиту сразу, без обучения. Файл лежит в
// репозитории (catalog/catalog.json); автор пополняет его выгрузкой того, чему
// инструмент научился на его маке.
package catalog

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"unicode"

	"golang.org/x/net/publicsuffix"

	"vpnlock/internal/learn"
	"vpnlock/internal/resolver"
)

// InClone — где каталог лежит в клоне репозитория.
const InClone = "catalog/catalog.json"

// Format — версия формата, которую понимает эта сборка. Меняется, только когда
// старая сборка поняла бы новый файл неверно.
const Format = 1

// Catalog — файл каталога.
type Catalog struct {
	Format  int    `json:"format"`
	Updated string `json:"updated,omitempty"` // день последней выгрузки, ГГГГ-ММ-ДД
	Apps    []App  `json:"apps"`
}

// App — приложение в каталоге.
type App struct {
	Name    string   `json:"name"`
	MacOS   *MacOS   `json:"macos,omitempty"`
	Windows *Windows `json:"windows,omitempty"`
	Domains []string `json:"domains,omitempty"` // защищаются вместе с поддоменами
	Addrs   []string `json:"addrs,omitempty"`   // известные адреса сервиса
}

// MacOS — как приложение узнаётся на маке: по идентификатору пакета или,
// у консольной программы (Claude Code), по имени команды.
type MacOS struct {
	ID      string `json:"id,omitempty"`      // CFBundleIdentifier
	Command string `json:"command,omitempty"` // claude
}

// Windows — как приложение узнаётся на Windows (заполняется на Windows): по
// имени исполняемого файла, которым его добавили (Notion.exe; у приложений на
// Squirrel — и Update.exe не годится, нужен свой), или по семейству пакета Store.
type Windows struct {
	Exe   []string `json:"exe,omitempty"`
	Store string   `json:"store,omitempty"`
}

// ErrNewer — каталог записан более новой версией формата: эта сборка его не
// применяет и действует по прежнему каталогу.
var ErrNewer = errors.New("каталог записан более новой версией vpnlock — обнови инструмент, а пока действует прежний каталог")

// Parse разбирает каталог. Записи, которых не может быть, отбрасываются, а
// warnings объясняют, что отброшено: пустой идентификатор, не домен, адрес,
// который нельзя закрывать (локальный, служебный).
func Parse(data []byte) (c Catalog, warnings []string, err error) {
	if err := json.Unmarshal(data, &c); err != nil {
		return Catalog{}, nil, fmt.Errorf("каталог не читается: %w", err)
	}
	if c.Format < 1 {
		return Catalog{}, nil, errors.New("в каталоге нет версии формата")
	}
	if c.Format > Format {
		return Catalog{}, nil, ErrNewer
	}
	apps := c.Apps[:0]
	for _, a := range c.Apps {
		if a.MacOS != nil && a.MacOS.ID == "" && a.MacOS.Command == "" {
			a.MacOS = nil
		}
		if a.Name == "" || (a.MacOS == nil && a.Windows == nil) {
			warnings = append(warnings, fmt.Sprintf("запись без имени или без идентификатора приложения: %q", a.Name))
			continue
		}
		a.Domains = slices.DeleteFunc(a.Domains, func(d string) bool {
			if !resolver.ValidDomain(d) {
				warnings = append(warnings, fmt.Sprintf("%s: %q — не домен", a.Name, d))
				return true
			}
			return false
		})
		a.Addrs = slices.DeleteFunc(a.Addrs, func(s string) bool {
			ip, err := netip.ParseAddr(s)
			if err != nil || !learn.Acceptable(ip, 443) {
				warnings = append(warnings, fmt.Sprintf("%s: %q — адрес, который нельзя закрывать", a.Name, s))
				return true
			}
			return false
		})
		apps = append(apps, a)
	}
	c.Apps = apps
	return c, warnings, nil
}

// ForWindows — приложение по имени исполняемого файла или, если family не
// пусто, по семейству пакета Store. Регистр не важен: в Windows его нет.
func (c Catalog) ForWindows(exe, family string) (App, bool) {
	for _, a := range c.Apps {
		w := a.Windows
		switch {
		case w == nil:
		case family != "":
			if strings.EqualFold(w.Store, family) {
				return a, true
			}
		case exe != "" && slices.ContainsFunc(w.Exe, func(e string) bool { return strings.EqualFold(e, exe) }):
			return a, true
		}
	}
	return App{}, false
}

// ForMac — приложение по идентификатору пакета.
func (c Catalog) ForMac(id string) (App, bool) {
	for _, a := range c.Apps {
		if a.MacOS != nil && id != "" && a.MacOS.ID == id {
			return a, true
		}
	}
	return App{}, false
}

// ForMacCommand — консольная программа по имени команды.
func (c Catalog) ForMacCommand(name string) (App, bool) {
	for _, a := range c.Apps {
		if a.MacOS != nil && name != "" && a.MacOS.Command == name {
			return a, true
		}
	}
	return App{}, false
}

// Learned — приложение, которому инструмент научился на маке автора.
type Learned struct {
	Name    string
	ID      string   // идентификатор пакета; у консольной программы пусто
	Command string   // имя консольной программы: путь к ней в каталог не идёт
	Domains []string // защищённые домены, чьи адреса совпали с адресами приложения
	Addrs   []string // адреса приложения без адресов VPN автора (их убрала служба)
}

// Change — что выгрузка добавила к приложению.
type Change struct {
	App     string
	New     bool // приложения в каталоге не было
	Domains []string
	Exact   []string // из Domains — сторонние, записанные точным именем
	Addrs   []string
}

// Drop — что выгрузка отбросила и почему.
type Drop struct {
	App, Value, Why string
}

// Report — итог выгрузки для экрана.
type Report struct {
	Changes []Change
	Drops   []Drop
}

// Merge вносит выученное в каталог. Собственные домены сервиса сворачиваются
// до зарегистрированного домена (api.notion.so → notion.so), сторонние
// (аналитика, отчёты об ошибках) записываются точным именем: свёрнутый
// sentry.io закрыл бы вне VPN весь этот сервис у всех учеников. Имена внутри
// общих хостингов (<имя>.github.io и подобные) отбрасываются как личные — так
// в каталог не попадают рабочие пространства. Записи о приложениях, которых нет
// в learned, не трогаются; у тех, что есть, только добавляется новое.
func Merge(cur Catalog, learned []Learned, today string) (Catalog, Report) {
	out := Catalog{Format: Format, Updated: today, Apps: slices.Clone(cur.Apps)}
	var rep Report
	for _, l := range learned {
		mac := MacOS{ID: l.ID, Command: l.Command}
		i := slices.IndexFunc(out.Apps, func(a App) bool { return a.MacOS != nil && *a.MacOS == mac })
		if i < 0 {
			out.Apps = append(out.Apps, App{Name: l.Name, MacOS: &mac})
			i = len(out.Apps) - 1
		}
		a := out.Apps[i]
		own := serviceDomains(a, l)
		var domains, exact []string
		for _, d := range l.Domains {
			value, thirdParty, why := fold(d, own)
			if why != "" {
				rep.Drops = append(rep.Drops, Drop{App: l.Name, Value: d, Why: why})
				continue
			}
			if !slices.Contains(domains, value) {
				domains = append(domains, value)
				if thirdParty {
					exact = append(exact, value)
				}
			}
		}
		ch := Change{App: a.Name, New: len(cur.Apps) <= i}
		a.Domains, ch.Domains = addNew(a.Domains, domains)
		for _, d := range ch.Domains {
			if slices.Contains(exact, d) {
				ch.Exact = append(ch.Exact, d)
			}
		}
		a.Addrs, ch.Addrs = addNew(a.Addrs, l.Addrs)
		out.Apps[i] = a
		if ch.New || len(ch.Domains) > 0 || len(ch.Addrs) > 0 {
			rep.Changes = append(rep.Changes, ch)
		}
	}
	if len(rep.Changes) == 0 {
		out.Updated = cur.Updated // ничего нового — дата каталога та же
	}
	slices.SortStableFunc(out.Apps, func(a, b App) int { return strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name)) })
	return out, rep
}

// serviceDomains — проверка «зарегистрированный домен принадлежит самому
// сервису приложения l»: свёрнутые домены его записи в каталоге entry, домен
// из идентификатора пакета (com.openai.chat → openai.com) и домены с именем
// приложения (Notion → notion.so, notion.com). Остальные — сторонние.
func serviceDomains(entry App, l Learned) func(etld1 string) bool {
	own := map[string]bool{}
	for _, d := range entry.Domains {
		if e, err := publicsuffix.EffectiveTLDPlusOne(d); err == nil && e == d {
			own[d] = true
		}
	}
	if parts := strings.Split(strings.ToLower(l.ID), "."); len(parts) >= 2 {
		own[parts[1]+"."+parts[0]] = true
	}
	name := strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return unicode.ToLower(r)
		}
		return -1
	}, l.Name)
	return func(etld1 string) bool {
		label, _, _ := strings.Cut(etld1, ".")
		return own[etld1] || (name != "" && label == name)
	}
}

// fold — домен для каталога или причина его отбросить: собственный домен
// сервиса (own) — до зарегистрированного, сторонний (thirdParty) — как есть.
func fold(d string, own func(etld1 string) bool) (value string, thirdParty bool, why string) {
	d = resolver.Normalize(d)
	if !resolver.ValidDomain(d) {
		return "", false, "не домен"
	}
	etld1, err := publicsuffix.EffectiveTLDPlusOne(d)
	if err != nil {
		return "", false, "у домена нет зарегистрированной части"
	}
	if suffix, icann := publicsuffix.PublicSuffix(etld1); !icann && strings.Contains(suffix, ".") {
		return "", false, fmt.Sprintf("похоже на личное: имя внутри общего хостинга %s", suffix)
	}
	if own(etld1) {
		return etld1, false, ""
	}
	return d, true, ""
}

// addNew добавляет к cur значения из add, которых там нет; added — добавленное.
func addNew(cur, add []string) (out, added []string) {
	out = slices.Clone(cur)
	for _, v := range add {
		if !slices.Contains(out, v) {
			out = append(out, v)
			added = append(added, v)
		}
	}
	return out, added
}

// Marshal — каталог для записи в репозиторий: с отступами и переводом строки в
// конце, чтобы разница в git читалась.
func Marshal(c Catalog) ([]byte, error) {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}
