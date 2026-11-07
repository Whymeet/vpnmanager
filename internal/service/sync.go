package service

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"vpnlock/internal/catalog"
	"vpnlock/internal/config"
	"vpnlock/internal/core"
	"vpnlock/internal/version"
)

// staleAfter — сколько каталог может не сверяться с репозиторием, прежде чем
// журнал и статус напомнят обновиться.
const staleAfter = 7 * 24 * time.Hour

// syncState — что известно о ежедневном обновлении каталога из клона.
type syncState struct {
	checked      time.Time // когда каталог последний раз сверился с репозиторием
	problem      string    // почему последнее обновление не удалось; пусто — удалось
	cloneVersion string    // версия инструмента в клоне на последнем обновлении
	reminded     time.Time // когда журнал последний раз напоминал об устаревшем каталоге
}

// loadSync берёт состояние обновления из настроек. Обновления ещё не было —
// каталог свежий на день, когда его положила установка.
func (e *engine) loadSync(st config.Settings) {
	e.sync = syncState{checked: st.CatalogChecked, problem: st.SyncProblem, cloneVersion: st.CloneVersion}
	if e.sync.checked.IsZero() {
		if fi, err := os.Stat(e.catalogFile()); err == nil {
			e.sync.checked = fi.ModTime()
		}
	}
}

// syncCatalog принимает итог ежедневного обновления: git pull в клоне прошёл —
// служба берёт из клона каталог и версию инструмента; не прошёл — problem, и
// тогда ничего не меняется: защита работает на последнем каталоге.
func (e *engine) syncCatalog(clone, problem string) ([]string, error) {
	now := e.d.Now()
	var data []byte
	cloneVersion := ""
	if _, err := os.Stat(clone); errors.Is(err, fs.ErrNotExist) {
		problem = "клон " + clone + " не найден — перемещён или удалён; переустанови vpnlock из нового места по setup/README.md"
	} else if problem == "" {
		var err error
		if data, err = readClone(clone, catalog.InClone); err != nil {
			problem = fmt.Sprintf("в клоне %s не прочитать %s: %v", clone, catalog.InClone, err)
		}
		if v, err := readClone(clone, cloneVersionFile); err == nil {
			cloneVersion = oneLine(string(v))
		}
	}
	if problem != "" {
		e.mu.Lock()
		e.sync.problem = problem
		on := e.onCatalog()
		e.mu.Unlock()
		e.record([]core.Event{{Time: now, Kind: core.KindCatalog, Text: "каталог не обновился: " + problem + on}})
		return nil, e.cfg.Update(func(s *config.Settings) { s.SyncProblem = problem })
	}
	var warnings []string
	if cur, err := os.ReadFile(e.catalogFile()); err != nil || !bytes.Equal(cur, data) {
		w, err := e.setCatalog(data)
		if err != nil {
			why := "каталог в клоне не применён: " + err.Error()
			e.mu.Lock()
			e.sync.problem = why
			e.mu.Unlock()
			e.cfg.Update(func(s *config.Settings) { s.SyncProblem = why })
			return nil, err
		}
		warnings = w
	}
	e.mu.Lock()
	e.sync.checked, e.sync.problem, e.sync.cloneVersion = now, "", cloneVersion
	e.mu.Unlock()
	if version.Newer(cloneVersion, e.d.Version) {
		e.record([]core.Event{{Time: now, Kind: core.KindCatalog,
			Text: fmt.Sprintf("в клоне новая версия vpnlock %s (работает %s) — обнови по разделу «Как обновиться» в setup/README.md", cloneVersion, e.d.Version)}})
	}
	return warnings, e.cfg.Update(func(s *config.Settings) {
		s.CatalogChecked, s.SyncProblem, s.CloneVersion = now, "", cloneVersion
	})
}

// cloneVersionFile — версия инструмента в клоне.
const cloneVersionFile = "internal/version/VERSION"

// maxCloneFile — больше файл из клона служба не читает: каталог — десятки
// килобайт.
const maxCloneFile = 1 << 20

// readClone читает файл name из клона. В клон пишут и обычные программы, а
// служба работает от root (SYSTEM), поэтому по ссылкам за пределы клона она не
// ходит (os.Root) и читает только обычный файл не больше maxCloneFile.
func readClone(clone, name string) ([]byte, error) {
	root, err := os.OpenRoot(clone)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	name = filepath.FromSlash(name)
	// Не обычный файл (канал, устройство) не открывается вовсе: чтение из
	// канала повисло бы.
	if fi, err := root.Lstat(name); err != nil {
		return nil, err
	} else if !fi.Mode().IsRegular() {
		return nil, errors.New("не обычный файл")
	}
	f, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil {
		return nil, err
	} else if !fi.Mode().IsRegular() {
		return nil, errors.New("не обычный файл")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxCloneFile+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxCloneFile {
		return nil, fmt.Errorf("больше %d байт", maxCloneFile)
	}
	return data, nil
}

// oneLine — первая строка s без управляющих символов, не длиннее 300 символов:
// текст от клиента идёт в журнал и статус, а их читают в терминале.
func oneLine(s string) string {
	s, _, _ = strings.Cut(strings.TrimSpace(s), "\n")
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
	if r := []rune(s); len(r) > 300 {
		s = string(r[:300]) + "…"
	}
	return strings.TrimSpace(s)
}

// remindStale напоминает в журнале, если каталог не сверялся с репозиторием
// дольше недели, — не чаще раза в сутки.
func (e *engine) remindStale() {
	now := e.d.Now()
	e.mu.Lock()
	days := e.staleDays(now)
	if days == 0 || now.Sub(e.sync.reminded) < 24*time.Hour {
		e.mu.Unlock()
		return
	}
	e.sync.reminded = now
	why := e.sync.problem
	on := e.onCatalog()
	e.mu.Unlock()
	if why == "" {
		why = "ежедневное обновление не доходит до службы"
	}
	e.record([]core.Event{{Time: now, Kind: core.KindCatalog,
		Text: fmt.Sprintf("каталог не обновлялся %d %s: %s%s. Обновить вручную: git pull в клоне, затем vpnlock catalog load",
			days, core.Plural(days, "день", "дня", "дней"), why, on)}})
}

// staleDays — сколько дней каталог не сверялся с репозиторием, если дольше
// недели; иначе 0. Вызывать под e.mu.
func (e *engine) staleDays(now time.Time) int {
	if e.catalog.Format == 0 || e.sync.checked.IsZero() || now.Sub(e.sync.checked) <= staleAfter {
		return 0
	}
	return int(now.Sub(e.sync.checked) / (24 * time.Hour))
}

// onCatalog — « — защита работает на каталоге от …», если каталог есть.
// Вызывать под e.mu.
func (e *engine) onCatalog() string {
	if e.catalog.Format == 0 {
		return ""
	}
	return " — защита работает на каталоге " + catalogDay(e.catalog.Updated)
}

// syncStatus — напоминания для статуса.
func (e *engine) syncStatus() (stale int, problem, newer string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if version.Newer(e.sync.cloneVersion, e.d.Version) {
		newer = e.sync.cloneVersion
	}
	return e.staleDays(e.d.Now()), e.sync.problem, newer
}
