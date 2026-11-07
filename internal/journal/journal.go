// Package journal — журнал службы: что делает защита и почему. События лежат
// по файлу на день, хранятся 7 дней, и их можно смотреть в реальном времени.
package journal

import (
	"bufio"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"vpnlock/internal/core"
)

// Keep — сколько хранятся события.
const Keep = 7 * 24 * time.Hour

const dayLayout = "2006-01-02"

// Journal — журнал в каталоге dir.
type Journal struct {
	dir string
	now func() time.Time

	mu   sync.Mutex
	day  string
	file *os.File
	subs map[chan core.Event]struct{}
}

// Open открывает журнал и удаляет события старше Keep.
func Open(dir string, now func() time.Time) (*Journal, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	j := &Journal{dir: dir, now: now, subs: map[chan core.Event]struct{}{}}
	j.Prune()
	return j, nil
}

// Add записывает событие и раздаёт его тем, кто смотрит журнал сейчас.
func (j *Journal) Add(e core.Event) error {
	line, err := json.Marshal(e)
	if err != nil {
		return err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	for ch := range j.subs {
		select {
		case ch <- e:
		default: // смотрящий не успевает читать — событие для него пропадает, файл цел
		}
	}
	if day := e.Time.Format(dayLayout); day != j.day || j.file == nil {
		if j.file != nil {
			j.file.Close()
		}
		f, err := os.OpenFile(filepath.Join(j.dir, day+".jsonl"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			j.file = nil
			return err
		}
		j.day, j.file = day, f
		j.pruneLocked()
	}
	_, err = j.file.Write(append(line, '\n'))
	return err
}

// Follow отдаёт последние n событий и канал новых. Подписка и чтение идут под
// одной блокировкой: событие не потеряется между ними и не придёт дважды.
// Отписка — stop.
func (j *Journal) Follow(n int) (recent []core.Event, live <-chan core.Event, stop func()) {
	j.mu.Lock()
	defer j.mu.Unlock()
	recent = j.tailLocked(n)
	ch := make(chan core.Event, 64)
	j.subs[ch] = struct{}{}
	return recent, ch, func() {
		j.mu.Lock()
		defer j.mu.Unlock()
		delete(j.subs, ch)
	}
}

// Prune удаляет файлы, все события в которых старше Keep.
func (j *Journal) Prune() {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.pruneLocked()
}

func (j *Journal) pruneLocked() {
	cutoff := j.now().Add(-Keep)
	for _, name := range j.days() {
		day, err := time.ParseInLocation(dayLayout, strings.TrimSuffix(name, ".jsonl"), time.Local)
		if err == nil && day.AddDate(0, 0, 1).Before(cutoff) {
			os.Remove(filepath.Join(j.dir, name))
		}
	}
}

// tailLocked — последние n событий не старше Keep, от старых к новым.
func (j *Journal) tailLocked(n int) []core.Event {
	cutoff := j.now().Add(-Keep)
	var out []core.Event
	days := j.days()
	for i := len(days) - 1; i >= 0 && len(out) < n; i-- {
		var dayEvents []core.Event
		f, err := os.Open(filepath.Join(j.dir, days[i]))
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			var e core.Event
			if json.Unmarshal(sc.Bytes(), &e) == nil && !e.Time.Before(cutoff) {
				dayEvents = append(dayEvents, e)
			}
		}
		f.Close()
		out = append(dayEvents, out...)
	}
	if len(out) > n {
		out = out[len(out)-n:]
	}
	return out
}

// days — файлы журнала по порядку дней.
func (j *Journal) days() []string {
	entries, err := os.ReadDir(j.dir)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	var names []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".jsonl") {
			names = append(names, e.Name())
		}
	}
	slices.Sort(names)
	return names
}

// Close закрывает файл дня.
func (j *Journal) Close() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.file == nil {
		return nil
	}
	err := j.file.Close()
	j.file = nil
	return err
}
