// Package config — локальные настройки службы: правило, выходы, приложения,
// обученные адреса. Файл принадлежит службе (root, 0600) и лежит в системном
// каталоге установки, а не в репозитории.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Schema — версия формата файла, которую понимает эта сборка.
const Schema = 1

// Settings — содержимое файла. Поля добавляют таски, которые вводят настройки.
// Новые поля только добавляются и необязательны, поэтому формат не меняется:
// файл прежней версии открывается как есть.
type Settings struct {
	Schema int `json:"schema"`
	// Protected — защищённые сервисы, заданные доменом, с последними известными
	// адресами. Хранятся, чтобы после перезапуска службы таблицы файрвола
	// наполнились сразу, ещё до первого разрешения имени.
	Protected []Protected `json:"protected,omitempty"`
	// Addrs — адреса, защищённые вручную, без домена: protect с адресом или
	// import из файла.
	Addrs []string `json:"addrs,omitempty"`
	// Apps — защищённые приложения.
	Apps []App `json:"apps,omitempty"`
	// Rule — правило на все защищённые приложения: "any" (по умолчанию) —
	// любой выход не из России, "mine" — только мои выходы.
	Rule string `json:"rule,omitempty"`
	// Exits — мои выходы: адреса выхода VPN, которые человек запомнил сам.
	// Среди них адреса его VPN, поэтому настройки не покидают компьютер.
	Exits []Exit `json:"exits,omitempty"`
	// VPNClientServers — серверы VPN: к ним сам клиент VPN ходил мимо туннеля, пока
	// выход был проверен. Если сервер на адресе защищённого сервиса (VPN через
	// CDN), он разрешён на физическом интерфейсе — иначе клиент не
	// переподключится. Прежний ключ vpnServers не читается: туда попадали
	// соединения любых программ.
	VPNClientServers []string `json:"vpnClientServers,omitempty"`
	// NotifyOff — системные уведомления выключены; журнал пишется всё равно.
	NotifyOff bool `json:"notifyOff,omitempty"`
	// CatalogChecked — когда ежедневное обновление последний раз сверило
	// каталог с репозиторием. SyncProblem — почему последнее не удалось
	// (пусто — удалось). CloneVersion — версия инструмента в клоне тогда же.
	CatalogChecked time.Time `json:"catalogChecked,omitzero"`
	SyncProblem    string    `json:"syncProblem,omitempty"`
	CloneVersion   string    `json:"cloneVersion,omitempty"`
}

// Exit — запомненный выход VPN.
type Exit struct {
	Name    string    `json:"name"`    // как назвал человек: «Server 1»
	IP      string    `json:"ip"`      // адрес выхода — не адрес сервера VPN
	Country string    `json:"country"` // ISO 3166-1
	Saved   time.Time `json:"saved"`
	// Unverified — адрес введён вручную (remember с адресом), и служба через
	// него ещё не выходила; страны пока нет.
	Unverified bool `json:"unverified,omitempty"`
}

// App — защищённое приложение. Узнаётся по пакету (путь к .app) и по
// идентификатору пакета; обновление приложения заменяет файлы внутри пакета и
// ничего из этого не меняет.
type App struct {
	ID    string    `json:"id"`   // CFBundleIdentifier
	Name  string    `json:"name"` // как приложение называется в Finder
	Path  string    `json:"path"` // /Applications/Notion.app; на Windows — что защищается
	Added time.Time `json:"added"`
	// Exe — на Windows: имя файла, которым приложение добавили (Notion.exe); по
	// нему приложение находится в каталоге.
	Exe string `json:"exe,omitempty"`
	// WorkSecs — сколько секунд приложение проработало, пока выход был проверен.
	// Через две минуты (и если оно успело выйти в сеть) оно считается обученным.
	WorkSecs int `json:"workSecs,omitempty"`
	// Learned — приложение обучено: статус «защищено».
	Learned   bool      `json:"learned,omitempty"`
	LearnedAt time.Time `json:"learnedAt,omitzero"`
	// Addrs — удалённые адреса, к которым подключались процессы приложения.
	Addrs []string `json:"addrs,omitempty"`
	// Catalog — приложение защищено по каталогу, без обучения.
	Catalog bool `json:"catalog,omitempty"`
	// Command — консольная программа на macOS (Claude Code): Path — что
	// защищается, Name — имя команды. Учится только до статуса «защищено».
	Command bool `json:"command,omitempty"`
	// Forgotten — адреса и домены, которые человек у приложения убрал
	// (forget): оно их больше не выучит, и каталог их не вернёт.
	Forgotten []string `json:"forgotten,omitempty"`
}

// Protected — защищённый сервис: домен и его адреса (строками, как их пишет
// netip.Addr). Адреса обновляет резолвер. Домен держится, пока у него есть
// владелец: команда protect (Manual) или приложение из каталога (Apps).
type Protected struct {
	Domain string   `json:"domain"`
	Addrs  []string `json:"addrs,omitempty"`
	Manual bool     `json:"manual,omitempty"`
	Apps   []string `json:"apps,omitempty"` // идентификаторы приложений
}

// Store — файл настроек службы.
type Store struct {
	path string
	mu   sync.Mutex
	cur  Settings
}

// Open читает настройки, а если файла ещё нет — создаёт его по умолчанию.
// Повреждённый файл или файл от более новой версии не открывается: служба не
// должна молча забыть, что она защищала.
func Open(path string) (*Store, error) {
	s := &Store{path: path}
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		s.cur = Settings{Schema: Schema}
		return s, s.write(s.cur)
	}
	if err != nil {
		return nil, err
	}
	var st Settings
	if err := json.Unmarshal(data, &st); err != nil || st.Schema < 1 {
		return nil, fmt.Errorf("настройки повреждены: %s", path)
	}
	// Домены, записанные до владельцев (0.3–0.5), защищали командой protect.
	for i, p := range st.Protected {
		if !p.Manual && len(p.Apps) == 0 {
			st.Protected[i].Manual = true
		}
	}
	if st.Schema > Schema {
		return nil, fmt.Errorf("настройки записаны более новой версией appguard (формат %d, эта сборка понимает %d) — обнови инструмент", st.Schema, Schema)
	}
	s.cur = st
	return s, nil
}

// Get возвращает копию текущих настроек (срезы не разделяются с хранилищем).
func (s *Store) Get() Settings {
	s.mu.Lock()
	defer s.mu.Unlock()
	return clone(s.cur)
}

// Update меняет настройки функцией mutate и атомарно пишет их на диск. При
// ошибке записи настройки в памяти остаются прежними.
func (s *Store) Update(mutate func(*Settings)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := clone(s.cur)
	mutate(&next)
	next.Schema = Schema
	if err := s.write(next); err != nil {
		return err
	}
	s.cur = next
	return nil
}

func clone(s Settings) Settings {
	out := s
	out.Protected = make([]Protected, len(s.Protected))
	for i, p := range s.Protected {
		p.Addrs = append([]string(nil), p.Addrs...)
		p.Apps = append([]string(nil), p.Apps...)
		out.Protected[i] = p
	}
	out.Exits = append([]Exit(nil), s.Exits...)
	out.Apps = make([]App, len(s.Apps))
	for i, a := range s.Apps {
		a.Addrs = append([]string(nil), a.Addrs...)
		a.Forgotten = append([]string(nil), a.Forgotten...)
		out.Apps[i] = a
	}
	return out
}

// write пишет файл атомарно: временный файл рядом, fsync, rename. Оборванная
// запись не оставляет полфайла.
func (s *Store) write(st Settings) error {
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".config-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // после rename удалять уже нечего
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(append(data, '\n')); err != nil {
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
	return os.Rename(tmp.Name(), s.path)
}
