// Package service — служба appguard: держит настройки и отвечает клиентам по
// локальному каналу. Всё, что трогает систему, приходит адаптерами (Deps),
// поэтому тесты гоняют службу целиком с подменёнными адаптерами.
package service

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"appguard/internal/apps"
	"appguard/internal/config"
	"appguard/internal/core"
	"appguard/internal/enforce"
	"appguard/internal/exitcheck"
	"appguard/internal/ipc"
	"appguard/internal/journal"
	"appguard/internal/paths"
	"appguard/internal/resolver"
)

// Accounts — учётные записи компьютера.
type Accounts interface {
	// IsAdmin — вправе ли тот, кто на другом конце канала, менять настройки.
	IsAdmin(p ipc.Peer) (bool, error)
	// Name — кто это, для сообщений.
	Name(p ipc.Peer) string
	// Owns — путь path принадлежит тому, кто на другом конце канала.
	Owns(p ipc.Peer, path string) (bool, error)
}

// Installation — то, что поставила установка.
type Installation interface {
	// Remove снимает файлы установки и описание службы.
	Remove() error
	// Stop снимает работающую службу с launchd (останавливает через диспетчер
	// служб Windows или systemd), не дожидаясь этого.
	Stop() error
}

// Network — наблюдатель сети.
type Network interface {
	// Watch шлёт снимок сразу, а затем — при каждой перемене, пока не отменён ctx.
	Watch(ctx context.Context) <-chan core.Snapshot
}

// Deps — пути и адаптеры ОС.
type Deps struct {
	Layout       paths.Layout
	Version      string
	Accounts     Accounts
	Installation Installation
	Network      Network
	Fetch        exitcheck.Fetcher  // запросы проверки выхода через туннель
	Enforce      enforce.Enforcer   // правила файрвола
	Upstreams    resolver.Upstreams // шифрованный и российский DNS для защищённых доменов
	SystemDNS    SystemDNS          // кто направляет защищённые домены на резолвер службы
	Notify       Notifier           // уведомления об открытии и закрытии сервисов
	// Reach соединяется с to только через интерфейс via: так проверка
	// убеждается, что мимо VPN до защищённого сервиса не достучаться.
	Reach        func(ctx context.Context, via core.Tunnel, to netip.AddrPort) error
	DNSAddr      string                              // где слушает резолвер службы («127.0.0.1:0» — любой порт)
	Apps         Scanner                             // процессы и соединения защищённых приложений
	Answers      Answers                             // ответы DNS на туннеле: домены приложений; nil — не учатся
	ReadApp      func(path string) (apps.App, error) // приложение по пути: пакет .app или exe
	PhysicalAddr func() (netip.Addr, bool)           // адрес физического интерфейса сейчас
	ScanEvery    time.Duration                       // как часто смотреть соединения приложений
	LearnFor     time.Duration                       // сколько приложение должно проработать при проверенном выходе
	RemindEvery  time.Duration                       // как часто журнал напоминает о запущенном, но не обученном приложении
	CheckEvery   time.Duration                       // как часто перепроверять выход
	NotifyAfter  time.Duration                       // сколько закрытие длится, прежде чем о нём уведомить
	ProbeEvery   time.Duration                       // как часто проверять «Россию напрямую» без событий сети
	GuardEvery   time.Duration                       // как часто сторож сверяет правила файрвола
	// Physical — физический интерфейс сейчас: через него зонд узнаёт домашний адрес.
	Physical func() (core.Tunnel, bool)
	// Ready вызывается один раз, когда поставлены первые правила: systemd ждёт
	// этого, прежде чем поднимать сеть. nil — ждать некому.
	Ready func()
	// Alive вызывается из цикла сторожа, пока служба работает.
	Alive func()
	Now   func() time.Time
	Logf  func(format string, args ...any)
}

// Notifier — системные уведомления вошедшему пользователю.
type Notifier interface {
	Notify(text string) error
}

// SystemDNS — доменные резолверы системы.
type SystemDNS interface {
	// Set направляет на резолвер службы ровно эти домены; skipped — домены, у
	// которых уже есть чужой резолвер.
	Set(domains []string) (skipped []string, err error)
	// Clear убирает всё, что направлял appguard.
	Clear() error
}

// russianWait — сколько резолвер ждёт российский DNS, прежде чем ответить
// программе адресами шифрованного.
const russianWait = 1500 * time.Millisecond

// journalTail — сколько последних событий показывает `appguard log` при открытии.
const journalTail = 50

// stopGrace — сколько служба после удаления ждёт, что система её снимет, прежде
// чем выйти сама (если её запустили не как службу).
const stopGrace = 5 * time.Second

// Run работает, пока не отменён ctx.
func Run(ctx context.Context, d Deps) error {
	if err := os.MkdirAll(d.Layout.StateDir, 0o700); err != nil {
		return err
	}
	unlock, err := lock(d.Layout.LockFile)
	if err != nil {
		return err
	}
	defer unlock()
	// Настройки открываются раньше канала: служба с повреждёнными настройками
	// не отвечает, что всё в порядке.
	cfg, err := config.Open(d.Layout.ConfigFile)
	if err != nil {
		return err
	}
	j, err := journal.Open(filepath.Join(d.Layout.StateDir, "journal"), d.Now)
	if err != nil {
		return fmt.Errorf("журнал: %w", err)
	}
	defer j.Close()
	ln, err := ipc.Listen(d.Layout.Socket)
	if err != nil {
		return fmt.Errorf("канал %s: %w", d.Layout.Socket, err)
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	eng := newEngine(d, j, cfg.Get().Protected, cfg.Get().Addrs, cfg.Get().Apps)
	eng.loadPolicy(cfg.Get())
	eng.loadServers(cfg.Get().VPNClientServers)
	eng.notifyOff = cfg.Get().NotifyOff
	eng.loadSync(cfg.Get())
	eng.cfg = cfg
	res := &resolver.Resolver{Up: d.Upstreams, RussianWait: russianWait}
	eng.lookup = res.Lookup
	dnsSrv := &resolver.Server{Resolver: res, Match: eng.match, Learn: eng.learn, Logf: d.Logf}
	if err := dnsSrv.Start(d.DNSAddr); err != nil {
		return fmt.Errorf("резолвер %s: %w", d.DNSAddr, err)
	}
	defer dnsSrv.Stop()
	eng.dnsAddr = dnsSrv.Addr()
	s := &service{d: d, started: d.Now(), cancel: cancel, ctx: ctx, journal: j, engine: eng}
	// Метка «работаю» лежит, пока служба работает. Осталась от прошлого
	// запуска — тот оборвался (принудительно завершён, упал, выключилось
	// питание), и система запустила службу заново.
	running := filepath.Join(d.Layout.StateDir, "running")
	if _, err := os.Stat(running); err == nil {
		s.note("служба %s перезапущена: прошлый запуск оборвался, правила файрвола всё это время оставались в системе", d.Version)
	} else {
		s.note("служба %s запущена", d.Version)
	}
	if err := os.WriteFile(running, nil, 0o600); err != nil {
		d.Logf("метка запуска: %v", err)
	}
	// Run возвращается, только когда движок закончил: блокировка снимается после,
	// и следующий запуск не застанет горутины прежнего.
	var wg sync.WaitGroup
	wg.Go(func() { s.engine.run(ctx) })
	err = (&ipc.Server{Handler: s.handle, Logf: d.Logf}).Serve(ln)
	cancel()
	wg.Wait()
	s.note("служба остановлена")
	os.Remove(running)
	return err
}

type service struct {
	d       Deps
	started time.Time
	cancel  context.CancelFunc
	ctx     context.Context
	journal *journal.Journal
	engine  *engine
}

// note пишет событие самой службы — в журнал и в её собственный вывод.
func (s *service) note(format string, args ...any) {
	text := fmt.Sprintf(format, args...)
	s.d.Logf("%s", text)
	if err := s.journal.Add(core.Event{Time: s.d.Now(), Kind: core.KindService, Text: text}); err != nil {
		s.d.Logf("журнал: %v", err)
	}
}

func (s *service) handle(peer ipc.Peer, req ipc.Request, r *ipc.Reply) func() {
	switch req.Cmd {
	case ipc.CmdStatus:
		day, n := s.engine.catalogInfo()
		stale, problem, newer := s.engine.syncStatus()
		manual, manualAddrs := s.engine.manualStatus()
		r.Send(ipc.Response{OK: true, Status: &ipc.Status{
			Version: s.d.Version, StartedAt: s.started, Rule: s.engine.ruleNow(), Exits: s.engine.exitsStatus(), NotifyOff: s.engine.notifyIsOff(),
			Paths: s.engine.paths(), Apps: s.engine.appsStatus(), Catalog: day, CatalogN: n,
			Manual: manual, ManualAddrs: manualAddrs,
			CatalogStale: stale, SyncProblem: problem, NewVersion: newer,
		}})
		return nil
	case ipc.CmdCatalog:
		if refusal, ok := s.admin(peer); !ok {
			r.Send(refusal)
			return nil
		}
		warnings, err := s.engine.setCatalog(req.Catalog)
		if err != nil {
			r.Send(ipc.Response{Code: ipc.CodeFailed, Error: "Каталог не применён: " + err.Error()})
			return nil
		}
		r.Send(ipc.Response{OK: true, Warnings: warnings})
		return nil
	case ipc.CmdRule:
		if refusal, ok := s.admin(peer); !ok {
			r.Send(refusal)
			return nil
		}
		if err := s.engine.setRule(req.Rule); err != nil {
			r.Send(ipc.Response{Code: ipc.CodeFailed, Error: err.Error()})
			return nil
		}
		r.Send(ipc.Response{OK: true})
		return nil
	case ipc.CmdProtection:
		r.Send(ipc.Response{OK: true, Protection: new(s.engine.protectionNow())})
		return nil
	case ipc.CmdNotify:
		// Уведомления включает и выключает любой: защиту они не меняют, а
		// значок у часов работает от имени человека, без прав администратора
		// (на Windows — без повышения).
		if err := s.engine.setNotify(req.Notify); err != nil {
			r.Send(ipc.Response{Code: ipc.CodeFailed, Error: err.Error()})
			return nil
		}
		r.Send(ipc.Response{OK: true})
		return nil
	case ipc.CmdSync:
		clone, refusal, ok := s.syncer(peer)
		if !ok {
			r.Send(refusal)
			return nil
		}
		warnings, err := s.engine.syncCatalog(clone, oneLine(req.Problem))
		if err != nil {
			r.Send(ipc.Response{Code: ipc.CodeFailed, Error: "Каталог не применён: " + err.Error()})
			return nil
		}
		r.Send(ipc.Response{OK: true, Warnings: warnings})
		return nil
	case ipc.CmdCheck:
		r.Send(ipc.Response{OK: true, Check: s.engine.check(s.ctx)})
		return nil
	case ipc.CmdRemember:
		if refusal, ok := s.admin(peer); !ok {
			r.Send(refusal)
			return nil
		}
		x, err := s.engine.remember(displayName(req.Name), req.IP)
		if err != nil && x.IP == "" {
			r.Send(ipc.Response{Code: ipc.CodeFailed, Error: err.Error()})
			return nil
		}
		r.Send(ipc.Response{OK: true, Exit: &x})
		return nil
	case ipc.CmdApp:
		a, d, err := s.engine.appDetail(req.AppID)
		if err != nil {
			r.Send(ipc.Response{Code: ipc.CodeFailed, Error: err.Error()})
			return nil
		}
		r.Send(ipc.Response{OK: true, App: &a, Detail: &d})
		return nil
	case ipc.CmdForgetExit:
		if refusal, ok := s.admin(peer); !ok {
			r.Send(refusal)
			return nil
		}
		gone, err := s.engine.forgetExit(strings.TrimSpace(req.Name))
		if err != nil && len(gone) == 0 {
			r.Send(ipc.Response{Code: ipc.CodeFailed, Error: err.Error()})
			return nil
		}
		r.Send(ipc.Response{OK: true, Exits: gone})
		return nil
	case ipc.CmdForgetLearned:
		if refusal, ok := s.admin(peer); !ok {
			r.Send(refusal)
			return nil
		}
		forgot, warnings, err := s.engine.forget(req.AppID, req.Addrs)
		if err != nil && len(forgot) == 0 {
			r.Send(ipc.Response{Code: ipc.CodeFailed, Error: err.Error()})
			return nil
		}
		r.Send(ipc.Response{OK: true, Forgotten: forgot, Warnings: warnings})
		return nil
	case ipc.CmdExport:
		learned, dropped, err := s.engine.export(s.ctx)
		if err != nil {
			r.Send(ipc.Response{Code: ipc.CodeFailed, Error: err.Error()})
			return nil
		}
		r.Send(ipc.Response{OK: true, Learned: learned, Dropped: dropped})
		return nil
	case ipc.CmdAddApp:
		if refusal, ok := s.admin(peer); !ok {
			r.Send(refusal)
			return nil
		}
		st, err := s.engine.addApp(req.Path, req.Name)
		if err != nil {
			resp := ipc.Response{Code: ipc.CodeFailed, Error: "Не удалось добавить: " + err.Error()}
			if st.ID != "" {
				resp.App = &st
			}
			r.Send(resp)
			return nil
		}
		r.Send(ipc.Response{OK: true, App: &st})
		return nil
	case ipc.CmdRemoveApp:
		if refusal, ok := s.admin(peer); !ok {
			r.Send(refusal)
			return nil
		}
		st, err := s.engine.removeApp(req.AppID)
		if err != nil && st.ID == "" {
			r.Send(ipc.Response{Code: ipc.CodeFailed, Error: "Не удалось убрать: " + err.Error()})
			return nil
		}
		r.Send(ipc.Response{OK: true, App: &st})
		return nil
	case ipc.CmdJournal:
		s.streamJournal(req, r)
		return nil
	case ipc.CmdNotifications:
		s.streamNotifications(r)
		return nil
	case ipc.CmdProtect:
		if refusal, ok := s.admin(peer); !ok {
			r.Send(refusal)
			return nil
		}
		addrs, err := s.engine.protect(s.ctx, req.Domain)
		if err != nil {
			r.Send(ipc.Response{Code: ipc.CodeFailed, Error: fmt.Sprintf("Не удалось защитить %s: %v", req.Domain, err)})
			return nil
		}
		s.note("защита включена для %s (%d %s)", req.Domain, len(addrs), core.Plural(len(addrs), "адрес", "адреса", "адресов"))
		r.Send(ipc.Response{OK: true})
		return nil
	case ipc.CmdImport:
		if refusal, ok := s.admin(peer); !ok {
			r.Send(refusal)
			return nil
		}
		got, dropped, err := s.engine.importList(req.Domains, req.Addrs)
		if err != nil {
			r.Send(ipc.Response{Code: ipc.CodeFailed, Error: "Импорт не применён: " + err.Error(), Warnings: dropped})
			return nil
		}
		if got.Domains+got.Addrs > 0 {
			s.note("импорт: защищено вручную %d %s и %d %s", got.Domains, core.Plural(got.Domains, "домен", "домена", "доменов"),
				got.Addrs, core.Plural(got.Addrs, "адрес", "адреса", "адресов"))
		}
		r.Send(ipc.Response{OK: true, Imported: &got, Warnings: dropped})
		return nil
	case ipc.CmdUnprotect:
		if refusal, ok := s.admin(peer); !ok {
			r.Send(refusal)
			return nil
		}
		had, err := s.engine.unprotect(req.Domain)
		if err != nil {
			r.Send(ipc.Response{Code: ipc.CodeFailed, Error: fmt.Sprintf("Не удалось снять защиту с %s: %v", req.Domain, err)})
			return nil
		}
		if had {
			s.note("защита снята с %s", req.Domain)
		}
		r.Send(ipc.Response{OK: true})
		return nil
	case ipc.CmdUninstall:
		if refusal, ok := s.admin(peer); !ok {
			r.Send(refusal)
			return nil
		}
		s.d.Logf("удаление по запросу %s (pid %d)", s.d.Accounts.Name(peer), peer.PID)
		if err := s.engine.clear(); err != nil {
			r.Send(ipc.Response{Code: ipc.CodeFailed, Error: "Не удалось снять правила файрвола: " + err.Error()})
			return nil
		}
		if err := s.d.SystemDNS.Clear(); err != nil {
			r.Send(ipc.Response{Code: ipc.CodeFailed, Error: "Не удалось снять доменные резолверы: " + err.Error()})
			return nil
		}
		if err := s.d.Installation.Remove(); err != nil {
			r.Send(ipc.Response{Code: ipc.CodeFailed, Error: "Удалить до конца не вышло: " + err.Error()})
			return nil
		}
		r.Send(ipc.Response{OK: true})
		return s.stop
	}
	r.Send(ipc.Response{
		Code:  ipc.CodeUnknown,
		Error: fmt.Sprintf("Служба не знает команды %q: похоже, она старше этой команды appguard.", req.Cmd),
	})
	return nil
}

// streamJournal шлёт последние события, а с Follow — и новые, пока клиент
// слушает и служба работает.
func (s *service) streamJournal(req ipc.Request, r *ipc.Reply) {
	tail := req.Tail
	if tail <= 0 || tail > 1000 {
		tail = journalTail
	}
	recent, live, stop := s.journal.Follow(tail)
	defer stop()
	for _, e := range recent {
		if r.Send(ipc.Response{OK: true, Event: &e}) != nil {
			return
		}
	}
	if !req.Follow {
		return
	}
	gone := r.Stream()
	for {
		select {
		case e := <-live:
			if r.Send(ipc.Response{OK: true, Event: &e}) != nil {
				return
			}
		case <-gone:
			return
		case <-s.ctx.Done():
			return
		}
	}
}

// streamNotifications шлёт уведомления об открытии и закрытии сервисов, пока
// клиент слушает и служба работает. Читать их может любой пользователь: в них
// то же, что в журнале.
func (s *service) streamNotifications(r *ipc.Reply) {
	notes, cancel := s.engine.hub.subscribe()
	defer cancel()
	gone := r.Stream()
	for {
		select {
		case note := <-notes:
			if r.Send(ipc.Response{OK: true, Event: &note}) != nil {
				return
			}
		case <-gone:
			return
		case <-s.ctx.Done():
			return
		}
	}
}

// syncer — кто вправе прислать итог ежедневного обновления каталога:
// администратор или владелец клона, из которого поставлен appguard (его записала
// установка). Задача обновления запускает git в клоне, а туда пишут и обычные
// программы, поэтому на Windows она работает без повышения — и служба пускает
// её как владельца клона. Сам каталог служба читает из клона сама: прислать
// свой нельзя.
func (s *service) syncer(peer ipc.Peer) (string, ipc.Response, bool) {
	data, err := os.ReadFile(s.d.Layout.CloneFile)
	clone := strings.TrimSpace(string(data))
	if err != nil || clone == "" {
		return "", ipc.Response{Code: ipc.CodeFailed, Error: "Неизвестно, из какого клона поставлен appguard: переустанови его по setup/README.md."}, false
	}
	// Клона нет — служба запишет это сама, своими словами: тут верить некому.
	if _, err := os.Stat(clone); errors.Is(err, fs.ErrNotExist) {
		return clone, ipc.Response{}, true
	}
	if owns, err := s.d.Accounts.Owns(peer, clone); err == nil && owns {
		return clone, ipc.Response{}, true
	}
	refusal, ok := s.admin(peer)
	return clone, refusal, ok
}

// admin пропускает только администратора: на macOS менять настройки без sudo
// может любой участник группы admin, на Windows — PowerShell, запущенный от
// имени администратора. Остальным — отказ с объяснением.
func (s *service) admin(peer ipc.Peer) (ipc.Response, bool) {
	ok, err := s.d.Accounts.IsAdmin(peer)
	if err != nil {
		s.d.Logf("не удалось проверить права %s: %v", s.d.Accounts.Name(peer), err)
	}
	if err == nil && ok {
		return ipc.Response{}, true
	}
	text := fmt.Sprintf("Менять настройки appguard может только администратор этого компьютера, а у пользователя %s таких прав нет.",
		s.d.Accounts.Name(peer))
	if runtime.GOOS == "windows" {
		text = "Менять настройки appguard можно только из PowerShell, открытого от имени администратора: " +
			"в меню «Пуск» найди «PowerShell», правой кнопкой — «Запуск от имени администратора», и повтори команду там."
	}
	return ipc.Response{Code: ipc.CodeForbidden, Error: text}, false
}

// stop снимает службу после удаления. Ответ клиенту к этому времени уже ушёл.
func (s *service) stop() {
	if err := s.d.Installation.Stop(); err != nil {
		s.d.Logf("не удалось снять службу: %v", err)
	}
	time.AfterFunc(stopGrace, s.cancel)
}
