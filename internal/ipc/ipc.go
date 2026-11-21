// Package ipc — локальный канал между клиентом (меню и команды) и службой.
// Одно соединение — один запрос: строка JSON туда, строка JSON обратно.
package ipc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"vpnlock/internal/catalog"
	"vpnlock/internal/core"
)

// Команды службы.
const (
	CmdStatus        = "status"
	CmdJournal       = "journal"
	CmdProtect       = "protect"        // закрыть адреса сервиса по домену или адрес (служебная)
	CmdUnprotect     = "unprotect"      // снять защиту с домена или адреса
	CmdImport        = "import"         // закрыть сразу домены и адреса из файла
	CmdAddApp        = "add-app"        // защитить приложение
	CmdRemoveApp     = "remove-app"     // снять защиту с приложения
	CmdApp           = "app"            // что держит приложение: адреса, домены, забытое
	CmdCatalog       = "catalog"        // загрузить новый каталог приложений
	CmdExport        = "export"         // выученное на этом маке — для выгрузки в каталог
	CmdRule          = "rule"           // сменить правило
	CmdRemember      = "remember"       // запомнить текущий выход или введённый адрес
	CmdForgetExit    = "forget-exit"    // убрать выход из моих
	CmdForgetLearned = "forget-learned" // убрать у приложения выученные адреса и домены
	CmdNotify        = "notify"         // включить или выключить уведомления
	CmdCheck         = "check"          // проверка: правила, выход, сервисы мимо VPN
	CmdSync          = "sync"           // итог ежедневного обновления каталога из клона
	CmdProtection    = "protection"     // открыта ли защита сейчас: для значка у часов
	// CmdNotifications — поток уведомлений об открытии и закрытии сервисов: на
	// Windows их показывает задача в сеансе пользователя.
	CmdNotifications = "notifications"
	CmdUninstall     = "uninstall"
)

// Коды отказов в Response.Code.
const (
	CodeForbidden = "forbidden" // менять настройки может только администратор
	CodeUnknown   = "unknown"   // служба не знает такой команды
	CodeFailed    = "failed"    // команда не выполнилась
)

// Request — запрос клиента.
type Request struct {
	Cmd string `json:"cmd"`
	// Для журнала: сколько последних событий прислать и следить ли за новыми.
	Tail   int  `json:"tail,omitempty"`
	Follow bool `json:"follow,omitempty"`
	// Для protect/unprotect — домен защищённого сервиса или адрес.
	Domain string `json:"domain,omitempty"`
	// Для import — домены и адреса из файла (пачкой: запрос не больше 64 КБ);
	// для forget-learned в Addrs — что забыть: адреса и домены вперемешку.
	Domains []string `json:"domains,omitempty"`
	Addrs   []string `json:"addrs,omitempty"`
	// Для add-app — путь к пакету приложения (/Applications/Notion.app); для
	// remove-app, app и forget-learned — его идентификатор. Имя и идентификатор служба читает из
	// самого пакета: присланному клиентом она не верит.
	Path  string `json:"path,omitempty"`
	AppID string `json:"appId,omitempty"`
	// Для catalog — содержимое файла каталога.
	Catalog []byte `json:"catalog,omitempty"`
	// Для rule — новое правило (core.RuleAny, core.RuleMine).
	Rule string `json:"rule,omitempty"`
	// Для remember — имя выхода; для forget-exit — имя или адрес выхода; для
	// add-app на Windows — имя приложения из меню «Пуск» (на macOS имя берётся
	// из пакета).
	Name string `json:"name,omitempty"`
	// Для remember — адрес выхода, введённый вручную; пусто — текущий
	// проверенный выход.
	IP string `json:"ip,omitempty"`
	// Для notify — включить (true) или выключить уведомления.
	Notify bool `json:"notify,omitempty"`
	// Для sync — почему обновиться не вышло; пусто — git pull прошёл, и
	// каталог с версией инструмента служба берёт из клона сама.
	Problem string `json:"problem,omitempty"`
}

// Response — ответ службы. Error — текст для человека, клиент печатает его как есть.
type Response struct {
	OK     bool        `json:"ok"`
	Code   string      `json:"code,omitempty"`
	Error  string      `json:"error,omitempty"`
	Status *Status     `json:"status,omitempty"`
	Event  *core.Event `json:"event,omitempty"`
	App    *AppStatus  `json:"app,omitempty"` // для add-app, remove-app и app: о каком приложении речь
	// Для app — его адреса и домены.
	Detail *AppDetail `json:"detail,omitempty"`
	// Для export — выученные приложения и что из их адресов отброшено.
	Learned []catalog.Learned `json:"learned,omitempty"`
	Dropped []catalog.Drop    `json:"dropped,omitempty"`
	// Для catalog и import — что отброшено при разборе.
	Warnings []string `json:"warnings,omitempty"`
	// Для import — сколько доменов и адресов защищено впервые.
	Imported *Imported `json:"imported,omitempty"`
	// Для remember — какой выход запомнен; для forget-exit — какие забыты.
	Exit  *ExitStatus  `json:"exit,omitempty"`
	Exits []ExitStatus `json:"exits,omitempty"`
	// Для forget-learned — что забыто (адреса и домены); чего не нашлось —
	// в Warnings.
	Forgotten []string `json:"forgotten,omitempty"`
	// Для check — пункты проверки.
	Check []CheckItem `json:"check,omitempty"`
	// Для protection — защита сейчас.
	Protection *Protection `json:"protection,omitempty"`
}

// Protection — защита сейчас: что показывает значок рядом с часами. Части, а не
// готовая фраза: меню значка коротким заголовком и строкой под ним.
type Protection struct {
	Open      bool   `json:"open"`                // защищённые приложения в сети
	IP        string `json:"ip,omitempty"`        // выход, которым открыто
	Country   string `json:"country,omitempty"`   // его страна, код
	Reason    string `json:"reason,omitempty"`    // почему закрыто; пусто — выход проверяется
	NotifyOff bool   `json:"notifyOff,omitempty"` // уведомления выключены
}

// Итог пункта проверки.
const (
	CheckOK   = "ok"   // в порядке
	CheckWarn = "warn" // защита держится, но есть что сказать (VPN выключен и т. п.)
	CheckFail = "fail" // защита не работает так, как обещано
)

// CheckItem — пункт проверки.
type CheckItem struct {
	Name   string `json:"name"`
	Result string `json:"result"` // CheckOK, CheckWarn, CheckFail
	Detail string `json:"detail"`
	Hint   string `json:"hint,omitempty"` // что сделать
}

// Imported — итог import: сколько доменов и адресов добавилось к защите.
type Imported struct {
	Domains int `json:"domains"`
	Addrs   int `json:"addrs"`
}

// AppDetail — что держит приложение: адреса и домены, закрытые вне VPN, и что
// человек у него убрал (forget).
type AppDetail struct {
	Addrs     []string `json:"addrs,omitempty"`
	Domains   []string `json:"domains,omitempty"`
	Forgotten []string `json:"forgotten,omitempty"`
}

// ExitStatus — запомненный выход.
type ExitStatus struct {
	Name    string `json:"name"`
	IP      string `json:"ip"`
	Country string `json:"country"`
	// Unverified — адрес введён вручную, и служба через него ещё не выходила:
	// страна пока неизвестна.
	Unverified bool `json:"unverified,omitempty"`
}

// Status — состояние службы.
type Status struct {
	Version   string       `json:"version"`
	StartedAt time.Time    `json:"startedAt"`
	Rule      string       `json:"rule"`                // core.RuleAny или core.RuleMine
	NotifyOff bool         `json:"notifyOff,omitempty"` // уведомления выключены
	Exits     []ExitStatus `json:"exits,omitempty"`
	Paths     []PathStatus `json:"paths"`
	Apps      []AppStatus  `json:"apps"`
	Catalog   string       `json:"catalog,omitempty"` // день каталога, ГГГГ-ММ-ДД; пусто — каталога нет
	CatalogN  int          `json:"catalogApps,omitempty"`
	// Manual — домены, защищённые вручную (protect, import); ManualAddrs —
	// сколько адресов защищено вручную без домена.
	Manual      []string `json:"manual,omitempty"`
	ManualAddrs int      `json:"manualAddrs,omitempty"`
	// CatalogStale — сколько дней каталог не сверялся с репозиторием, если
	// больше недели; SyncProblem — почему последнее обновление не удалось;
	// NewVersion — в клоне версия новее работающей.
	CatalogStale int    `json:"catalogStale,omitempty"`
	SyncProblem  string `json:"syncProblem,omitempty"`
	NewVersion   string `json:"newVersion,omitempty"`
}

// AppStatus — защищённое приложение.
type AppStatus struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Path     string `json:"path"`
	Learned  bool   `json:"learned"`           // «защищено»; иначе «ждёт обучения»
	Catalog  bool   `json:"catalog"`           // защищено по каталогу, без обучения
	Running  bool   `json:"running"`           // процессы приложения запущены
	Addrs    int    `json:"addrs"`             // сколько адресов узнано
	Domains  int    `json:"domains"`           // сколько доменов держит: из каталога и выученных
	WorkSecs int    `json:"workSecs"`          // сколько секунд проработало при проверенном выходе
	NeedSecs int    `json:"needSecs"`          // сколько нужно, чтобы считаться обученным
	Open     bool   `json:"open"`              // выход сейчас проверен: обучение идёт
	Command  bool   `json:"command,omitempty"` // консольная программа на macOS
}

// PathStatus — путь через туннель VPN или системный прокси.
type PathStatus struct {
	Iface    string `json:"iface"` // интерфейс туннеля или «прокси адрес:порт»
	State    string `json:"state"` // pending, verified, russian, unverified
	IP       string `json:"ip,omitempty"`
	Country  string `json:"country,omitempty"`
	Summary  string `json:"summary"` // состояние одной строкой для человека
	Default  bool   `json:"default,omitempty"`
	Direct   bool   `json:"direct,omitempty"`   // клиент VPN отправляет российские адреса напрямую
	Proxy    bool   `json:"proxy,omitempty"`    // путь — системный прокси
	Listener string `json:"listener,omitempty"` // кто слушает порт прокси
}

// Peer — кто на другом конце канала. Его называет ядро, подделать клиент не может.
type Peer struct {
	UID int // macOS; на Windows -1
	PID int
	// Admin — на Windows: клиент пришёл по каналу администратора, а туда ядро
	// пускает только программы, запущенные от имени администратора.
	Admin bool
}

const (
	dialTimeout    = 2 * time.Second
	callTimeout    = 15 * time.Second
	requestTimeout = 5 * time.Second
	maxRequest     = 64 << 10
)

var (
	// ErrNotRunning — служба не слушает канал: не установлена, остановлена или ещё стартует.
	ErrNotRunning = errors.New("служба не отвечает")
	// ErrEnded — служба закрыла поток ответов: остановилась или перезапускается.
	ErrEnded = errors.New("служба закрыла соединение")
)

// Call отправляет запрос службе и ждёт ответа.
func Call(socket string, req Request) (Response, error) {
	return CallWait(socket, req, callTimeout)
}

// CallWait — Call со своим сроком: для команды, которую служба выполняет долго.
func CallWait(socket string, req Request, wait time.Duration) (Response, error) {
	conn, err := dial(socket)
	if err != nil {
		return Response{}, fmt.Errorf("%w: %v", ErrNotRunning, err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(wait))
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return Response{}, err
	}
	var resp Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return Response{}, fmt.Errorf("служба не ответила: %w", err)
	}
	return resp, nil
}

// Stream отправляет запрос и передаёт each каждый ответ, пока служба их шлёт.
// Ошибка each прерывает чтение и возвращается как есть.
func Stream(socket string, req Request, each func(Response) error) error {
	return StreamContext(context.Background(), socket, req, each)
}

// StreamContext — Stream, который прерывается отменой ctx (тогда возвращается
// ctx.Err()).
func StreamContext(ctx context.Context, socket string, req Request, each func(Response) error) error {
	conn, err := dial(socket)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrNotRunning, err)
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	err = stream(conn, req, each)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

func stream(conn net.Conn, req Request, each func(Response) error) error {
	conn.SetWriteDeadline(time.Now().Add(callTimeout))
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return err
	}
	dec := json.NewDecoder(conn)
	for {
		var resp Response
		if err := dec.Decode(&resp); err != nil {
			if errors.Is(err, io.EOF) {
				return ErrEnded
			}
			return err
		}
		if err := each(resp); err != nil {
			return err
		}
	}
}

// Reply — ответ на один запрос.
type Reply struct {
	conn net.Conn
	enc  *json.Encoder
}

// Send отправляет ответ. Обычная команда отвечает один раз, журнал — строкой
// на событие. Срок записи считается заново: долгая команда не должна терять ответ
// из-за срока, заведённого на чтение запроса.
func (r *Reply) Send(resp Response) error {
	r.conn.SetWriteDeadline(time.Now().Add(requestTimeout))
	return r.enc.Encode(resp)
}

// Stream снимает тайм-аут: ответы идут, пока клиент слушает. Канал
// закрывается, когда клиент отключился.
func (r *Reply) Stream() <-chan struct{} {
	r.conn.SetDeadline(time.Time{})
	gone := make(chan struct{})
	go func() {
		io.Copy(io.Discard, r.conn)
		close(gone)
	}()
	return gone
}

// Handler отвечает на запрос через r. after, если не nil, выполняется, когда
// ответ уже ушёл клиенту: так служба успевает ответить на `uninstall`, прежде
// чем снять себя.
type Handler func(peer Peer, req Request, r *Reply) (after func())

// Server принимает запросы клиентов.
type Server struct {
	Handler Handler
	Logf    func(format string, args ...any)
}

// Serve работает, пока не закрыт ln.
func (s *Server) Serve(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if errors.Is(err, net.ErrClosed) {
			return nil
		}
		if err != nil {
			return err
		}
		go s.serve(conn)
	}
}

func (s *Server) serve(conn net.Conn) {
	defer conn.Close()
	peer, err := peerOf(conn)
	if err != nil {
		s.Logf("канал: не удалось узнать, кто подключился: %v", err)
		return
	}
	conn.SetDeadline(time.Now().Add(requestTimeout))
	var req Request
	if err := json.NewDecoder(io.LimitReader(conn, maxRequest)).Decode(&req); err != nil {
		return
	}
	after := s.Handler(peer, req, &Reply{conn: conn, enc: json.NewEncoder(conn)})
	conn.Close()
	if after != nil {
		after()
	}
}
