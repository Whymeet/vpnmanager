// Package procs — что запущено и к чему подключено. По процессам определяется,
// какие из них принадлежат защищённому приложению, а по их сокетам — удалённые
// адреса, к которым приложение ходит. Служба работает от root и видит процессы
// всех пользователей.
package procs

import (
	"bufio"
	"bytes"
	"net/netip"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// AppRef — приложение, процессы которого ищутся.
type AppRef struct {
	ID   string // идентификатор пакета
	Path string // /Applications/Notion.app; у консольной программы — что защищается
	// Command — консольная программа (Claude Code): её процессы узнаются по
	// пути к файлу от ядра, а не по пути из ps.
	Command bool
}

// Remote — удалённый конец соединения процесса.
type Remote struct {
	Addr  netip.Addr
	Port  uint16
	Proto string // tcp или udp
}

// Activity — что известно о приложении сейчас.
type Activity struct {
	Running bool     // есть хотя бы один его процесс
	Remotes []Remote // исходящие соединения всех его процессов
}

// Proc — процесс и исполняемый файл, из которого он запущен.
type Proc struct {
	PID  int
	Path string
}

// Conn — соединение процесса.
type Conn struct {
	PID    int
	Proto  string
	Local  netip.AddrPort
	Remote netip.AddrPort
	State  string // состояние TCP (ESTABLISHED, SYN_SENT…); у UDP пусто
}

// Established — соединение установлено. У UDP состояния нет: сокет, привязанный
// к удалённому адресу, считается установленным.
func (c Conn) Established() bool { return c.Proto == "udp" || c.State == "ESTABLISHED" }

// ParseProcs разбирает вывод `ps -A -o pid=,comm=`: номер процесса и путь к
// исполняемому файлу, который может содержать пробелы.
func ParseProcs(out []byte) []Proc {
	var procs []Proc
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		num, path, ok := strings.Cut(line, " ")
		if !ok {
			continue
		}
		pid, err := strconv.Atoi(num)
		if err != nil || pid <= 0 {
			continue
		}
		if path = strings.TrimSpace(path); path != "" {
			procs = append(procs, Proc{PID: pid, Path: path})
		}
	}
	return procs
}

// ParseConns разбирает вывод `lsof -F pPnT`: по записи на сокет. Берутся
// исходящие соединения — те, у которых есть удалённый конец и локальный порт
// не слушается тем же процессом: иначе это входящее соединение к самому
// приложению, а не к его сервису.
func ParseConns(out []byte) []Conn {
	var (
		pid       int
		cur       *socket
		listening = map[int]map[uint16]bool{}
		found     []Conn
	)
	flush := func() {
		if cur != nil && pid != 0 {
			if c, ok := cur.conn(pid, listening); ok {
				found = append(found, c)
			}
		}
		cur = nil
	}
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if len(line) < 2 {
			continue
		}
		val := line[1:]
		switch line[0] {
		case 'p':
			flush()
			pid, _ = strconv.Atoi(val)
		case 'f':
			flush()
			cur = &socket{}
		case 'P':
			if cur != nil {
				cur.proto = strings.ToLower(val)
			}
		case 'n':
			if cur != nil {
				cur.name = val
			}
		case 'T':
			if st, ok := strings.CutPrefix(val, "ST="); ok && cur != nil {
				cur.state = st
			}
		}
	}
	flush()
	// Слушающие порты известны только после разбора всего вывода: сокет, который
	// слушает порт, может идти в выводе позже соединения, принятого на него.
	out2 := found[:0]
	for _, c := range found {
		if !listening[c.PID][c.Local.Port()] {
			out2 = append(out2, c)
		}
	}
	return out2
}

// socket — запись о сокете в выводе lsof.
type socket struct{ proto, name, state string }

// conn превращает запись в соединение. Слушающие сокеты (и непривязанные UDP)
// отмечаются в listening и соединением не считаются.
func (s socket) conn(pid int, listening map[int]map[uint16]bool) (Conn, bool) {
	if s.proto != "tcp" && s.proto != "udp" {
		return Conn{}, false
	}
	localStr, remoteStr, connected := strings.Cut(s.name, "->")
	if !connected || s.state == "LISTEN" {
		if port, ok := portOf(localStr); ok {
			if listening[pid] == nil {
				listening[pid] = map[uint16]bool{}
			}
			listening[pid][port] = true
		}
		return Conn{}, false
	}
	local, lerr := netip.ParseAddrPort(strings.TrimSpace(localStr))
	remote, rerr := netip.ParseAddrPort(strings.TrimSpace(remoteStr))
	if lerr != nil || rerr != nil {
		return Conn{}, false
	}
	return Conn{PID: pid, Proto: s.proto, Local: local, Remote: remote, State: s.state}, true
}

// utunControl — имя управляющего сокета utun в выводе lsof: «[ctl
// com.apple.net.utun_control id 5 unit 12]». Номер unit на единицу больше
// номера интерфейса: unit 12 — utun11.
var utunControl = regexp.MustCompile(`^\[ctl com\.apple\.net\.utun_control id \d+ unit (\d+)\]$`)

// ParseTunnelOwners разбирает вывод `lsof -F ptn`: процессы, у которых открыт
// управляющий сокет интерфейса iface (utunN). Такой сокет держит тот, кто
// создал туннель, — клиент VPN или его расширение Network Extension; без прав
// root к utun_control не подключиться. Считается только сокет ядра (тип
// systm): то же имя у lsof бывает и у unix-сокета, который заведёт кто угодно.
func ParseTunnelOwners(out []byte, iface string) []int {
	n, ok := strings.CutPrefix(iface, "utun")
	num, err := strconv.Atoi(n)
	if !ok || err != nil || num < 0 {
		return nil
	}
	unit := strconv.Itoa(num + 1)
	var (
		pid    int
		typ    string // тип текущего файла
		owners []int
	)
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if len(line) < 2 {
			continue
		}
		switch line[0] {
		case 'p':
			typ = ""
			pid, _ = strconv.Atoi(line[1:])
		case 'f':
			typ = ""
		case 't':
			typ = line[1:]
		case 'n':
			if m := utunControl.FindStringSubmatch(line[1:]); m != nil && m[1] == unit && typ == "systm" && pid > 0 && !slices.Contains(owners, pid) {
				owners = append(owners, pid)
			}
		}
	}
	return owners
}

// ParseListeners разбирает вывод `lsof -F pn` для слушающих сокетов TCP:
// процессы, которые слушают один из адресов at — сам адрес или «все адреса» с
// тем же портом.
func ParseListeners(out []byte, at []netip.AddrPort) []int {
	var (
		pid  int
		pids []int
	)
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		line := sc.Text()
		if len(line) < 2 {
			continue
		}
		switch line[0] {
		case 'p':
			pid, _ = strconv.Atoi(line[1:])
		case 'n':
			name := line[1:]
			if strings.Contains(name, "->") {
				continue
			}
			local, ok := netip.AddrPort{}, false
			if port, wild := strings.CutPrefix(name, "*:"); wild {
				if p, err := strconv.ParseUint(port, 10, 16); err == nil {
					local, ok = netip.AddrPortFrom(netip.IPv4Unspecified(), uint16(p)), true
				}
			} else if ap, err := netip.ParseAddrPort(name); err == nil {
				local, ok = ap, true
			}
			if ok && pid > 0 && ListensOn(local, at) && !slices.Contains(pids, pid) {
				pids = append(pids, pid)
			}
		}
	}
	return pids
}

// ListensOn — слушающий сокет на local принимает соединения на один из адресов
// at: адрес тот же или «все адреса», порт тот же.
func ListensOn(local netip.AddrPort, at []netip.AddrPort) bool {
	return slices.ContainsFunc(at, func(a netip.AddrPort) bool {
		return local.Port() == a.Port() && (local.Addr().Unmap() == a.Addr().Unmap() || local.Addr().IsUnspecified())
	})
}

// portOf — порт из «*:8080», «127.0.0.1:8080» или «[::1]:8080».
func portOf(hostport string) (uint16, bool) {
	i := strings.LastIndex(hostport, ":")
	if i < 0 {
		return 0, false
	}
	p, err := strconv.ParseUint(hostport[i+1:], 10, 16)
	return uint16(p), err == nil
}

// Match — исполняемый файл exe относится к приложению app:
//   - он лежит внутри пакета — основной процесс, вспомогательные процессы,
//     XPC-службы, агенты входа и обновлятор внутри пакета;
//   - или это обновлятор, который приложение копирует в кэш на время обновления
//     (Sparkle, Squirrel/ShipIt): путь проходит через Library/Caches, а каталог
//     в нём назван по идентификатору пакета.
//
// real — путь пакета без символических ссылок: процесс запущен по настоящему
// пути, а в списке приложений может лежать ссылка (Safari).
func Match(exe string, app AppRef, real string) bool {
	for _, root := range []string{app.Path, real} {
		if root != "" && strings.HasPrefix(exe, root+"/") {
			return true
		}
	}
	if app.ID == "" || !strings.Contains(exe, "/Library/Caches/") {
		return false
	}
	for _, part := range strings.Split(filepath.ToSlash(exe), "/") {
		if part == app.ID || strings.HasPrefix(part, app.ID+".") {
			return true
		}
	}
	return false
}
