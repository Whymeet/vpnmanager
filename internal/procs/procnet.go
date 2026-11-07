package procs

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"net/netip"
	"path"
	"slices"
	"strconv"
	"strings"
)

// procStates — состояния TCP из /proc/net/tcp, которые нужны службе.
var procStates = map[string]string{"01": "ESTABLISHED", "02": "SYN_SENT", "0A": "LISTEN"}

// Socket — сокет из /proc/net/{tcp,tcp6,udp,udp6}: кому он принадлежит, таблица
// не говорит, только номер inode. PID у Conn пуст, пока владельца не найдёт
// просмотр /proc/<pid>/fd.
type Socket struct {
	Inode uint64
	UID   int
	Conn  Conn
}

// ParseProcNet разбирает таблицу /proc/net/<proto>. proto — tcp или udp, адреса
// семейства определяются по длине. Строки с inode 0 — соединения, от которых уже не
// осталось сокета (TIME_WAIT): они не нужны.
func ParseProcNet(proto string, data []byte) []Socket {
	var out []Socket
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 10 || f[0] == "sl" {
			continue
		}
		local, ok1 := procAddr(f[1])
		remote, ok2 := procAddr(f[2])
		inode, err := strconv.ParseUint(f[9], 10, 64)
		uid, uerr := strconv.Atoi(f[7])
		if !ok1 || !ok2 || err != nil || uerr != nil || inode == 0 {
			continue
		}
		c := Conn{Proto: proto, Local: local, Remote: remote}
		if proto == "tcp" {
			c.State = procStates[strings.ToUpper(f[3])]
		}
		out = append(out, Socket{Inode: inode, UID: uid, Conn: c})
	}
	return out
}

// OwnerlessUDPPorts — порты UDP-сокетов из socks, которых нет в owners: сокет root
// без подключения есть, а процесса у него нет. Так выглядит сокет самого ядра.
func OwnerlessUDPPorts(socks []Socket, owners map[uint64]int) []uint16 {
	var out []uint16
	for _, s := range socks {
		if _, owned := owners[s.Inode]; owned || s.Conn.Proto != "udp" || s.Conn.Local.Port() == 0 ||
			s.UID != 0 || s.Conn.Remote.Port() != 0 {
			continue
		}
		out = append(out, s.Conn.Local.Port())
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// Lasting — сокеты из after, которые были и в before.
func Lasting(before, after []Socket) []Socket {
	seen := make(map[uint64]bool, len(before))
	for _, s := range before {
		seen[s.Inode] = true
	}
	return slices.DeleteFunc(slices.Clone(after), func(s Socket) bool { return !seen[s.Inode] })
}

// AbsScript делает абсолютным путь к скрипту в аргументах интерпретатора:
// `cd /opt/bot && python3 bot.py`. Скрипт — первый аргумент не с минуса, как в
// MatchCommand. cwd пуст — аргументы остаются как есть.
func AbsScript(argv []string, cwd string) []string {
	if cwd == "" || len(argv) < 2 {
		return argv
	}
	out := slices.Clone(argv)
	for i, a := range out[1:] {
		if !strings.HasPrefix(a, "-") {
			if !strings.HasPrefix(a, "/") {
				out[i+1] = path.Join(cwd, a)
			}
			break
		}
	}
	return out
}

// procAddr разбирает «0100007F:0050»: адрес — слова по 4 байта в порядке байтов
// машины, порт — обычное шестнадцатеричное число. IPv4 внутри tcp6 разворачивается.
func procAddr(s string) (netip.AddrPort, bool) {
	addr, port, ok := strings.Cut(s, ":")
	if !ok {
		return netip.AddrPort{}, false
	}
	raw, err := hex.DecodeString(addr)
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return netip.AddrPort{}, false
	}
	for i := 0; i+4 <= len(raw); i += 4 {
		binary.BigEndian.PutUint32(raw[i:], binary.NativeEndian.Uint32(raw[i:]))
	}
	ip, ok := netip.AddrFromSlice(raw)
	p, err := strconv.ParseUint(port, 16, 16)
	if !ok || err != nil {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(ip.Unmap(), uint16(p)), true
}

// Outgoing — исходящие соединения из таблицы: у них есть удалённый конец, а
// локальный порт не слушается (иначе это входящее соединение к самому приложению).
func Outgoing(socks []Socket) []Socket {
	listening := map[uint16]bool{}
	for _, s := range socks {
		if s.Conn.State == "LISTEN" {
			listening[s.Conn.Local.Port()] = true
		}
	}
	var out []Socket
	for _, s := range socks {
		if s.Conn.State != "LISTEN" && s.Conn.Remote.Addr().IsValid() && !s.Conn.Remote.Addr().IsUnspecified() &&
			!listening[s.Conn.Local.Port()] {
			out = append(out, s)
		}
	}
	return out
}

// SocketInode — номер inode из ссылки /proc/<pid>/fd/N вида «socket:[12345]».
func SocketInode(link string) (uint64, bool) {
	s, ok := strings.CutPrefix(link, "socket:[")
	if !ok {
		return 0, false
	}
	n, err := strconv.ParseUint(strings.TrimSuffix(s, "]"), 10, 64)
	return n, err == nil
}

// ParseArgv разбирает /proc/<pid>/cmdline: аргументы, каждый с нулём в конце.
func ParseArgv(data []byte) []string {
	if len(data) == 0 {
		return nil
	}
	return strings.Split(strings.TrimRight(string(data), "\x00"), "\x00")
}

// ParseCgroups разбирает /proc/<pid>/cgroup: путь в единой иерархии (строка
// «0::…») и в иерархии net_cls (строка «N:net_cls…:…»).
func ParseCgroups(data []byte) (unified, netCls string) {
	for line := range strings.Lines(string(data)) {
		parts := strings.SplitN(strings.TrimSpace(line), ":", 3)
		if len(parts) != 3 {
			continue
		}
		switch {
		case parts[0] == "0" && parts[1] == "":
			unified = parts[2]
		case containsField(parts[1], "net_cls"):
			netCls = parts[2]
		}
	}
	return unified, netCls
}

func containsField(list, name string) bool {
	for f := range strings.SplitSeq(list, ",") {
		if f == name {
			return true
		}
	}
	return false
}

// InUnit — процесс из cgroup-пути path работает в службе systemd unit: своя
// группа службы или вложенная.
func InUnit(path, unit string) bool {
	return strings.Contains(path+"/", "/"+unit+"/")
}

// ExePath — путь исполняемого файла из ссылки /proc/<pid>/exe: файл могли
// заменить обновлением, тогда ядро дописывает « (deleted)».
func ExePath(link string) string { return strings.TrimSuffix(link, " (deleted)") }
