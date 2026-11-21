package procs

import (
	"context"
	"maps"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"appguard/internal/apps"
)

// System — процессы и сокеты живой системы: всё берётся из /proc, служба работает
// от root и видит процессы всех пользователей.
type System struct{}

// Process — процесс глазами /proc.
type Process struct {
	PID     int
	Exe     string   // настоящий путь исполняемого файла
	Argv    []string // аргументы
	Unified string   // cgroup в единой иерархии: по ней видно службу systemd
	NetCls  string   // cgroup в иерархии net_cls: по ней видно, что процесс закрыт
}

// Processes — процессы системы. Потоки ядра (у них нет exe) пропускаются, как и
// процессы, которые успели завершиться.
func Processes() []Process {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	var out []Process
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		dir := filepath.Join("/proc", e.Name())
		link, err := os.Readlink(filepath.Join(dir, "exe"))
		if err != nil {
			continue
		}
		p := Process{PID: pid, Exe: ExePath(link)}
		if data, err := os.ReadFile(filepath.Join(dir, "cgroup")); err == nil {
			p.Unified, p.NetCls = ParseCgroups(data)
		}
		if Interpreter(p.Exe) {
			if data, err := os.ReadFile(filepath.Join(dir, "cmdline")); err == nil {
				cwd, _ := os.Readlink(filepath.Join(dir, "cwd"))
				p.Argv = AbsScript(ParseArgv(data), cwd)
			}
		}
		out = append(out, p)
	}
	return out
}

// Belongs — процесс p относится к приложению a: к службе systemd — по её cgroup,
// к программе — по пути исполняемого файла или скрипта в аргументах интерпретатора.
func Belongs(p Process, a AppRef, resolve func(string) (string, bool)) bool {
	if unit, ok := strings.CutPrefix(a.Path, apps.ServicePrefix); ok {
		return InUnit(p.Unified, unit)
	}
	return MatchCommand(a.Path, p.Exe, p.Argv, resolve)
}

// Resolver снимает символические ссылки и помнит ответы одного прохода.
func Resolver() func(string) (string, bool) {
	type link struct {
		real string
		ok   bool
	}
	seen := map[string]link{}
	return func(p string) (string, bool) {
		l, ok := seen[p]
		if !ok {
			real, err := filepath.EvalSymlinks(p)
			l = link{real, err == nil}
			seen[p] = l
		}
		return l.real, l.ok
	}
}

// Scan находит процессы приложений и их исходящие соединения. Приложение без
// процессов получает Running=false.
func (System) Scan(_ context.Context, list []AppRef) (map[string]Activity, error) {
	result := make(map[string]Activity, len(list))
	for _, a := range list {
		result[a.ID] = Activity{}
	}
	resolve := Resolver()
	pidApp := map[int]string{}
	for _, p := range Processes() {
		for _, a := range list {
			if Belongs(p, a, resolve) {
				pidApp[p.PID] = a.ID
				act := result[a.ID]
				act.Running = true
				result[a.ID] = act
				break
			}
		}
	}
	if len(pidApp) == 0 {
		return result, nil
	}
	owner := socketOwners(slices.Collect(maps.Keys(pidApp)))
	seen := map[string]map[Remote]bool{}
	for _, s := range Outgoing(sockets()) {
		pid, ok := owner[s.Inode]
		if !ok {
			continue
		}
		id := pidApp[pid]
		r := Remote{Addr: s.Conn.Remote.Addr(), Port: s.Conn.Remote.Port(), Proto: s.Conn.Proto}
		if seen[id] == nil {
			seen[id] = map[Remote]bool{}
		}
		if seen[id][r] {
			continue
		}
		seen[id][r] = true
		act := result[id]
		act.Remotes = append(act.Remotes, r)
		result[id] = act
	}
	return result, nil
}

// KernelUDPPorts — порты UDP-сокетов самого ядра: через такой сокет шлёт свои пакеты
// туннель в ядре (WireGuard). Таблица читается до и после обхода процессов: сокет,
// закрытый посреди обхода, выглядел бы сокетом без владельца, а через порт из этого
// списка программа вышла бы мимо защиты.
func KernelUDPPorts() []uint16 {
	before := sockets()
	owners := socketOwners(allPIDs())
	return OwnerlessUDPPorts(Lasting(before, sockets()), owners)
}

// sockets — все сокеты TCP и UDP системы.
func sockets() []Socket {
	var out []Socket
	for _, t := range []struct{ file, proto string }{{"tcp", "tcp"}, {"tcp6", "tcp"}, {"udp", "udp"}, {"udp6", "udp"}} {
		if data, err := os.ReadFile(filepath.Join("/proc/net", t.file)); err == nil {
			out = append(out, ParseProcNet(t.proto, data)...)
		}
	}
	return out
}

// socketOwners — номер inode сокета → процесс из pids, у которого он открыт.
func socketOwners(pids []int) map[uint64]int {
	out := map[uint64]int{}
	for _, pid := range pids {
		dir := filepath.Join("/proc", strconv.Itoa(pid), "fd")
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if link, err := os.Readlink(filepath.Join(dir, e.Name())); err == nil {
				if inode, ok := SocketInode(link); ok {
					out[inode] = pid
				}
			}
		}
	}
	return out
}

// allPIDs — номера всех процессов.
func allPIDs() []int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	var out []int
	for _, e := range entries {
		if pid, err := strconv.Atoi(e.Name()); err == nil {
			out = append(out, pid)
		}
	}
	return out
}

// Peers — соединения всех процессов, у которых локальный адрес local. Клиент
// WireGuard в ядре сюда не попадает: у его сокета нет процесса, поэтому сервер
// WireGuard служба не узнаёт, как не узнаёт и UDP-сервер на macOS.
func (System) Peers(_ context.Context, local netip.Addr) ([]Conn, error) {
	var mine []Socket
	for _, s := range sockets() {
		if s.Conn.Local.Addr().Unmap() == local.Unmap() {
			mine = append(mine, s)
		}
	}
	if len(mine) == 0 {
		return nil, nil // обходить дескрипторы всех процессов незачем
	}
	owner := socketOwners(allPIDs())
	var out []Conn
	for _, s := range mine {
		if pid, ok := owner[s.Inode]; ok {
			c := s.Conn
			c.PID = pid
			out = append(out, c)
		}
	}
	return out, nil
}

// TunnelOwners — какие из процессов pids держат интерфейс туннеля iface: у того,
// кто создал TUN, открыт /dev/net/tun, и ядро пишет имя интерфейса в fdinfo.
func (System) TunnelOwners(_ context.Context, iface string, pids []int) ([]int, error) {
	var out []int
	for _, pid := range pids {
		if holdsTun(pid, iface) {
			out = append(out, pid)
		}
	}
	return out, nil
}

func holdsTun(pid int, iface string) bool {
	dir := filepath.Join("/proc", strconv.Itoa(pid), "fdinfo")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	want := "iff:\t" + iface
	for _, e := range entries {
		if data, err := os.ReadFile(filepath.Join(dir, e.Name())); err == nil && hasLine(string(data), want) {
			return true
		}
	}
	return false
}

func hasLine(text, line string) bool {
	for l := range strings.Lines(text) {
		if strings.TrimRight(l, "\n") == line {
			return true
		}
	}
	return false
}

// ProxyOwners — какие из процессов pids слушают TCP на одном из адресов at.
func (System) ProxyOwners(_ context.Context, at []netip.AddrPort, pids []int) ([]int, error) {
	if len(at) == 0 || len(pids) == 0 {
		return nil, nil
	}
	owner := socketOwners(pids)
	var out []int
	for _, s := range sockets() {
		pid, ok := owner[s.Inode]
		if ok && s.Conn.State == "LISTEN" && ListensOn(s.Conn.Local, at) && !slices.Contains(out, pid) {
			out = append(out, pid)
		}
	}
	return out, nil
}
