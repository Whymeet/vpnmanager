package procs

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const (
	psPath   = "/bin/ps"
	lsofPath = "/usr/sbin/lsof"
	// scanTimeout — сколько ждать ps и lsof. Зависший lsof (сетевая файловая
	// система, залипший процесс) не должен останавливать обучение.
	scanTimeout = 8 * time.Second
)

// System — процессы и сокеты живой системы.
type System struct{}

// Scan находит процессы приложений и их исходящие соединения. Приложение без
// процессов получает Running=false.
func (System) Scan(ctx context.Context, apps []AppRef) (map[string]Activity, error) {
	ctx, cancel := context.WithTimeout(ctx, scanTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, psPath, "-A", "-o", "pid=,comm=").Output()
	if err != nil {
		return nil, fmt.Errorf("ps: %w", err)
	}
	pidApp, pids := own(ParseProcs(out), apps, procArgs)

	result := make(map[string]Activity, len(apps))
	for _, a := range apps {
		result[a.ID] = Activity{}
	}
	for _, id := range pidApp {
		act := result[id]
		act.Running = true
		result[id] = act
	}
	if len(pids) == 0 {
		return result, nil
	}

	// -a: выбрать процессы И интернет-сокеты.
	out, err = lsof(ctx, "-a", "-p", pidList(pids), "-i", "-F", "pPnT")
	if err != nil {
		return nil, err
	}
	seen := map[string]map[Remote]bool{}
	for _, c := range ParseConns(out) {
		id := pidApp[c.PID]
		if id == "" {
			continue
		}
		r := Remote{Addr: c.Remote.Addr().Unmap(), Port: c.Remote.Port(), Proto: c.Proto}
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

// own сопоставляет процессы приложениям. Приложение с символической ссылкой в
// пути (Safari) ищется и по настоящему пути. Консольная программа — по пути к
// файлу и аргументам от ядра (args): ps показывает, как её вызвали (claude), а
// это argv[0], который процесс задаёт себе сам. Путь из ps только отсеивает
// процессы, о которых ядро спрашивать незачем: абсолютный, не интерпретатор и
// не в папке программы.
func own(procs []Proc, apps []AppRef, args func(pid int) (string, []string, bool)) (pidApp map[int]string, pids []int) {
	reals := make([]string, len(apps))
	for i, a := range apps {
		if r, err := filepath.EvalSymlinks(a.Path); err == nil {
			reals[i] = r
		}
	}
	type link struct {
		real string
		ok   bool
	}
	links := map[string]link{}
	resolve := func(p string) (string, bool) {
		l, seen := links[p]
		if !seen {
			real, err := filepath.EvalSymlinks(p)
			l = link{real, err == nil}
			links[p] = l
		}
		return l.real, l.ok
	}
	var commands []AppRef
	for _, a := range apps {
		if a.Command {
			commands = append(commands, a)
		}
	}
	pidApp = map[int]string{}
	for _, p := range procs {
		id := ""
		for i, a := range apps {
			if !a.Command && Match(p.Path, a, reals[i]) {
				id = a.ID
				break
			}
		}
		if id == "" && len(commands) > 0 && worthAsking(p.Path, commands, resolve) {
			if exe, argv, ok := args(p.PID); ok {
				for _, a := range commands {
					if MatchCommand(a.Path, exe, argv, resolve) {
						id = a.ID
						break
					}
				}
			}
		}
		if id != "" {
			pidApp[p.PID] = id
			pids = append(pids, p.PID)
		}
	}
	return pidApp, pids
}

// worthAsking — о процессе с путём comm из ps стоит спросить ядро: путь не
// абсолютный, это интерпретатор или он ведёт в папку консольной программы.
func worthAsking(comm string, commands []AppRef, resolve func(string) (string, bool)) bool {
	if !strings.HasPrefix(comm, "/") || Interpreter(comm) {
		return true
	}
	real, _ := resolve(comm)
	return slices.ContainsFunc(commands, func(a AppRef) bool {
		return slices.ContainsFunc([]string{comm, real}, func(p string) bool { return p == a.Path || strings.HasPrefix(p, a.Path+"/") })
	})
}

// procArgs — путь, по которому запущен исполняемый файл процесса pid, и его
// аргументы — от ядра (kern.procargs2). Чужие процессы так видит только root:
// служба.
func procArgs(pid int) (string, []string, bool) {
	buf, err := unix.SysctlRaw("kern.procargs2", pid)
	if err != nil {
		return "", nil, false
	}
	return ParseProcArgs(buf)
}

// compile-time: System годится там, где нужен сканер.
var _ interface {
	Scan(context.Context, []AppRef) (map[string]Activity, error)
} = System{}

// Peers — соединения всех процессов, у которых локальный адрес local.
func (System) Peers(ctx context.Context, local netip.Addr) ([]Conn, error) {
	out, err := lsof(ctx, "-i", "-F", "pPnT")
	if err != nil {
		return nil, err
	}
	var peers []Conn
	for _, c := range ParseConns(out) {
		if c.Local.Addr().Unmap() == local.Unmap() {
			peers = append(peers, c)
		}
	}
	return peers, nil
}

// TunnelOwners — какие из процессов pids держат интерфейс туннеля iface.
func (System) TunnelOwners(ctx context.Context, iface string, pids []int) ([]int, error) {
	if len(pids) == 0 {
		return nil, nil
	}
	out, err := lsof(ctx, "-p", pidList(pids), "-F", "ptn")
	if err != nil {
		return nil, err
	}
	return ParseTunnelOwners(out, iface), nil
}

// ProxyOwners — какие из процессов pids слушают TCP на одном из адресов at:
// так опознаётся клиент VPN в режиме системного прокси.
func (System) ProxyOwners(ctx context.Context, at []netip.AddrPort, pids []int) ([]int, error) {
	if len(pids) == 0 || len(at) == 0 {
		return nil, nil
	}
	out, err := lsof(ctx, "-a", "-p", pidList(pids), "-iTCP", "-sTCP:LISTEN", "-F", "pn")
	if err != nil {
		return nil, err
	}
	return ParseListeners(out, at), nil
}

// lsof запускает lsof с args: -n -P — без имён хостов и портов, -w — без
// предупреждений о процессах, исчезнувших по ходу. Код 1 без вывода — ничего
// не нашлось (у выбранных процессов нет таких сокетов), это не ошибка.
func lsof(ctx context.Context, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, scanTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, lsofPath, append([]string{"-nP", "-w"}, args...)...).Output()
	var exit *exec.ExitError
	if err != nil && !(errors.As(err, &exit) && exit.ExitCode() == 1 && len(out) == 0) {
		return nil, fmt.Errorf("lsof: %w", err)
	}
	return out, nil
}

// pidList — номера процессов через запятую, для lsof -p.
func pidList(pids []int) string {
	strs := make([]string, len(pids))
	for i, p := range pids {
		strs[i] = strconv.Itoa(p)
	}
	return strings.Join(strs, ",")
}
