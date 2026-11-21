package procs

import (
	"context"
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"

	"appguard/internal/apps"
)

// Scan находит процессы приложений — программы папки установки, сам exe или
// программы пакета Store — и их исходящие соединения TCP. Таблица UDP Windows
// удалённых адресов не знает: QUIC приложения так не виден.
func (System) Scan(_ context.Context, list []AppRef) (map[string]Activity, error) {
	targets := make([]Target, len(list))
	for i, a := range list {
		targets[i] = targetOf(a.Path)
	}
	procs, err := processes()
	if err != nil {
		return nil, err
	}
	pidApp := map[int]string{}
	for _, p := range procs {
		for i, t := range targets {
			if t.Has(p.Path) {
				pidApp[p.PID] = list[i].ID
				break
			}
		}
	}

	result := make(map[string]Activity, len(list))
	for _, a := range list {
		result[a.ID] = Activity{}
	}
	for _, id := range pidApp {
		act := result[id]
		act.Running = true
		result[id] = act
	}
	if len(pidApp) == 0 {
		return result, nil
	}
	seen := map[string]map[Remote]bool{}
	for _, af := range []uint32{windows.AF_INET, windows.AF_INET6} {
		conns, err := tcpConns(af)
		if err != nil {
			return nil, err
		}
		for _, c := range conns {
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
	}
	return result, nil
}

// targetOf — цель приложения по пути из настроек.
func targetOf(path string) Target {
	if family, ok := strings.CutPrefix(path, apps.PackagePrefix); ok {
		return Target{Path: path, PackageDirs: apps.PackageDirs(family)}
	}
	fi, err := os.Stat(path)
	return Target{Path: path, Dir: err == nil && fi.IsDir()}
}

// processes — все процессы с полными путями их exe. Процесс, путь которого не
// узнать (системный, уже завершился), пропускается.
func processes() ([]Proc, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snap)
	var out []Proc
	e := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	for err = windows.Process32First(snap, &e); err == nil; err = windows.Process32Next(snap, &e) {
		if e.ProcessID == 0 {
			continue
		}
		if path, ok := imagePath(e.ProcessID); ok {
			out = append(out, Proc{PID: int(e.ProcessID), Path: path})
		}
	}
	return out, nil
}

// imagePath — полный путь exe процесса pid.
func imagePath(pid uint32) (string, bool) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", false
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n := uint32(len(buf))
	if windows.QueryFullProcessImageName(h, 0, &buf[0], &n) != nil {
		return "", false
	}
	return windows.UTF16ToString(buf[:n]), true
}
