package apps

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// unitName — имя службы systemd: в команды systemctl попадает только оно.
var unitName = regexp.MustCompile(`^[A-Za-z0-9:_.\\@-]+\.service$`)

// launcher — программы, которые запускают чужое: интерпретаторы и запускатели. Ярлык
// с такой программой — не приложение, а её защита закрыла бы всё, что идёт через неё.
var launcher = regexp.MustCompile(`^(sh|bash|dash|zsh|fish|env|sudo|su|pkexec|python[0-9.]*|pypy[0-9.]*|perl[0-9.]*|ruby[0-9.]*|node|nodejs|java|mono|dotnet|wine|wine64|flatpak|snap|snapd|electron[0-9]*|xdg-open|gtk-launch|gio|exo-open|kioclient[0-9]*)$`)

// snapExec — строка обёртки, которая передаёт запуск команде snap. Такие обёртки
// лежат в /usr/bin вместо пакетов, переехавших в snap: firefox, chromium.
var snapExec = regexp.MustCompile(`(?m)^\s*exec\s+"?(/snap/bin/[A-Za-z0-9._-]+)`)

// Read узнаёт приложение по пути к программе или по службе systemd
// (systemd:<имя>.service). Защищено оно сразу: сеть закрывается самому процессу,
// учить его адреса не нужно.
func Read(path string) (App, error) {
	if unit, ok := strings.CutPrefix(path, ServicePrefix); ok {
		return readService(unit)
	}
	path = filepath.Clean(path)
	if !filepath.IsAbs(path) {
		return App{}, fmt.Errorf("%s — не путь к программе (нужно вроде /usr/bin/curl или ~/.local/bin/claude)", path)
	}
	// Команда snap — ссылка на сам snap: снимать её нельзя, защитился бы он.
	if name, ok := snapName(path); ok {
		return readSnap(name, path)
	}
	a, err := readCommand(path)
	if err != nil {
		return a, err
	}
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return App{}, err
	}
	if data := scriptHead(real); data != nil {
		if m := snapExec.FindSubmatch(data); m != nil {
			if name, ok := snapName(string(m[1])); ok {
				return readSnap(name, path)
			}
		}
	}
	if Launcher(real) {
		return App{}, fmt.Errorf("%s запускает другие программы: закрыть её — значит закрыть их все. Защити саму программу или скрипт: vpnlock add /путь/к/скрипту", filepath.Base(path))
	}
	if root := binRoot(real); root != "" {
		a.ID, a.Path = CommandPrefix+root, root
	}
	a.Instant = true
	return a, nil
}

// Launcher — path запускает чужие программы, а не работает сам.
func Launcher(path string) bool { return launcher.MatchString(filepath.Base(path)) }

// snapName — имя snap у команды /snap/bin/<имя> или /snap/bin/<имя>.<команда>.
func snapName(path string) (string, bool) {
	rest, ok := strings.CutPrefix(path, "/snap/bin/")
	if !ok || rest == "" || strings.Contains(rest, "/") {
		return "", false
	}
	name, _, _ := strings.Cut(rest, ".")
	return name, name != ""
}

// readSnap защищает папку /snap/<имя>: ревизии лежат внутри неё, и обновление snap
// остаётся под защитой.
func readSnap(name, path string) (App, error) {
	dir := "/snap/" + name
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		return App{}, fmt.Errorf("пакет snap %s не установлен", name)
	}
	return App{ID: CommandPrefix + dir, Name: filepath.Base(path), Path: dir, Command: true, Instant: true}, nil
}

// scriptHead — начало файла, если это скрипт; иначе nil.
func scriptHead(path string) []byte {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	buf := make([]byte, 64<<10)
	n, _ := io.ReadFull(f, buf)
	if !bytes.HasPrefix(buf[:n], []byte("#!")) {
		return nil
	}
	return buf[:n]
}

// binRoot — папка продукта над bin: /opt/foo/bin/foo или /usr/share/code/bin/code.
// Команда там часто только скрипт, а работает соседний файл папки продукта (значок
// VS Code запускает /usr/share/code/code). У общих папок (/usr, /opt) — пусто.
func binRoot(real string) string {
	d := filepath.Dir(real)
	if b := filepath.Base(d); b != "bin" && b != "sbin" {
		return ""
	}
	root := filepath.Dir(d)
	if up := filepath.Dir(root); up == "/usr/share" || up == "/usr/lib" || !sharedDir(root) {
		return root
	}
	return ""
}

// Moved — команда name уже не то, что защищается под id: файл цели исчез или
// обновление переставило ссылку на другую папку.
func Moved(name, id string) bool {
	target, ok := strings.CutPrefix(id, CommandPrefix)
	if !ok {
		return false
	}
	if _, err := os.Stat(target); err != nil {
		return true
	}
	path, err := exec.LookPath(name)
	if err != nil {
		return false
	}
	a, err := Read(path)
	return err == nil && a.ID != id
}

// readService проверяет у systemd, что такая служба есть.
func readService(unit string) (App, error) {
	if !unitName.MatchString(unit) {
		return App{}, fmt.Errorf("%q — не имя службы systemd", unit)
	}
	out, err := exec.Command("systemctl", "show", "-p", "LoadState", "--value", "--", unit).Output()
	if err != nil {
		return App{}, fmt.Errorf("systemctl show %s: %w", unit, err)
	}
	if state := strings.TrimSpace(string(out)); state != "loaded" {
		return App{}, fmt.Errorf("службы %s нет (systemd: %s)", unit, state)
	}
	return App{ID: ServicePrefix + unit, Name: strings.TrimSuffix(unit, ".service"), Path: ServicePrefix + unit, Instant: true, Command: true}, nil
}

// ServiceExecs — файлы, которые запускает служба: на них ставится перехват запуска.
func ServiceExecs(unit string) ([]string, error) {
	if !unitName.MatchString(unit) {
		return nil, fmt.Errorf("%q — не имя службы systemd", unit)
	}
	out, err := exec.Command("systemctl", "show", "-p", "ExecStartPre", "-p", "ExecStart", "-p", "ExecStartPost", "--", unit).Output()
	if err != nil {
		return nil, fmt.Errorf("systemctl show %s: %w", unit, err)
	}
	list := ExecPaths(string(out))
	// Путь запуска в событии перехвата настоящий, а в описании службы — как написал
	// автор: /usr/bin/python3, /bin/sh.
	for i, p := range list {
		if real, err := filepath.EvalSymlinks(p); err == nil {
			list[i] = real
		}
	}
	return list, nil
}

// FindService — служба systemd с таким именем: nginx или nginx.service. Нет — пусто.
func FindService(name string) string {
	unit := name
	if !strings.HasSuffix(unit, ".service") {
		unit += ".service"
	}
	if _, err := readService(unit); err != nil {
		return ""
	}
	return ServicePrefix + unit
}

// SameProgram — служба запускает ту же программу, что и команда path: nginx из
// PATH и nginx.service — одно и то же, а ssh и ssh.service (sshd) — нет.
func SameProgram(service, path string) bool {
	execs, err := ServiceExecs(strings.TrimPrefix(service, ServicePrefix))
	if err != nil {
		return false
	}
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return false
	}
	return slices.ContainsFunc(execs, func(p string) bool {
		r, err := filepath.EvalSymlinks(p)
		return err == nil && r == real
	})
}

// Dirs — папки меню приложений: системные, Flatpak, Snap и пользователя.
func Dirs() []string {
	dirs := []string{"/usr/share/applications", "/usr/local/share/applications",
		"/var/lib/flatpak/exports/share/applications", "/var/lib/snapd/desktop/applications"}
	if home := userHome(); home != "" {
		dirs = append(dirs, filepath.Join(home, ".local", "share", "applications"))
	}
	return dirs
}

// userHome — домашняя папка того, кто сел за компьютер: под sudo это не root.
func userHome() string {
	if name := os.Getenv("SUDO_USER"); name != "" && os.Geteuid() == 0 {
		if u, err := user.Lookup(name); err == nil {
			return u.HomeDir
		}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return home
}

// Scan — установленное: приложения меню из папок dirs и включённые службы systemd.
// Программы, которых нет на диске, в список не попадают, как и ярлыки запускателей
// (Flatpak, sh -c, python3 скрипт): защитить по ним нечего. Список отсортирован по
// имени.
func Scan(dirs []string) []App {
	var found []App
	seen := map[string]bool{}
	add := func(a App) {
		if !seen[a.ID] {
			seen[a.ID] = true
			found = append(found, a)
		}
	}
	for _, dir := range dirs {
		files, _ := filepath.Glob(filepath.Join(dir, "*.desktop"))
		for _, f := range files {
			data, err := os.ReadFile(f)
			if err != nil {
				continue
			}
			d, ok := ParseDesktop(data)
			if !ok {
				continue
			}
			path, err := exec.LookPath(d.Exec)
			if err != nil {
				continue
			}
			if a, err := Read(path); err == nil {
				a.Name, a.Path = d.Name, path
				add(a)
			}
		}
	}
	if out, err := exec.Command("systemctl", "list-unit-files", "--type=service", "--no-legend", "--no-pager").Output(); err == nil {
		for _, unit := range UnitNames(string(out)) {
			add(App{ID: ServicePrefix + unit, Name: strings.TrimSuffix(unit, ".service"), Path: ServicePrefix + unit, Instant: true, Command: true})
		}
	}
	slices.SortFunc(found, func(a, b App) int {
		if c := strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name)); c != 0 {
			return c
		}
		return strings.Compare(a.Path, b.Path)
	})
	return found
}
