package apps

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// versionName — папка или файл, названные версией: 2.1.301, v20.1.0,
// 2.60.0_1 (ревизия формулы Homebrew).
var versionName = regexp.MustCompile(`^v?[0-9]+(\.[0-9]+)*([._+-][0-9A-Za-z][0-9A-Za-z._+-]*)?$`)

// binDirs — папки, в которых лежат программы, а не сама программа.
var binDirs = map[string]bool{"bin": true, "sbin": true, "libexec": true, ".bin": true}

// sharedDirs — общие папки macOS и Linux: в них лежат разные программы, и
// защищать такую папку целиком нельзя.
var sharedDirs = map[string]bool{
	"/": true, "/opt": true, "/usr/local": true, "/usr/local/lib": true, "/usr/local/opt": true,
	"/usr/local/Cellar": true, "/usr/local/Caskroom": true, "/opt/homebrew": true, "/opt/homebrew/lib": true,
	"/opt/homebrew/opt": true, "/opt/homebrew/Cellar": true, "/opt/homebrew/Caskroom": true, "/opt/local": true,
	"/Applications": true, "/Library": true, "/Users": true, "/tmp": true, "/private/tmp": true, "/var": true, "/private/var": true,
	"/home": true, "/root": true, "/srv": true, "/snap": true, "/var/lib": true, "/var/opt": true,
}

// homeShared — стандартные папки внутри домашней, после /Users/<имя>/ или
// /home/<имя>/. Сама домашняя и все папки прямо в ней (~/bin, ~/go, ~/Downloads)
// — общие тоже.
var homeShared = []string{"Library/Application Support", "Library/Caches", ".local/share", ".local/lib", ".local/state", ".config", ".cache"}

// readCommand читает консольную программу: исполняемый файл или ссылку на
// него (~/.local/bin/claude). Имя — как её вызывают, по пути до ссылок; что
// защищается — по настоящему пути (CommandTarget).
func readCommand(path string) (App, error) {
	real, err := filepath.EvalSymlinks(path)
	if errors.Is(err, fs.ErrNotExist) {
		return App{}, fmt.Errorf("программы %s нет", path)
	}
	if err != nil {
		return App{}, err
	}
	fi, err := os.Stat(real)
	if err != nil {
		return App{}, err
	}
	if !fi.Mode().IsRegular() || fi.Mode().Perm()&0o111 == 0 {
		return App{}, fmt.Errorf("%s — не программа: нужен исполняемый файл", path)
	}
	target, _ := CommandTarget(real)
	return App{ID: CommandPrefix + target, Name: filepath.Base(path), Path: target, Command: true}, nil
}

// CommandTarget — что защищать у консольной программы. real — путь к
// её файлу без символических ссылок (~/.local/bin/claude ведёт в
// ~/.local/share/claude/versions/2.1.301). Защищается папка установки — там же
// будущие версии и вспомогательные программы:
//   - у пакета node — папка пакета в node_modules (…/node_modules/@openai/codex);
//   - у файла в папке версии (Homebrew: Cellar/gh/2.60.0/bin/gh) — папка над версией;
//   - иначе — папка файла (у Claude Code — versions/, куда ложатся новые версии).
//
// Если такая папка общая (bin, системные, домашняя и её стандартные папки),
// защищается только сам файл: dir=false.
func CommandTarget(real string) (target string, dir bool) {
	if pkg, ok := nodePackage(real); ok {
		return pkg, true
	}
	d := path.Dir(real)
	switch {
	case binDirs[path.Base(d)] && versionName.MatchString(path.Base(path.Dir(d))):
		d = path.Dir(path.Dir(d))
	case versionName.MatchString(path.Base(d)):
		d = path.Dir(d)
	}
	if sharedDir(d) {
		return real, false
	}
	return d, true
}

// nodePackage — папка пакета node, внутри которой лежит real:
// …/node_modules/<пакет> или …/node_modules/@<область>/<пакет>.
func nodePackage(real string) (string, bool) {
	const nm = "/node_modules/"
	i := strings.Index(real, nm)
	if i < 0 {
		return "", false
	}
	parts := strings.Split(real[i+len(nm):], "/")
	n := 1
	if strings.HasPrefix(parts[0], "@") {
		n = 2
	}
	if len(parts) <= n || parts[0] == ".bin" || slices.Contains(parts[:n], "") {
		return "", false
	}
	return real[:i+len(nm)] + strings.Join(parts[:n], "/"), true
}

// sharedDir — в папке d лежат разные программы.
func sharedDir(d string) bool {
	switch {
	case sharedDirs[d], binDirs[path.Base(d)], path.Base(d) == "node_modules":
		return true
	case d == "/System" || strings.HasPrefix(d, "/System/"):
		return true
	case (d == "/usr" || strings.HasPrefix(d, "/usr/")) && !strings.HasPrefix(d, "/usr/local/"):
		return true
	}
	for _, homes := range []string{"/Users/", "/home/"} {
		if rest, ok := strings.CutPrefix(d, homes); ok {
			_, inHome, _ := strings.Cut(rest, "/")
			return !strings.Contains(inHome, "/") || slices.Contains(homeShared, inHome)
		}
	}
	if rest, ok := strings.CutPrefix(d, "/root/"); ok {
		return !strings.Contains(rest, "/") || slices.Contains(homeShared, rest)
	}
	return false
}
