package procs

import (
	"bytes"
	"encoding/binary"
	"path"
	"regexp"
	"strings"
)

// interpreter — программы, которые исполняют скрипт: у консольной программы
// на node или python процесс — интерпретатор, а сама программа — путь в его
// аргументах (node /opt/homebrew/bin/codex).
var interpreter = regexp.MustCompile(`^(node|bun|deno|ruby|perl|php|sh|bash|zsh|dash|python[0-9.]*)$`)

// Interpreter — исполняемый файл exe исполняет скрипты.
func Interpreter(exe string) bool { return interpreter.MatchString(path.Base(exe)) }

// MatchCommand — процесс относится к консольной программе, у которой
// защищается target (папка установки или сам файл): его исполняемый файл
// лежит там, или он интерпретатор, первый аргумент-путь которого лежит там.
// exe и argv — от ядра; resolve снимает символические ссылки и отвечает
// false, если файла нет: программу запускают по ссылке (~/.local/bin/claude),
// а защищается её настоящая папка. Аргументы процесс задаёт себе сам, поэтому
// путь в них засчитывается, только если такой файл есть.
func MatchCommand(target, exe string, argv []string, resolve func(string) (string, bool)) bool {
	in := func(p string) bool { return p == target || strings.HasPrefix(p, target+"/") }
	at := func(p string) bool {
		real, ok := resolve(p)
		return strings.HasPrefix(p, "/") && ok && (in(p) || in(real))
	}
	if at(exe) {
		return true
	}
	if real, _ := resolve(exe); !Interpreter(exe) && !Interpreter(real) {
		return false
	}
	for _, a := range argv[min(1, len(argv)):] {
		if !strings.HasPrefix(a, "-") {
			return at(a)
		}
	}
	return false
}

// ParseProcArgs разбирает ответ sysctl kern.procargs2: число аргументов
// (int32 в порядке байтов машины), путь, по которому запущен исполняемый
// файл, нули выравнивания и аргументы, каждый с нулём в конце. Дальше идёт
// окружение — оно не нужно.
func ParseProcArgs(buf []byte) (exe string, argv []string, ok bool) {
	if len(buf) < 4 {
		return "", nil, false
	}
	argc := int(binary.NativeEndian.Uint32(buf))
	rest := buf[4:]
	i := bytes.IndexByte(rest, 0)
	if i <= 0 {
		return "", nil, false
	}
	exe, rest = string(rest[:i]), bytes.TrimLeft(rest[i:], "\x00")
	for len(argv) < argc && len(rest) > 0 {
		arg, after, _ := bytes.Cut(rest, []byte{0})
		argv = append(argv, string(arg))
		rest = after
	}
	return exe, argv, true
}
