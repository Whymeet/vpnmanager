package apps

import (
	"bufio"
	"bytes"
	"regexp"
	"strings"
)

// Desktop — запись .desktop: что видно в меню приложений Linux.
type Desktop struct {
	Name string
	Exec string // программа: первое слово Exec= без окружения и кавычек
}

// ParseDesktop разбирает файл .desktop. Записи, которых нет в меню (NoDisplay,
// Hidden), не приложения (Type≠Application) и без Exec=, отбрасываются. Имя —
// переведённое на русский, если оно есть.
func ParseDesktop(data []byte) (Desktop, bool) {
	vals := map[string]string{}
	inEntry := false
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "[") {
			inEntry = line == "[Desktop Entry]"
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok && inEntry {
			if _, seen := vals[k]; !seen {
				vals[strings.TrimSpace(k)] = strings.TrimSpace(v)
			}
		}
	}
	if vals["NoDisplay"] == "true" || vals["Hidden"] == "true" || (vals["Type"] != "" && vals["Type"] != "Application") {
		return Desktop{}, false
	}
	name := vals["Name[ru]"]
	if name == "" {
		name = vals["Name"]
	}
	prog := execProgram(vals["Exec"])
	if name == "" || prog == "" {
		return Desktop{}, false
	}
	return Desktop{Name: name, Exec: prog}, true
}

// assignment — приставка ПЕРЕМЕННАЯ=значение; значение бывает и путём.
var assignment = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)

// execProgram — программа из строки Exec=: без кавычек и без приставки
// env ПЕРЕМЕННАЯ=значение.
func execProgram(line string) string {
	fields := splitExec(line)
	for len(fields) > 0 {
		f := fields[0]
		if f == "env" || strings.HasSuffix(f, "/env") || assignment.MatchString(f) {
			fields = fields[1:]
			continue
		}
		return f
	}
	return ""
}

// splitExec режет строку Exec= по пробелам с учётом двойных кавычек.
func splitExec(line string) []string {
	var out []string
	var cur strings.Builder
	quoted, have := false, false
	for _, r := range line {
		switch {
		case r == '"':
			quoted, have = !quoted, true
		case r == ' ' && !quoted:
			if have {
				out = append(out, cur.String())
				cur.Reset()
				have = false
			}
		default:
			cur.WriteRune(r)
			have = true
		}
	}
	if have {
		out = append(out, cur.String())
	}
	return out
}

// ExecPaths разбирает ответ `systemctl show -p ExecStart`: у каждой команды
// службы поле «path=<файл>».
func ExecPaths(show string) []string {
	var out []string
	for f := range strings.FieldsSeq(show) {
		if p, ok := strings.CutPrefix(f, "path="); ok && p != "" {
			out = append(out, p)
		}
	}
	return out
}

// UnitNames разбирает `systemctl list-unit-files --type=service`: службы, которые
// включены. Шаблоны (foo@.service) не службы: у них нет процессов.
func UnitNames(list string) []string {
	var out []string
	for line := range strings.Lines(list) {
		f := strings.Fields(line)
		if len(f) >= 2 && f[1] == "enabled" && strings.HasSuffix(f[0], ".service") && !strings.HasSuffix(f[0], "@.service") {
			out = append(out, f[0])
		}
	}
	return out
}
