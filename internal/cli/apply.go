package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"vpnlock/internal/core"
	"vpnlock/internal/ipc"
)

// apply — `vpnlock apply [файл]`: применить конфиг. Без файла — конфиг своей
// системы из клона: configs/macos.conf, configs/linux.conf или
// configs/windows.conf. Файл сначала проверяется целиком, потом применяется по
// строке; первая неудача останавливает команду. Конфиг только добавляет:
// выход, программу или домен, которых в нём нет, команда не трогает. Запускать
// можно сколько угодно раз: что уже настроено, остаётся как есть.
func apply(env Env, args []string) int {
	if len(args) > 1 {
		fmt.Fprintln(env.Err, "Укажи один конфиг: vpnlock apply [файл] — без файла берётся конфиг этой системы из клона.")
		return 2
	}
	switch {
	case runtime.GOOS == "windows" && !env.Root:
		fmt.Fprintln(env.Err, "Применить конфиг можно только из PowerShell, открытого от имени администратора: в меню «Пуск» найди «PowerShell», правой кнопкой — «Запуск от имени администратора», и повтори там vpnlock apply. Ничего не изменено.")
		return 1
	case runtime.GOOS != "windows" && env.Root:
		// Под sudo PATH и домашняя папка — root: консольные программы
		// человека не нашлись бы и молча пропустились.
		fmt.Fprintln(env.Err, "Запусти без sudo, от своей учётной записи: vpnlock apply. Прав администратора для этого хватает. Ничего не изменено.")
		return 1
	}
	file, ok := configFile(env, args)
	if !ok {
		return 1
	}
	data, err := os.ReadFile(file)
	if err != nil {
		fmt.Fprintf(env.Err, "Конфиг не читается: %v. Ничего не изменено.\n", err)
		return 1
	}
	if len(data) > 1<<20 {
		fmt.Fprintf(env.Err, "%s больше 1 МБ — это не конфиг vpnlock. Ничего не изменено.\n", file)
		return 1
	}
	lines, err := parseConfig(data)
	if err != nil {
		fmt.Fprintf(env.Err, "%s, %v. Ничего не изменено.\n", file, err)
		return 1
	}
	if _, ok := currentStatus(env); !ok {
		return 1
	}

	fmt.Fprintf(env.Out, "Применяю конфиг %s\n", file)
	dir := filepath.Dir(file)
	skipped := 0
	for _, l := range lines {
		code, skip := applyLine(env, dir, l)
		if skip {
			skipped++
			continue
		}
		if code != 0 {
			fmt.Fprintf(env.Err, "✗ Строка %d не применена — причина выше, дальше конфиг не применялся. Исправь и запусти ещё раз: что уже применено, останется как есть.\n", l.n)
			return 1
		}
	}

	fmt.Fprintln(env.Out)
	var out bytes.Buffer
	status(captured(env, &out))
	printIndented(env, out.String(), "  ")
	fmt.Fprintln(env.Out)
	if skipped > 0 {
		fmt.Fprintf(env.Out, "✓ Готово. Пропущено: %d %s — на этом компьютере их нет; поставишь — запусти vpnlock apply ещё раз.\n",
			skipped, core.Plural(skipped, "программа", "программы", "программ"))
	} else {
		fmt.Fprintln(env.Out, "✓ Готово: конфиг применён.")
	}
	if st, ok := statusQuiet(env); ok {
		nextSteps(env, st)
	}
	return 0
}

// nextSteps подсказывает, что осталось после общего конфига: свои выходы VPN
// и правило «только мои выходы». Их в общий конфиг не пишут — у каждого свои.
func nextSteps(env Env, st *ipc.Status) {
	switch {
	case len(st.Exits) == 0:
		fmt.Fprintln(env.Out, `
Дальше — твои выходы VPN, чтобы сервисы открывались только через них:
  vpnlock remember <имя>            подключи VPN и запомни его выход; повтори для каждого VPN
  vpnlock remember <имя> <адрес>    или по адресу выхода, без подключения (адрес, который видят сайты)`)
		if st.Rule != core.RuleMine {
			fmt.Fprintln(env.Out, "  vpnlock rule mine                 затем правило «только мои выходы»")
		}
	case st.Rule != core.RuleMine:
		fmt.Fprintln(env.Out, "\nЧтобы сервисы открывались только через твои выходы: vpnlock rule mine")
	}
}

// configFile — какой конфиг применять: указанный файл или конфиг этой системы
// в клоне (текущая папка или клон, из которого ставили).
func configFile(env Env, args []string) (string, bool) {
	if len(args) == 1 {
		file := expandPath(env, args[0])
		if abs, err := filepath.Abs(file); err == nil {
			file = abs
		}
		return file, true
	}
	clone, ok := findClone(env, nil)
	if !ok {
		fmt.Fprintln(env.Err, "Не нашёл клон vpnlock: запусти команду из папки клона или укажи конфиг — vpnlock apply <файл>. Ничего не изменено.")
		return "", false
	}
	file := filepath.Join(clone, "configs", configName(runtime.GOOS))
	if _, err := os.Stat(file); err != nil {
		fmt.Fprintf(env.Err, "В клоне нет конфига для этой системы: %s. Ничего не изменено.\n", file)
		return "", false
	}
	return file, true
}

// configName — конфиг системы goos в папке configs клона. Систему знает сама
// сборка: собранная под другую систему программа здесь не запустилась бы.
func configName(goos string) string {
	switch goos {
	case "darwin":
		return "macos.conf"
	case "windows":
		return "windows.conf"
	}
	return goos + ".conf"
}

// confLine — команда конфига. У app и import один аргумент — остаток строки:
// в пути бывают пробелы.
type confLine struct {
	n    int // номер строки в файле
	key  string
	args []string
}

// parseConfig разбирает конфиг целиком, до каких-либо изменений: ошибка в
// любой строке — отказ, чтобы не применить половину. По команде в строке, # —
// комментарий до конца строки.
func parseConfig(data []byte) ([]confLine, error) {
	text := strings.TrimPrefix(string(data), "\uFEFF") // Блокнот Windows пишет BOM
	var lines []confLine
	for i, raw := range strings.Split(text, "\n") {
		line, _, _ := strings.Cut(raw, "#")
		line = strings.TrimSpace(line)
		words := strings.Fields(line)
		if len(words) == 0 {
			continue
		}
		key, args := strings.ToLower(words[0]), words[1:]
		rest := strings.TrimSpace(line[len(words[0]):])
		problem := ""
		switch key {
		case "exit":
			if len(args) < 2 {
				problem = "нужно имя и адрес выхода: exit Германия 203.0.113.5"
			} else if _, err := netip.ParseAddr(args[len(args)-1]); err != nil {
				problem = fmt.Sprintf("«%s» — не адрес: exit Германия 203.0.113.5", args[len(args)-1])
			}
		case "rule":
			if len(args) != 1 || (!strings.EqualFold(args[0], "mine") && !strings.EqualFold(args[0], "any")) {
				problem = "нужно rule mine или rule any"
			}
		case "app", "import":
			args = []string{strings.Trim(rest, `"'`)}
			if args[0] == "" && key == "app" {
				problem = "нужно имя или путь: app claude"
			} else if args[0] == "" {
				problem = "нужен файл: import domains.txt"
			}
		case "protect":
			if len(args) == 0 {
				problem = "нужен домен или адрес: protect claude.ai"
			}
		case "notifications":
			if len(args) != 1 || (!strings.EqualFold(args[0], "on") && !strings.EqualFold(args[0], "off")) {
				problem = "нужно notifications on или notifications off"
			}
		default:
			problem = fmt.Sprintf("нет команды «%s»: есть app, protect, import, notifications, exit, rule", words[0])
		}
		if problem != "" {
			return nil, fmt.Errorf("строка %d: %s", i+1, problem)
		}
		lines = append(lines, confLine{n: i + 1, key: key, args: args})
	}
	if len(lines) == 0 {
		return nil, errors.New("в нём нет ни одной команды")
	}
	return lines, nil
}

// applyLine выполняет строку конфига той же командой vpnlock, что набрал бы
// человек, и показывает её вывод с отступом. skipped — программы на этом
// компьютере нет.
func applyLine(env Env, dir string, l confLine) (code int, skipped bool) {
	var cmd []string
	switch l.key {
	case "app":
		return applyApp(env, dir, l.args[0])
	case "exit":
		cmd = append([]string{"remember"}, l.args...)
	case "import":
		cmd = []string{"import", inDir(dir, expandPath(env, l.args[0]))}
	default:
		cmd = append([]string{l.key}, l.args...)
	}
	fmt.Fprintf(env.Out, "  · vpnlock %s\n", shellJoin(cmd))
	var out bytes.Buffer
	code = Run(cmd, captured(env, &out))
	printIndented(env, out.String(), "      ")
	return code, false
}

// applyApp — строка app: программы, которой на этом компьютере нет, конфиг
// пропускает, а уже защищённую считает сделанной.
func applyApp(env Env, dir, arg string) (code int, skipped bool) {
	target := expandPath(env, arg)
	if looksLikePath(target) {
		target = inDir(dir, target)
		if _, err := os.Stat(target); errors.Is(err, fs.ErrNotExist) {
			fmt.Fprintf(env.Out, "  ! %s — нет на этом компьютере, пропускаю\n", arg)
			return 0, true
		}
	}
	var out bytes.Buffer
	sub := captured(env, &out)
	path, name, missing, ok := resolveApp(sub, target)
	if missing {
		fmt.Fprintf(env.Out, "  ! %s — нет на этом компьютере, пропускаю\n", arg)
		return 0, true
	}
	fmt.Fprintf(env.Out, "  · vpnlock add %s\n", shellJoin([]string{target}))
	if !ok {
		printIndented(env, out.String(), "      ")
		return 1, false
	}
	resp, err := ipc.Call(env.Layout.Socket, ipc.Request{Cmd: ipc.CmdAddApp, Path: path, Name: name})
	switch {
	case err != nil:
		code = silent(sub, err)
	case !resp.OK && resp.App != nil:
		fmt.Fprintf(sub.Out, "уже в списке — %s\n", appWord(resp.App.Learned))
	case !resp.OK:
		fmt.Fprintln(sub.Out, resp.Error)
		code = 1
	default:
		printAdded(sub, *resp.App)
	}
	printIndented(env, out.String(), "      ")
	return code, false
}

// captured — то же окружение, но вывод команды собирается в w, а спрашивать
// некого: конфиг применяется без вопросов.
func captured(env Env, w *bytes.Buffer) Env {
	env.In = strings.NewReader("")
	env.Out, env.Err = w, w
	env.Interactive = false
	env.Raw = nil
	return env
}

func printIndented(env Env, text, prefix string) {
	for _, line := range strings.Split(strings.TrimRight(text, "\n"), "\n") {
		if line == "" {
			fmt.Fprintln(env.Out)
			continue
		}
		fmt.Fprintln(env.Out, prefix+line)
	}
}

// shellJoin — команда для показа: аргумент с пробелом — в кавычках.
func shellJoin(args []string) string {
	out := make([]string, len(args))
	for i, a := range args {
		if strings.ContainsAny(a, " \t") {
			a = `"` + a + `"`
		}
		out[i] = a
	}
	return strings.Join(out, " ")
}

// inDir — путь из конфига: относительный считается от папки конфига.
func inDir(dir, p string) string {
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(dir, p)
}

// expandPath раскрывает в пути из конфига домашнюю папку: ~ — на всех
// системах, %USERPROFILE% и другие переменные окружения — на Windows. Один
// конфиг так подходит любому человеку.
func expandPath(env Env, p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") || strings.HasPrefix(p, `~\`) {
		home := env.Home
		if home == "" {
			home, _ = os.UserHomeDir()
		}
		if home != "" {
			p = filepath.Join(home, p[1:])
		}
	}
	if runtime.GOOS == "windows" {
		p = expandPercent(p, os.LookupEnv)
	}
	return p
}

var percentVar = regexp.MustCompile(`%([^%\\/]+)%`)

// expandPercent подставляет переменные окружения в записи Windows (%ИМЯ%).
// Неизвестная остаётся как есть: такого пути нет, и строку пропустят.
func expandPercent(p string, lookup func(string) (string, bool)) string {
	return percentVar.ReplaceAllStringFunc(p, func(m string) string {
		if v, ok := lookup(m[1 : len(m)-1]); ok {
			return v
		}
		return m
	})
}
