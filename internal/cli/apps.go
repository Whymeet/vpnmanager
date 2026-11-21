package cli

import (
	"bufio"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"appguard/internal/apps"
	"appguard/internal/core"
	"appguard/internal/ipc"
	"appguard/internal/tui"
)

// addApp — «Добавить приложение». Без аргумента в терминале — выбор из
// установленных; с аргументом — по имени («Notion»), по пути к пакету или,
// на macOS и Linux, консольная программа по имени команды (claude) или пути. На
// Linux — ещё и служба systemd (nginx, nginx.service).
func addApp(env Env, args []string) int {
	if len(args) > 1 {
		fmt.Fprintln(env.Err, "Укажи одно приложение: appguard add Notion")
		return 2
	}
	st, ok := currentStatus(env)
	if !ok {
		return 1
	}
	var path, name string
	switch {
	case len(args) == 1:
		var ok bool
		if path, name, _, ok = resolveApp(env, args[0]); !ok {
			return 1
		}
	default:
		if !env.Interactive {
			fmt.Fprintln(env.Err, "Укажи приложение: appguard add Notion — или запусти команду в терминале и выбери из списка.")
			return 2
		}
		a, ok := chooseInstalled(env, st.Apps)
		if !ok {
			return 1
		}
		path, name = a.Path, a.Name
	}
	resp, err := ipc.Call(env.Layout.Socket, ipc.Request{Cmd: ipc.CmdAddApp, Path: path, Name: name})
	if err != nil {
		return silent(env, err)
	}
	if !resp.OK {
		fmt.Fprintln(env.Err, resp.Error)
		return 1
	}
	printAdded(env, *resp.App)
	return 0
}

// printAdded — что стало с только что добавленным приложением.
func printAdded(env Env, a ipc.AppStatus) {
	switch {
	case a.Catalog:
		fmt.Fprintf(env.Out, "%s защищено по каталогу: без проверенного VPN его сервисы закрыты.\n", a.Name)
	case a.Learned:
		fmt.Fprintf(env.Out, "%s защищено: в сеть оно выходит только через проверенный VPN.\n", a.Name)
	case a.Command:
		fmt.Fprintf(env.Out, "%s добавлено и ждёт обучения. Включи VPN и поработай в программе пару минут: служба запомнит, куда она ходит, и статус сменится на «защищено». Адреса учатся только в эти минуты — не открывай через неё посторонние сайты.\n", a.Name)
	default:
		fmt.Fprintf(env.Out, "%s добавлено и ждёт обучения. Включи VPN и поработай в приложении пару минут: служба запомнит, куда оно ходит, и статус сменится на «защищено».\n", a.Name)
	}
}

// resolveApp находит, что защищать по аргументу add: путь к пакету или exe,
// консольную программу по имени (macOS, Linux), службу systemd (Linux) или
// приложение по имени. name — имя для людей, если оно известно. Не нашлось —
// ok ложно, причина уже в env.Err; missing — такого на компьютере нет вовсе
// (конфиг такую строку пропускает).
func resolveApp(env Env, arg string) (path, name string, missing, ok bool) {
	if looksLikePath(arg) {
		if abs, err := filepath.Abs(arg); err == nil {
			arg = abs
		}
		return arg, "", false, true
	}
	found, command := findInstalled(env, arg), findCommand(arg)
	service, ok := pickService(env, arg, command)
	if !ok {
		return "", "", false, false
	}
	// Claude — приложение, claude — команда: у приложений имя как в Finder,
	// у команд — как их набирают. Путь нужен, только если совпало и то и другое.
	if command != "" && !slices.ContainsFunc(found, func(a apps.App) bool { return a.Name == arg }) {
		found = nil
	}
	switch {
	case service != "":
		return service, "", false, true
	case len(found) > 0 && command != "":
		fmt.Fprintf(env.Err, "Под «%s» подходит и приложение, и консольная программа — укажи путь:\n  appguard add %q   — приложение\n  appguard add %q   — консольная программа\n", arg, found[0].Path, command)
		return "", "", false, false
	case command != "":
		return command, "", false, true
	case len(found) == 0:
		also := ""
		switch runtime.GOOS {
		case "darwin":
			also = ", и консольной программы с таким именем тоже"
		case "linux":
			also = ", и консольной программы со службой с таким именем тоже"
		}
		fmt.Fprintf(env.Err, "Приложения «%s» нет %s%s. Список установленных — appguard add (без имени), в терминале.\n", arg, installedWhere(), also)
		return "", "", true, false
	case len(found) > 1:
		fmt.Fprintf(env.Err, "Под «%s» подходит несколько приложений — укажи путь:\n", arg)
		for _, a := range found {
			fmt.Fprintf(env.Err, "  %s\n", a.Path)
		}
		return "", "", false, false
	}
	return found[0].Path, found[0].Name, false, true
}

// installedWhere — где лежат установленные приложения, для сообщений.
func installedWhere() string {
	switch runtime.GOOS {
	case "windows":
		return "в меню «Пуск» и среди приложений Store"
	case "linux":
		return "в меню приложений и среди служб"
	}
	return "в папках «Программы»"
}

// pickService решает, служба ли name. Имя службы и команды часто совпадают: если
// это одна программа, защищается сама программа — так закрыта и служба, и запуск
// руками; service пуст. Если разные (ssh и sshd) — угадывать нельзя, нужно
// уточнение: ok ложно.
func pickService(env Env, name, command string) (service string, ok bool) {
	if env.FindService == nil {
		return "", true
	}
	service = env.FindService(name)
	switch {
	case service == "" || command == "" || strings.HasSuffix(name, ".service"):
		return service, true
	case env.SameProgram(service, command):
		return "", true
	}
	fmt.Fprintf(env.Err, "Под «%s» подходит и служба, и консольная программа — укажи какую:\n  appguard add %s.service   — служба\n  appguard add %s   — консольная программа\n", name, name, command)
	return "", false
}

func looksLikePath(s string) bool {
	return strings.ContainsAny(s, `/\`) || strings.HasSuffix(s, ".app") || strings.HasSuffix(strings.ToLower(s), ".exe")
}

// findCommand — консольная программа с ровно таким именем в PATH (на macOS и
// Linux): её можно защитить, как приложение. Нет — пусто. Регистр сверяется по
// папке: файловая система мака его не различает, и LookPath("Claude") нашёл бы claude.
func findCommand(name string) string {
	if runtime.GOOS == "windows" {
		return ""
	}
	path, err := exec.LookPath(name)
	if err != nil && runtime.GOOS == "linux" {
		path, err = exec.LookPath("/snap/bin/" + name) // /snap/bin есть в PATH не у всех
	}
	if err != nil {
		return ""
	}
	path, err = filepath.Abs(path)
	if err != nil {
		return ""
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil || !slices.ContainsFunc(entries, func(e os.DirEntry) bool { return e.Name() == name }) {
		return ""
	}
	return path
}

// findInstalled — установленные приложения с таким именем (без учёта регистра).
func findInstalled(env Env, name string) []apps.App {
	var out []apps.App
	for _, a := range env.Installed() {
		if strings.EqualFold(a.Name, name) {
			out = append(out, a)
		}
	}
	return out
}

// chooseInstalled показывает установленные приложения, которых ещё нет в списке.
func chooseInstalled(env Env, added []ipc.AppStatus) (apps.App, bool) {
	var list []apps.App
	for _, a := range env.Installed() {
		if !slices.ContainsFunc(added, func(s ipc.AppStatus) bool { return s.ID == a.ID }) {
			list = append(list, a)
		}
	}
	if len(list) == 0 {
		fmt.Fprintf(env.Out, "Все приложения %s уже в списке.\n", installedWhere())
		return apps.App{}, false
	}
	items := make([]string, len(list))
	for i, a := range list {
		items[i] = a.Name
	}
	i, ok := choose(env, items, tui.Options{Title: "Какое приложение защитить?", Filter: true})
	if !ok {
		return apps.App{}, false
	}
	return list[i], true
}

// removeApp — «Убрать приложение»: только после предупреждения и согласия.
// Паузы нет: защиту можно только снять.
func removeApp(env Env, args []string) int {
	yes, rest := takeYes(args)
	if len(rest) > 1 {
		fmt.Fprintln(env.Err, "Укажи одно приложение: appguard remove Notion")
		return 2
	}
	st, ok := currentStatus(env)
	if !ok {
		return 1
	}
	if len(st.Apps) == 0 {
		fmt.Fprintln(env.Out, "В списке защищённых приложений пусто — убирать нечего.")
		return 0
	}
	var target ipc.AppStatus
	switch {
	case len(rest) == 1:
		a, ok := findApp(st.Apps, rest[0])
		if !ok {
			fmt.Fprintf(env.Err, "«%s» нет в списке защищённых приложений.\n", rest[0])
			return 1
		}
		target = a
	case env.Interactive:
		items := make([]string, len(st.Apps))
		for i, a := range st.Apps {
			items[i] = a.Name + " — " + appWord(a.Learned)
		}
		i, ok := choose(env, items, tui.Options{Title: "С какого приложения снять защиту?"})
		if !ok {
			return 1
		}
		target = st.Apps[i]
	default:
		fmt.Fprintln(env.Err, "Укажи приложение: appguard remove Notion")
		return 2
	}

	if !yes {
		if !env.Interactive {
			fmt.Fprintln(env.Err, "Снятие защиты нужно подтвердить: запусти команду в терминале или добавь --yes. Ничего не изменено.")
			return 1
		}
		fmt.Fprintf(env.Out, "Без VPN %s начнёт выходить в сеть с домашнего адреса, и сервис его увидит.\nСнять защиту? Напиши «да»: ", target.Name)
		if !confirmed(env.In) {
			fmt.Fprintln(env.Out, "Отменено — защита осталась.")
			return 1
		}
	}
	resp, err := ipc.Call(env.Layout.Socket, ipc.Request{Cmd: ipc.CmdRemoveApp, AppID: target.ID})
	if err != nil {
		return silent(env, err)
	}
	if !resp.OK {
		fmt.Fprintln(env.Err, resp.Error)
		return 1
	}
	fmt.Fprintf(env.Out, "С %s защита снята.\n", target.Name)
	return 0
}

// takeYes отделяет --yes/-y от остальных аргументов.
func takeYes(args []string) (bool, []string) {
	yes := false
	var rest []string
	for _, a := range args {
		if a == "--yes" || a == "-y" {
			yes = true
			continue
		}
		rest = append(rest, a)
	}
	return yes, rest
}

// rule — «Правило»: одно на все защищённые приложения. Без аргумента в
// терминале — выбор из двух; «мои» или «любой» — сразу.
func rule(env Env, args []string) int {
	st, ok := currentStatus(env)
	if !ok {
		return 1
	}
	var want string
	switch {
	case len(args) == 1:
		switch strings.ToLower(args[0]) {
		case "mine":
			want = core.RuleMine
		case "any":
			want = core.RuleAny
		default:
			fmt.Fprintf(env.Err, "Нет правила «%s»: appguard rule any — любой выход не из России, appguard rule mine — только мои выходы.\n", args[0])
			return 2
		}
	case len(args) > 1:
		fmt.Fprintln(env.Err, "Укажи одно правило: any или mine.")
		return 2
	case env.Interactive:
		rules := []string{core.RuleAny, core.RuleMine}
		items := make([]string, len(rules))
		for i, r := range rules {
			items[i] = ruleText(r)
			if r == st.Rule {
				items[i] += " — сейчас"
			}
		}
		i, ok := choose(env, items, tui.Options{Title: "Правило — одно на все защищённые приложения:"})
		if !ok {
			return 1
		}
		want = rules[i]
	default:
		printRule(env, st)
		return 0
	}
	if want != st.Rule {
		resp, err := ipc.Call(env.Layout.Socket, ipc.Request{Cmd: ipc.CmdRule, Rule: want})
		if err != nil {
			return silent(env, err)
		}
		if !resp.OK {
			fmt.Fprintln(env.Err, resp.Error)
			return 1
		}
		st.Rule = want
	}
	printRule(env, st)
	if want == core.RuleMine && len(st.Exits) == 0 {
		fmt.Fprintln(env.Out, "В списке пока нет ни одного выхода, поэтому защищённые сервисы закрыты. Подключи свой VPN и выбери «Запомнить текущий выход».")
	}
	return 0
}

func printRule(env Env, st *ipc.Status) {
	switch st.Rule {
	case core.RuleMine:
		fmt.Fprintln(env.Out, "Правило: только мои выходы — сервисы открыты, только когда выход VPN из твоего списка.")
	default:
		fmt.Fprintln(env.Out, "Правило: любой выход не из России — сервисы открыты, пока выход VPN проверен и он не в России.")
	}
	printExits(env, st.Exits)
}

func printExits(env Env, exits []ipc.ExitStatus) {
	if len(exits) == 0 {
		return
	}
	parts := make([]string, len(exits))
	for i, x := range exits {
		parts[i] = exitText(x)
	}
	fmt.Fprintf(env.Out, "Мои выходы: %s\n", strings.Join(parts, "; "))
}

func exitText(x ipc.ExitStatus) string {
	if x.Unverified {
		return fmt.Sprintf("%s — введён вручную, ещё не проверен (%s)", x.Name, x.IP)
	}
	return fmt.Sprintf("%s — %s (%s)", x.Name, core.CountryName(x.Country), x.IP)
}

// remember — «Запомнить текущий выход»: показывает адрес и страну выхода сейчас
// и сохраняет его под именем. Адрес последним аргументом (appguard remember
// Сингапур 203.0.113.5) — выход без подключения: страну служба узнает, когда
// выйдет через него. Нужен адрес выхода, а не сервера: у цепочек, где сервер
// в России, а выход за границей, они разные.
func remember(env Env, args []string) int {
	ip := ""
	if n := len(args); n > 0 {
		if a, err := netip.ParseAddr(args[n-1]); err == nil {
			ip, args = a.Unmap().String(), args[:n-1]
		}
	}
	st, ok := currentStatus(env)
	if !ok {
		return 1
	}
	if ip == "" {
		now, ok := currentExit(st)
		if !ok {
			fmt.Fprintln(env.Err, "Сейчас нет проверенного выхода — включи VPN и дождись в статусе строки «проверен». Или запомни выход по адресу, без подключения: appguard remember Сингапур 203.0.113.5")
			return 1
		}
		fmt.Fprintf(env.Out, "Сейчас выход %s, %s.\n", now.IP, core.CountryName(now.Country))
	}
	name := strings.TrimSpace(strings.Join(args, " "))
	if name == "" {
		if !env.Interactive {
			fmt.Fprintln(env.Err, "Укажи имя выхода: appguard remember Server 1 — текущий выход, appguard remember Сингапур 203.0.113.5 — выход по адресу, без подключения")
			return 2
		}
		fmt.Fprint(env.Out, "Как назвать этот выход (например, Server 1)? ")
		line, _ := bufio.NewReader(env.In).ReadString('\n') // тот же буфер, что завёл Run
		if name = strings.TrimSpace(line); name == "" {
			fmt.Fprintln(env.Out, "Имя не введено — ничего не запомнено.")
			return 1
		}
	}
	resp, err := ipc.Call(env.Layout.Socket, ipc.Request{Cmd: ipc.CmdRemember, Name: name, IP: ip})
	if err != nil {
		return silent(env, err)
	}
	if !resp.OK {
		fmt.Fprintln(env.Err, resp.Error)
		return 1
	}
	if ip != "" && resp.Exit.IP != ip {
		fmt.Fprintf(env.Err, "Служба старой версии запомнила под этим именем текущий выход (%s), а не %s. Обнови appguard — установкой из клона, она поставит новую версию поверх.\n", resp.Exit.IP, ip)
		return 1
	}
	fmt.Fprintf(env.Out, "Запомнено: %s.\n", exitText(*resp.Exit))
	if resp.Exit.Unverified {
		fmt.Fprintln(env.Out, `Страну служба узнает, когда ты подключишься через этот VPN. Нужен адрес выхода — тот, что видят
сайты, — а не адрес сервера из настроек VPN: у цепочек и серверов за CDN они разные. Если не
совпадёт, при правиле «только мои выходы» сервисы через этот VPN останутся закрыты, а статус
покажет настоящий адрес выхода.`)
	}
	if st.Rule != core.RuleMine {
		fmt.Fprintln(env.Out, "Чтобы сервисы открывались только через твои выходы, выбери правило «только мои выходы»: appguard rule mine")
	}
	return 0
}

// currentExit — проверенный выход маршрута по умолчанию, а если маршрут идёт
// мимо туннелей — единственный проверенный. Российский служба не сохранит и
// сама объяснит почему, поэтому он тоже «текущий».
func currentExit(st *ipc.Status) (ipc.ExitStatus, bool) {
	var found []ipc.PathStatus
	for _, p := range st.Paths {
		if p.State != "verified" && p.State != "russian" {
			continue
		}
		if p.Default {
			return ipc.ExitStatus{IP: p.IP, Country: p.Country}, true
		}
		found = append(found, p)
	}
	if len(found) == 1 {
		return ipc.ExitStatus{IP: found[0].IP, Country: found[0].Country}, true
	}
	return ipc.ExitStatus{}, false
}

// choose показывает список и возвращает выбор. В терминале — в посимвольном
// режиме; без терминала (тесты) ввод читается как есть.
func choose(env Env, items []string, o tui.Options) (int, bool) {
	if env.Raw != nil {
		restore, err := env.Raw()
		if err != nil {
			fmt.Fprintf(env.Err, "Терминал не переключился в режим меню: %v\n", err)
			return -1, false
		}
		defer restore()
	}
	i, err := tui.Select(env.In, env.Out, items, o)
	if err != nil {
		fmt.Fprintln(env.Err, err)
		return -1, false
	}
	return i, i >= 0
}

// currentStatus спрашивает статус; служба молчит — объясняет почему.
func currentStatus(env Env) (*ipc.Status, bool) {
	resp, err := ipc.Call(env.Layout.Socket, ipc.Request{Cmd: ipc.CmdStatus})
	if err != nil {
		silent(env, err)
		return nil, false
	}
	if !resp.OK || resp.Status == nil {
		fmt.Fprintln(env.Err, resp.Error)
		return nil, false
	}
	return resp.Status, true
}

func appWord(learned bool) string {
	if learned {
		return "защищено"
	}
	return "ждёт обучения"
}

// appLine — приложение в статусе. Пока оно не обучено, статус напоминает, что
// сделать.
func appLine(a ipc.AppStatus) string {
	if a.Learned {
		if a.Addrs == 0 && a.Domains == 0 {
			return a.Name + " — защищено"
		}
		return fmt.Sprintf("%s — защищено: %d %s, %d %s", a.Name, a.Addrs, core.Plural(a.Addrs, "адрес", "адреса", "адресов"),
			a.Domains, core.Plural(a.Domains, "домен", "домена", "доменов"))
	}
	progress := fmt.Sprintf("%s из %s", clock(a.WorkSecs), clock(a.NeedSecs))
	if a.Open && a.Running {
		return fmt.Sprintf("%s — ждёт обучения: учится через проверенный VPN, %s", a.Name, progress)
	}
	hint := "включи VPN и открой его"
	if a.Command {
		hint = "включи VPN и запусти программу"
	}
	return fmt.Sprintf("%s — ждёт обучения: ещё не защищено — %s (проработало %s)", a.Name, hint, progress)
}

func clock(secs int) string { return fmt.Sprintf("%d:%02d", secs/60, secs%60) }

func ruleText(rule string) string { return core.RuleText(rule) }
