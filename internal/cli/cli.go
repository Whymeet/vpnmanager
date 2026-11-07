// Package cli — команды vpnlock для человека. Команды и их аргументы —
// по-английски, меню и сообщения — по-русски.
package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"os"
	"os/signal"
	"runtime"
	"slices"
	"strings"
	"time"

	"vpnlock/internal/apps"
	"vpnlock/internal/core"
	"vpnlock/internal/ipc"
	"vpnlock/internal/paths"
	"vpnlock/internal/tray"
)

// Env — с чем работают команды: пути, ввод-вывод и действия, которые делает root.
type Env struct {
	Layout      paths.Layout
	Version     string
	In          io.Reader
	Out, Err    io.Writer
	Root        bool // команду запустили от root, через sudo; на Windows — от имени администратора
	Interactive bool // ввод — терминал: можно спросить подтверждение
	// Install ставит этот исполняемый файл службой и возвращает, что сказать
	// человеку сверх обычного (про каталог). Только от root.
	Install func() (note string, err error)
	// Uninstall снимает установку на месте. Только от root.
	Uninstall func() error
	// Update собирает vpnlock в клоне от имени человека и ставит новую версию
	// поверх прежней. Только от root.
	Update func(clone string) error
	// Raw переводит терминал в посимвольный режим для меню; nil — ввод читается
	// как есть (тесты).
	Raw func() (restore func() error, err error)
	// Installed — установленные приложения: папки «Программы» на macOS, меню
	// «Пуск» и Store на Windows, меню приложений и службы systemd на Linux.
	Installed func() []apps.App
	// Toast показывает уведомление в сеансе пользователя (Windows, агент
	// уведомлений); nil — показывает служба сама (macOS).
	Toast func(text string) error
	// Tray занимает место значка в сеансе и возвращает его показ: tray.ErrBusy —
	// значок уже есть, tray.ErrNoSession — показывать негде. nil — значка нет.
	Tray func() (tray.Icon, error)
	// Home — домашний каталог человека за терминалом (и под sudo — его, а не
	// root): проверка читает там настройки браузеров. Пусто — браузеры не
	// проверяются.
	Home string
	// FindService — служба системы с таким именем (nginx или nginx.service) в виде
	// пути для службы; пусто — такой нет. nil — служб система не защищает (всё,
	// кроме Linux). SameProgram — служба и команда запускают одну и ту же программу.
	FindService func(name string) string
	// Moved — команда name запускает уже не то, что защищается под id (Linux).
	Moved       func(name, id string) bool
	SameProgram func(service, command string) bool
}

// Время, за которое служба должна ответить после установки и уйти после удаления.
var (
	startWait = 10 * time.Second
	stopWait  = 10 * time.Second
	// removeWait — сколько ждать удаления через службу: не ответив, она всё равно
	// доводит его до конца, и клиент соврал бы об ошибке.
	removeWait = 2 * time.Minute
)

// Run выполняет команду и возвращает код выхода.
func Run(args []string, env Env) int {
	// Один буфер ввода на всю команду: меню и подтверждение читают из него, и
	// ответ, набранный сразу после выбора, не теряется в чужом буфере.
	if env.In != nil {
		env.In = bufio.NewReader(env.In)
	}
	if len(args) == 0 {
		if env.Interactive {
			return menu(env)
		}
		usage(env.Out)
		return 0
	}
	switch args[0] {
	case "status":
		if len(args) > 1 {
			return appDetail(env, strings.Join(args[1:], " "))
		}
		return status(env)
	case "log":
		return journal(env)
	case "add":
		return addApp(env, args[1:])
	case "remove":
		return removeApp(env, args[1:])
	case "rule":
		return rule(env, args[1:])
	case "remember":
		return remember(env, args[1:])
	case "forget":
		return forget(env, args[1:])
	case "notifications":
		return notifications(env, args[1:])
	case "check":
		return check(env)
	case "catalog":
		return catalogCmd(env, args[1:])
	case "uninstall":
		return uninstall(env, args[1:])
	case "update":
		return update(env, args[1:])
	case "install":
		return install(env)
	case "protect", "unprotect":
		return protect(env, args[0], args[1:])
	case "import":
		return importFile(env, args[1:])
	case "notify-agent":
		return notifyAgent(env)
	case "tray":
		return trayCmd(env)
	case "version", "--version":
		fmt.Fprintln(env.Out, env.Version)
		return 0
	case "help", "-h", "--help":
		usage(env.Out)
		return 0
	}
	fmt.Fprintf(env.Err, "Нет команды «%s».\n\n", args[0])
	usage(env.Err)
	return 2
}

func usage(w io.Writer) {
	fmt.Fprint(w, `vpnlock — приложения выходят в сеть только через проверенный VPN.

vpnlock без команды открывает меню: всё выбирается стрелками.

Команды:
  vpnlock add [имя|путь]              защитить приложение или консольную программу (claude); без имени — выбор из списка
  vpnlock remove [имя] [--yes]        снять защиту с приложения
  vpnlock rule [any|mine]             какое правило действует или сменить его
  vpnlock remember [имя] [адрес]      запомнить текущий выход VPN под именем; с адресом — без подключения
  vpnlock forget <выход>              убрать выход из моих — по имени или адресу
  vpnlock forget <имя> <адрес>...     убрать у приложения адрес или домен, выученный по ошибке
  vpnlock notifications [on|off]      уведомления о закрытии сервисов (журнал пишется всегда)
  vpnlock status [приложение]         служба, правило, VPN и выход, приложения; с именем — что выучило приложение
  vpnlock check                       правила, выход, сервисы мимо VPN, «безопасный DNS» браузеров
  vpnlock log                         события в реальном времени (выход — Ctrl+C)
  vpnlock update [клон]               после git pull: пересобрать и поставить новую версию (с правами администратора)
  vpnlock uninstall [--yes]           снять службу и всё, что поставила установка
  vpnlock catalog load [файл]         дать службе каталог (по умолчанию catalog/catalog.json клона)
  vpnlock catalog export [файл]       выученное на этом маке — в каталог клона или в файл для vpnlock import
  vpnlock catalog sync [клон]         git pull в клоне и каталог — службе (это раз в сутки делает задача)

Защита без приложения — по домену или адресу:
  vpnlock protect <домен|адрес>...    закрыть адреса сервиса везде, кроме проверенного VPN
  vpnlock unprotect <домен|адрес>...  снять защиту с домена или адреса
  vpnlock import <файл>               закрыть сразу всё из файла: выгрузка catalog export или список доменов и адресов

Установка и обновление — по setup/README.md в клоне репозитория.
`)
}

// protect/unprotect — служебные команды: защищаемый сервис задаётся доменом
// или адресом. Меняют настройки, поэтому нужны права администратора.
// Доменов можно несколько через пробел: не вышло с одним — остальные всё равно
// идут, код выхода скажет, что не всё.
func protect(env Env, cmd string, args []string) int {
	if len(args) == 0 || slices.Contains(args, "") {
		fmt.Fprintf(env.Err, "Укажи домен или адрес, можно несколько через пробел: vpnlock %s notion.so claude.ai 160.79.104.10\n", cmd)
		return 2
	}
	ipcCmd := ipc.CmdProtect
	if cmd == "unprotect" {
		ipcCmd = ipc.CmdUnprotect
	}
	code := 0
	for _, domain := range args {
		resp, err := ipc.Call(env.Layout.Socket, ipc.Request{Cmd: ipcCmd, Domain: domain})
		if err != nil {
			return silent(env, err)
		}
		if !resp.OK {
			fmt.Fprintln(env.Err, resp.Error)
			if resp.Code == ipc.CodeForbidden {
				return 1 // с остальными ответ будет тот же
			}
			code = 1
			continue
		}
		_, isAddr := netip.ParseAddr(domain)
		switch {
		case cmd == "protect" && isAddr == nil:
			fmt.Fprintf(env.Out, "Адрес %s защищён: без проверенного VPN он закрыт.\n", domain)
		case cmd == "protect":
			fmt.Fprintf(env.Out, "Сервис %s защищён: без проверенного VPN его адреса закрыты.\n", domain)
		default:
			fmt.Fprintf(env.Out, "С %s защита снята.\n", domain)
		}
	}
	return code
}

// manualLine — что защищено вручную (protect, import), для статуса: домены,
// если их немного, и сколько адресов. Пусто — ничего.
func manualLine(domains []string, addrs int) string {
	var parts []string
	switch {
	case len(domains) > 6:
		parts = append(parts, fmt.Sprintf("%d %s", len(domains), core.Plural(len(domains), "домен", "домена", "доменов")))
	case len(domains) > 0:
		parts = append(parts, strings.Join(domains, ", "))
	}
	if addrs > 0 {
		parts = append(parts, fmt.Sprintf("%d %s", addrs, core.Plural(addrs, "адрес", "адреса", "адресов")))
	}
	return strings.Join(parts, "; ")
}

func status(env Env) int {
	resp, err := ipc.Call(env.Layout.Socket, ipc.Request{Cmd: ipc.CmdStatus})
	if err != nil {
		return silent(env, err)
	}
	if !resp.OK || resp.Status == nil {
		fmt.Fprintln(env.Err, resp.Error)
		return 1
	}
	st := resp.Status
	fmt.Fprintf(env.Out, "Служба: работает с %s, версия %s\n", st.StartedAt.Local().Format("02.01 15:04"), st.Version)
	if st.Version != env.Version {
		fmt.Fprintf(env.Out, "У этой команды версия %s: в службу она встанет после повторной установки.\n", env.Version)
	}
	if st.Rule != "" {
		fmt.Fprintf(env.Out, "Правило: %s\n", ruleText(st.Rule))
		printExits(env, st.Exits)
		fmt.Fprintf(env.Out, "Уведомления: %s\n", notifyText(!st.NotifyOff))
	}
	switch {
	case st.Paths == nil:
		// Служба старой версии о VPN не сообщает — строка о версии выше это объясняет.
	case len(st.Paths) == 0:
		fmt.Fprintln(env.Out, "VPN: нет")
	case len(st.Paths) == 1:
		fmt.Fprintf(env.Out, "VPN: %s — %s\n", pathLabel(st.Paths[0]), st.Paths[0].Summary)
	default:
		fmt.Fprintln(env.Out, "VPN:")
		for _, p := range st.Paths {
			fmt.Fprintf(env.Out, "  %s — %s\n", pathLabel(p), p.Summary)
		}
	}
	if st.Apps != nil {
		if st.Catalog == "" {
			fmt.Fprintln(env.Out, "Каталог: не установлен — приложения учатся")
		} else {
			fmt.Fprintf(env.Out, "Каталог: %s, %d %s\n", dayText(st.Catalog), st.CatalogN, core.Plural(st.CatalogN, "приложение", "приложения", "приложений"))
		}
		if st.CatalogStale > 0 {
			fmt.Fprintf(env.Out, "  не обновлялся %d %s — обнови вручную: git pull в клоне, затем vpnlock catalog load\n",
				st.CatalogStale, core.Plural(st.CatalogStale, "день", "дня", "дней"))
		}
		if st.SyncProblem != "" {
			fmt.Fprintf(env.Out, "  последнее обновление не удалось: %s\n", st.SyncProblem)
		}
	}
	if st.NewVersion != "" {
		fmt.Fprintf(env.Out, "Новая версия: в клоне %s — обнови по разделу «Как обновиться» в setup/README.md\n", st.NewVersion)
	}
	switch {
	case st.Apps == nil:
		// Служба старой версии о приложениях не сообщает.
	case len(st.Apps) == 0:
		fmt.Fprintln(env.Out, "Приложения: пока ни одного — добавить: vpnlock add")
	default:
		fmt.Fprintln(env.Out, "Приложения:")
		for _, a := range st.Apps {
			fmt.Fprintf(env.Out, "  %s\n", appLine(a))
		}
	}
	if line := manualLine(st.Manual, st.ManualAddrs); line != "" {
		fmt.Fprintln(env.Out, "Вручную: "+line)
	}
	return 0
}

// pathLabel — имя пути для человека: интерфейс туннеля или прокси с процессом,
// который слушает его порт.
func pathLabel(p ipc.PathStatus) string {
	if p.Listener != "" {
		return p.Iface + " (" + p.Listener + ")"
	}
	return p.Iface
}

// journal показывает последние события и дальше — новые, пока его не закроют.
func journal(env Env) int { return journalContext(context.Background(), env) }

// followJournal — журнал из меню: Ctrl+C возвращает в меню, а не закрывает его.
func followJournal(env Env) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if code := journalContext(ctx, env); ctx.Err() == nil {
		return code
	}
	fmt.Fprintln(env.Out)
	return 0
}

func journalContext(ctx context.Context, env Env) int {
	header := false
	err := ipc.StreamContext(ctx, env.Layout.Socket, ipc.Request{Cmd: ipc.CmdJournal, Follow: true}, func(r ipc.Response) error {
		if !r.OK {
			return errors.New(r.Error)
		}
		if !header {
			fmt.Fprintln(env.Out, "Журнал vpnlock: события за неделю и новые по мере появления. Выход — Ctrl+C.")
			header = true
		}
		if r.Event != nil {
			fmt.Fprintln(env.Out, eventLine(*r.Event))
		}
		return nil
	})
	switch {
	case ctx.Err() != nil:
		return 0
	case errors.Is(err, ipc.ErrNotRunning):
		return silent(env, err)
	case errors.Is(err, ipc.ErrEnded):
		fmt.Fprintln(env.Out, "Служба остановилась — журнал прерван.")
		return 1
	case err != nil:
		fmt.Fprintln(env.Err, err)
		return 1
	}
	return 0
}

func eventLine(e core.Event) string {
	return e.Time.Local().Format("02.01 15:04:05") + "  " + e.Text
}

// statusQuiet — статус без сообщений об ошибках (для шапки меню).
func statusQuiet(env Env) (*ipc.Status, bool) {
	resp, err := ipc.Call(env.Layout.Socket, ipc.Request{Cmd: ipc.CmdStatus})
	if err != nil || !resp.OK || resp.Status == nil {
		return nil, false
	}
	return resp.Status, true
}

// silent объясняет, почему служба не ответила.
func silent(env Env, err error) int {
	if !errors.Is(err, ipc.ErrNotRunning) {
		fmt.Fprintf(env.Err, "Служба ответила непонятно: %v\n", err)
		return 1
	}
	if !installed(env.Layout) {
		fmt.Fprintln(env.Out, "vpnlock не установлен. Установка — по setup/README.md в клоне репозитория.")
		return 1
	}
	fmt.Fprintln(env.Out, "Служба: не отвечает — защита держится: правила файрвола остаются в системе, сервисы закрыты.")
	switch runtime.GOOS {
	case "windows":
		fmt.Fprintln(env.Out, "Обычно Windows перезапускает службу сама за несколько секунд.")
	case "linux":
		fmt.Fprintln(env.Out, "Обычно systemd перезапускает службу сам за несколько секунд.")
	default:
		fmt.Fprintln(env.Out, "Обычно launchd перезапускает службу сам за несколько секунд.")
	}
	fmt.Fprintf(env.Out, "Если сообщение не уходит, причина — в %s.\n", env.Layout.LogFile)
	return 1
}

func install(env Env) int {
	if !env.Root {
		switch runtime.GOOS {
		case "windows":
			fmt.Fprintln(env.Err, "Установка — одной командой из клона: powershell -NoProfile -ExecutionPolicy Bypass -File setup\\windows\\install.ps1. Права администратора она попросит сама. В системе ничего не изменено.")
		case "linux":
			fmt.Fprintln(env.Err, "Установка — одной командой из клона: ./install.cmd. Пароль она спросит сама. В системе ничего не изменено.")
		default:
			fmt.Fprintln(env.Err, "Установка — одной командой из клона: ./setup/macos/install.sh. Пароль она спросит сама. В системе ничего не изменено.")
		}
		return 1
	}
	fmt.Fprintf(env.Out, "· Ставлю службу vpnlock %s\n", env.Version)
	note, err := env.Install()
	if note != "" {
		fmt.Fprintf(env.Out, "· %s\n", note)
	}
	if err != nil {
		fmt.Fprintf(env.Err, "✗ Установка не удалась: %v\n", err)
		return 1
	}
	st, err := waitStatus(env.Layout.Socket)
	if err != nil {
		fmt.Fprintf(env.Err, "✗ Служба поставлена, но не отвечает. Причина — в %s.\n", env.Layout.LogFile)
		return 1
	}
	if runtime.GOOS == "windows" {
		fmt.Fprintf(env.Out, `✓ Служба vpnlock %s работает и будет стартовать вместе с системой.
  Проверить: vpnlock status — в новом окне PowerShell: в открытых окнах команды ещё нет.
`, st.Version)
		return 0
	}
	if runtime.GOOS == "linux" {
		fmt.Fprintf(env.Out, "✓ Служба vpnlock %s работает и будет стартовать вместе с системой.\n  Проверить: vpnlock status\n", st.Version)
		return 0
	}
	fmt.Fprintf(env.Out, `✓ Служба vpnlock %s работает и будет стартовать вместе с системой.
  Проверить: vpnlock status

macOS может показать уведомление «Добавлены фоновые объекты» — это служба vpnlock.
Не выключай её в Системных настройках → Основные → Объекты входа: иначе после
перезагрузки служба не стартует.
`, st.Version)
	return 0
}

// waitStatus ждёт, пока только что запущенная служба ответит на статус.
func waitStatus(socket string) (*ipc.Status, error) {
	deadline := time.Now().Add(startWait)
	for {
		resp, err := ipc.Call(socket, ipc.Request{Cmd: ipc.CmdStatus})
		if err == nil && resp.OK && resp.Status != nil {
			return resp.Status, nil
		}
		if time.Now().After(deadline) {
			if err == nil {
				err = errors.New(resp.Error)
			}
			return nil, err
		}
		time.Sleep(200 * time.Millisecond)
	}
}

const uninstallWarning = `vpnlock будет удалён: служба и все её правила снимаются, защищённые приложения
начнут выходить в сеть с домашнего адреса.
Удалить? Напиши «да»: `

func uninstall(env Env, args []string) int {
	yes := false
	for _, a := range args {
		if a != "--yes" && a != "-y" {
			fmt.Fprintf(env.Err, "«uninstall» снимает весь vpnlock и принимает только --yes, а получено «%s». Ничего не изменено.\n", a)
			return 2
		}
		yes = true
	}
	if !installed(env.Layout) {
		fmt.Fprintln(env.Out, "vpnlock не установлен — удалять нечего.")
		return 0
	}
	// На Windows служба сама себя не снимает: удаляют на месте, из PowerShell
	// от имени администратора. Без этого и спрашивать незачем.
	if runtime.GOOS == "windows" && !env.Root {
		fmt.Fprintln(env.Err, "Удалить vpnlock можно только из PowerShell, открытого от имени администратора: в меню «Пуск» найди «PowerShell», правой кнопкой — «Запуск от имени администратора», и повтори там vpnlock uninstall. Ничего не изменено.")
		return 1
	}
	if !yes {
		if !env.Interactive {
			fmt.Fprintln(env.Err, "Удаление нужно подтвердить: запусти команду в терминале или добавь --yes. Ничего не изменено.")
			return 1
		}
		fmt.Fprint(env.Out, uninstallWarning)
		if !confirmed(env.In) {
			fmt.Fprintln(env.Out, "Отменено — ничего не изменено.")
			return 1
		}
	}

	if env.Root {
		if err := env.Uninstall(); err != nil {
			fmt.Fprintf(env.Err, "✗ Удалить до конца не вышло: %v\n", err)
			return 1
		}
	} else if code := uninstallViaService(env); code != 0 {
		return code
	}
	fmt.Fprintln(env.Out, "✓ vpnlock удалён: служба снята, файлы установки убраны. Папка клона осталась — это обычная папка.")
	return 0
}

// uninstallViaService просит службу снять себя: так удаляет без sudo любой
// администратор.
func uninstallViaService(env Env) int {
	resp, err := ipc.CallWait(env.Layout.Socket, ipc.Request{Cmd: ipc.CmdUninstall}, removeWait)
	if errors.Is(err, ipc.ErrNotRunning) {
		fmt.Fprintln(env.Err, "Служба не отвечает, поэтому без пароля удалить не выйдет. С паролем администратора: sudo vpnlock uninstall")
		return 1
	}
	if err != nil {
		fmt.Fprintf(env.Err, "Служба ответила непонятно: %v\n", err)
		return 1
	}
	if !resp.OK {
		fmt.Fprintln(env.Err, resp.Error)
		return 1
	}
	// Служба уходит уже после ответа: ждём, пока закроется её канал.
	deadline := time.Now().Add(stopWait)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(env.Layout.Socket); errors.Is(err, fs.ErrNotExist) {
			return 0
		}
		time.Sleep(100 * time.Millisecond)
	}
	fmt.Fprintln(env.Out, "Служба ещё останавливается — через несколько секунд её не будет.")
	return 0
}

func confirmed(in io.Reader) bool {
	line, _ := bufio.NewReader(in).ReadString('\n') // тот же буфер, что завёл Run
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "да", "д", "yes", "y":
		return true
	}
	return false
}

// installed — на диске есть что-то от установки.
func installed(L paths.Layout) bool {
	for _, p := range L.Traces() {
		if _, err := os.Lstat(p); err == nil {
			return true
		}
	}
	return false
}
