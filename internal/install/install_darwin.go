package install

import (
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"vpnlock/internal/paths"
)

// Launchd — службы launchd в системном домене.
type Launchd interface {
	// Bootstrap загружает службу из plist и запускает её.
	Bootstrap(plist string) error
	// Bootout останавливает и выгружает службу и ждёт этого. Не загружена — не ошибка.
	Bootout(label string) error
	// BootoutDetached — то же отдельным процессом и без ожидания: так служба
	// снимает саму себя.
	BootoutDetached(label string) error
	// Enable снимает запрет на запуск службы, если его ставили.
	Enable(label string) error
	// BootstrapUser загружает задачу из plist в сеанс пользователя uid;
	// BootoutUser выгружает её оттуда. Не загружена — не ошибка.
	BootstrapUser(uid int, plist string) error
	BootoutUser(uid int, label string) error
}

// Installer ставит и снимает установку по раскладке Layout.
type Installer struct {
	Layout  paths.Layout
	Launchd Launchd
	// Agent — кому ставить ежедневную задачу каталога: тому, кто вызвал sudo.
	// nil — задача не ставится.
	Agent *Agent
	// Note — что сказать человеку после установки (про каталог); пусто — нечего.
	Note string
	// Clear снимает правила файрвола и резолверы при удалении на месте — после
	// остановки службы (иначе её сторож вернул бы правила) и до удаления файлов:
	// токен pf лежит в каталоге службы. nil — снимать нечего.
	Clear func() error
}

// Agent — ежедневная задача каталога в сеансе пользователя.
type Agent struct {
	UID   int    `json:"uid"`
	GID   int    `json:"gid"`
	Home  string `json:"home"`
	Clone string `json:"clone"` // клон, из которого обновляется каталог
	Plist string `json:"plist"` // заполняет установка
}

// Install ставит исполняемый файл src службой launchd и запускает её. Поверх
// прежней установки работает как обновление: служба перезапускается, настройки
// остаются.
func (in *Installer) Install(src string) error {
	L := in.Layout
	// Чужой файл на месте команды проверяется до любых изменений: установка
	// не должна остановиться на полпути.
	if err := in.commandFree(); err != nil {
		return err
	}
	if err := in.Launchd.Bootout(paths.Label); err != nil {
		return fmt.Errorf("не удалось остановить прежнюю службу: %w", err)
	}
	dirs := []struct {
		path string
		mode fs.FileMode
	}{
		{L.AppDir, 0o755},
		{filepath.Dir(L.Binary), 0o755},
		{L.StateDir, 0o700},
		{L.LogDir, 0o755},
	}
	for _, d := range dirs {
		if err := mkdir(d.path, d.mode); err != nil {
			return err
		}
	}
	// Системные каталоги не наши: их создаём, только если нет, и не трогаем
	// права существующих (/usr/local/bin у Homebrew принадлежит пользователю).
	if err := os.MkdirAll(filepath.Dir(L.Plist), 0o755); err != nil {
		return err
	}
	if err := copyFile(src, L.Binary, 0o755); err != nil {
		return fmt.Errorf("не удалось скопировать vpnlock: %w", err)
	}
	note, err := in.installCatalog(src)
	if err != nil {
		return err
	}
	in.Note = note
	if err := in.rememberClone(src); err != nil {
		return err
	}
	if err := in.linkCommand(); err != nil {
		return err
	}
	if err := writeFile(L.Plist, plist(L), 0o644); err != nil {
		return err
	}
	if err := in.Launchd.Enable(paths.Label); err != nil {
		return err
	}
	if err := in.Launchd.Bootstrap(L.Plist); err != nil {
		return err
	}
	in.Note = joinNotes(in.Note, in.installAgent(src))
	in.Note = joinNotes(in.Note, in.installTray())
	return nil
}

// installAgent ставит ежедневную задачу каталога в сеанс того, кто вызвал sudo:
// git pull в его клоне идёт с его ключами и паролями. Задача не поставилась —
// служба работает и так, на последнем каталоге; человек узнаёт почему.
func (in *Installer) installAgent(src string) string {
	a := in.Agent
	if a == nil {
		return "Ежедневное обновление каталога не поставлено: установку запустили не через sudo из своей учётной записи."
	}
	in.removeAgent() // прежняя задача — возможно, с другим клоном или у другого пользователя
	a.Clone = filepath.Dir(filepath.Dir(src))
	a.Plist = paths.AgentPlist(a.Home)
	dir := filepath.Dir(a.Plist)
	err := os.MkdirAll(dir, 0o755)
	if err == nil {
		err = chownTo(dir, a)
	}
	if err == nil {
		err = writeFile(a.Plist, agentPlist(in.Layout, a), 0o644)
	}
	if err == nil {
		err = chownTo(a.Plist, a)
	}
	if err == nil {
		var data []byte
		data, err = json.Marshal(a)
		if err == nil {
			err = writeFile(in.Layout.AgentFile, data, 0o644)
		}
	}
	if err != nil {
		return fmt.Sprintf("Ежедневное обновление каталога не поставлено: %v. Защита работает на текущем каталоге.", err)
	}
	if err := in.Launchd.BootstrapUser(a.UID, a.Plist); err != nil {
		// Без сеанса (вход по SSH) задача загрузится при следующем входе.
		return "Ежедневное обновление каталога поставлено — заработает при следующем входе в систему."
	}
	return "Ежедневное обновление каталога поставлено: раз в сутки git pull в клоне " + a.Clone + "."
}

// installTray ставит значок службы в сеанс того, кто вызвал sudo: при входе он
// появляется сам. Значок не встал — защита от него не зависит, человек узнаёт почему.
// Прежний значок снял removeAgent в installAgent.
func (in *Installer) installTray() string {
	a := in.Agent
	if a == nil {
		return "Значок не поставлен: установку запустили не через sudo из своей учётной записи."
	}
	plist := paths.TrayPlist(a.Home)
	err := writeFile(plist, trayPlist(in.Layout, a), 0o644)
	if err == nil {
		err = chownTo(plist, a)
	}
	if err != nil {
		return fmt.Sprintf("Значок не поставлен: %v. Защита работает и без него.", err)
	}
	if err := in.Launchd.BootstrapUser(a.UID, plist); err != nil {
		// Без сеанса (вход по SSH) значок загрузится при следующем входе.
		return "Значок появится в строке меню после следующего входа в систему."
	}
	return "Значок vpnlock — в строке меню, рядом с часами: есть значок — служба отвечает."
}

// removeAgent снимает то, что стоит в сеансе пользователя: ежедневную задачу каталога
// и значок. Путь значка — из Home: формат файла задачи от значка не зависит, поэтому
// и установки без значка снимаются правильно.
func (in *Installer) removeAgent() error {
	data, err := os.ReadFile(in.Layout.AgentFile)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var a Agent
	if err := json.Unmarshal(data, &a); err != nil {
		return fmt.Errorf("%s: %w", in.Layout.AgentFile, err)
	}
	errs := []error{in.Launchd.BootoutUser(a.UID, paths.CatalogLabel), in.Launchd.BootoutUser(a.UID, paths.TrayLabel)}
	files := []string{paths.TrayPlist(a.Home), paths.TrayLog(a.Home)}
	if a.Plist != "" {
		files = append(files, a.Plist)
	}
	for _, f := range files {
		if err := os.Remove(f); err != nil && !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	if err := os.Remove(in.Layout.AgentFile); err != nil && !errors.Is(err, fs.ErrNotExist) {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// chownTo отдаёт файл пользователю задачи: launchd его сеанса не возьмёт
// задачу из чужого файла. Не под root (тесты) — незачем и нельзя.
func chownTo(path string, a *Agent) error {
	if os.Geteuid() != 0 {
		return nil
	}
	return os.Lchown(path, a.UID, a.GID)
}

// agentPlist — ежедневная задача каталога: раз в сутки и при входе в систему
// `vpnlock catalog sync <клон>` от имени пользователя.
func agentPlist(L paths.Layout, a *Agent) []byte {
	esc := func(s string) string {
		var b strings.Builder
		xml.EscapeText(&b, []byte(s))
		return b.String()
	}
	logFile := filepath.Join(a.Home, "Library", "Logs", "vpnlock-catalog.log")
	return fmt.Appendf(nil, `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>%s</string>
	<key>ProgramArguments</key>
	<array>
		<string>%s</string>
		<string>catalog</string>
		<string>sync</string>
		<string>%s</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>StartInterval</key>
	<integer>86400</integer>
	<key>ProcessType</key>
	<string>Background</string>
	<key>StandardOutPath</key>
	<string>%s</string>
	<key>StandardErrorPath</key>
	<string>%s</string>
</dict>
</plist>
`, esc(paths.CatalogLabel), esc(L.Binary), esc(a.Clone), esc(logFile), esc(logFile))
}

// trayPlist — значок службы: при входе в графический сеанс `vpnlock tray` от имени
// пользователя. Упал — launchd поднимает его снова; вышел сам (vpnlock удалён) — нет.
// AbandonProcessGroup не задан: launchd при смерти задачи снимает её группу процессов,
// иначе osascript пережил бы родителя и значок соврал бы. ProcessType не Background:
// система не должна придерживать интерфейс.
func trayPlist(L paths.Layout, a *Agent) []byte {
	esc := func(s string) string {
		var b strings.Builder
		xml.EscapeText(&b, []byte(s))
		return b.String()
	}
	logFile := paths.TrayLog(a.Home)
	return fmt.Appendf(nil, `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>%s</string>
	<key>ProgramArguments</key>
	<array>
		<string>%s</string>
		<string>tray</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<dict>
		<key>SuccessfulExit</key>
		<false/>
	</dict>
	<key>LimitLoadToSessionType</key>
	<string>Aqua</string>
	<key>StandardOutPath</key>
	<string>%s</string>
	<key>StandardErrorPath</key>
	<string>%s</string>
</dict>
</plist>
`, esc(paths.TrayLabel), esc(L.Binary), esc(logFile), esc(logFile))
}

// Remove снимает всё, что поставила установка, кроме самой работающей службы —
// её останавливает Bootout. Описание службы удаляется первым: даже если дальше
// что-то не выйдет, после перезагрузки служба не стартует.
func (in *Installer) Remove() error {
	L := in.Layout
	var errs []error
	rm := func(p string) {
		if err := os.RemoveAll(p); err != nil {
			errs = append(errs, err)
		}
	}
	rm(L.Plist)
	if err := in.removeAgent(); err != nil {
		errs = append(errs, err)
	}
	if ours, _ := in.commandIsOurs(); ours {
		rm(L.CommandLink)
	}
	rm(L.AppDir)
	rm(L.LogDir)
	return errors.Join(errs...)
}

// Stop снимает службу с launchd, не дожидаясь этого: служба вызывает его, уже
// ответив клиенту.
func (in *Installer) Stop() error { return in.Launchd.BootoutDetached(paths.Label) }

// Uninstall — снятие на месте от root: когда удаляют через sudo или служба не
// отвечает. Сначала описание службы — после перезагрузки она уже не стартует,
// что бы ни случилось дальше; затем остановка службы, правила (Clear) и только
// потом файлы. Служба не остановилась — правила и файлы остаются: она
// продолжает защищать, удаление можно повторить.
func (in *Installer) Uninstall() error {
	if err := os.Remove(in.Layout.Plist); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := in.Launchd.Bootout(paths.Label); err != nil {
		return fmt.Errorf("служба не остановилась: %w", err)
	}
	var errs []error
	// Сокет убирает сама служба при остановке; после падения он мог остаться.
	if err := os.Remove(in.Layout.Socket); err != nil && !errors.Is(err, fs.ErrNotExist) {
		errs = append(errs, err)
	}
	if in.Clear != nil {
		if err := in.Clear(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(append(errs, in.Remove())...)
}

// plist — описание службы для launchd: стартует при загрузке системы и
// перезапускается, если завершилась.
func plist(L paths.Layout) []byte {
	esc := func(s string) string {
		var b strings.Builder
		xml.EscapeText(&b, []byte(s))
		return b.String()
	}
	return fmt.Appendf(nil, `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>%s</string>
	<key>ProgramArguments</key>
	<array>
		<string>%s</string>
		<string>daemon</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>StandardOutPath</key>
	<string>%s</string>
	<key>StandardErrorPath</key>
	<string>%s</string>
</dict>
</plist>
`, esc(paths.Label), esc(L.Binary), esc(L.LogFile), esc(L.LogFile))
}
