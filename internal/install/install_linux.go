package install

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"vpnlock/internal/paths"
)

// Systemd — службы systemd.
type Systemd interface {
	// Reload перечитывает описания служб.
	Reload() error
	// Start включает автозапуск юнита и запускает его, дожидаясь готовности.
	Start(unit string) error
	// Halt останавливает юнит и ждёт этого; автозапуск остаётся. Юнита нет — не ошибка.
	Halt(unit string) error
	// Disable только выключает автозапуск: юнит продолжает работать. Так удаление
	// идёт из самой службы. Юнита нет — не ошибка.
	Disable(unit string) error
	// Forget убирает память systemd о завершившемся юните: упавшая задача иначе
	// осталась бы в списке юнитов и после удаления файла.
	Forget(unit string)
	// StopDetached просит systemd остановить юнит, не дожидаясь: так служба
	// останавливает саму себя.
	StopDetached(unit string) error
}

// Installer ставит и снимает установку по раскладке Layout.
type Installer struct {
	Layout  paths.Layout
	Systemd Systemd
	// Agent — от чьего имени обновлять каталог: тот, кто вызвал sudo. nil — задача
	// не ставится.
	Agent *Agent
	// Note — что сказать человеку после установки (про каталог); пусто — нечего.
	Note string
	// Preflight проверяет, что система умеет всё нужное: до любых изменений.
	// nil — проверять нечего (тесты).
	Preflight func() error
	// Clear снимает правила файрвола и резолверы при удалении на месте — после
	// остановки службы (иначе её сторож вернул бы правила). nil — снимать нечего.
	Clear func() error
}

// Agent — чьим именем ходит ежедневное обновление каталога: git в клоне идёт с его
// ключами и паролями, а служба принимает итог от владельца клона.
type Agent struct {
	UID   int
	GID   int
	Home  string
	Clone string // клон, из которого обновляется каталог; заполняет установка
}

// Install ставит исполняемый файл src службой systemd и запускает её. Поверх
// прежней установки работает как обновление: служба перезапускается, настройки
// остаются, а правила всё это время лежат в ядре.
func (in *Installer) Install(src string) error {
	// Всё, что может отказать, проверяется до изменений: установка не должна
	// остановиться на полпути.
	if err := in.commandFree(); err != nil {
		return err
	}
	if in.Preflight != nil {
		if err := in.Preflight(); err != nil {
			return fmt.Errorf("%w. В системе ничего не изменено", err)
		}
	}
	if err := in.Systemd.Halt(paths.Unit); err != nil {
		return fmt.Errorf("не удалось остановить прежнюю службу: %w", err)
	}
	if err := in.place(src); err != nil {
		// Обновление не должно оставить компьютер без службы: прежняя цела.
		in.Systemd.Start(paths.Unit)
		return err
	}
	if err := in.Systemd.Start(paths.Unit); err != nil {
		return err
	}
	in.Note = joinNotes(in.Note, in.installTimer(src))
	in.Note = joinNotes(in.Note, in.installTray())
	return nil
}

// place раскладывает файлы установки и описание службы.
func (in *Installer) place(src string) error {
	L := in.Layout
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
	if err := os.MkdirAll(filepath.Dir(L.UnitFile), 0o755); err != nil {
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
	if err := writeFile(L.UnitFile, unitFile(L), 0o644); err != nil {
		return err
	}
	return in.Systemd.Reload()
}

// installTimer ставит ежедневное обновление каталога. Не поставилось — служба
// работает и так, на последнем каталоге; человек узнаёт почему.
func (in *Installer) installTimer(src string) string {
	a := in.Agent
	if a == nil {
		return "Ежедневное обновление каталога не поставлено: установку запустили не через sudo из своей учётной записи."
	}
	L := in.Layout
	a.Clone = filepath.Dir(filepath.Dir(src))
	if !IsClone(a.Clone) {
		// Переустановка установленной командой: клон записала первая установка.
		data, err := os.ReadFile(L.CloneFile)
		if err != nil {
			return "Ежедневное обновление каталога не поставлено: неизвестно, где клон. Запусти установку из клона."
		}
		a.Clone = strings.TrimSpace(string(data))
	}
	err := writeFile(L.TaskFile, taskFile(L, a), 0o644)
	if err == nil {
		err = writeFile(L.TimerFile, timerFile(), 0o644)
	}
	if err == nil {
		err = in.Systemd.Reload()
	}
	if err == nil {
		err = in.Systemd.Start(paths.CatalogTimer)
	}
	if err != nil {
		return fmt.Sprintf("Ежедневное обновление каталога не поставлено: %v. Защита работает на текущем каталоге.", err)
	}
	return "Ежедневное обновление каталога поставлено: раз в сутки git pull в клоне " + a.Clone + "."
}

// installTray ставит автозапуск значка службы. Запущенный значок сам увидит, что служба
// вернулась; в сеанс человека его запускает install.sh, у root к сеансу нет доступа.
// Значок не встал — защита от него не зависит, человек узнаёт почему.
func (in *Installer) installTray() string {
	start := in.Layout.TrayStart
	err := os.MkdirAll(filepath.Dir(start), 0o755)
	if err == nil {
		err = writeFile(start, trayStartFile(in.Layout), 0o644)
	}
	if err != nil {
		return fmt.Sprintf("Значок не поставлен: %v. Защита работает и без него.", err)
	}
	return "Значок службы запускается при входе в рабочий стол."
}

// Remove снимает всё, что поставила установка, кроме самой работающей службы.
// Описание службы удаляется первым: даже если дальше что-то не выйдет, после
// перезагрузки служба не стартует.
func (in *Installer) Remove() error {
	L := in.Layout
	var errs []error
	note := func(err error) {
		if err != nil {
			errs = append(errs, err)
		}
	}
	note(in.Systemd.Halt(paths.CatalogTimer))
	note(in.Systemd.Disable(paths.CatalogTimer))
	note(in.Systemd.Disable(paths.Unit))
	for _, f := range []string{L.UnitFile, L.TimerFile, L.TaskFile, L.TrayStart} {
		note(os.RemoveAll(f))
	}
	note(in.Systemd.Reload())
	in.Systemd.Forget(paths.CatalogService)
	if ours, _ := in.commandIsOurs(); ours {
		note(os.RemoveAll(L.CommandLink))
	}
	note(os.RemoveAll(L.AppDir))
	note(os.RemoveAll(L.LogDir))
	return errors.Join(errs...)
}

// Stop просит systemd остановить службу: служба вызывает его, уже ответив клиенту.
func (in *Installer) Stop() error { return in.Systemd.StopDetached(paths.Unit) }

// Uninstall — снятие на месте от root: когда удаляют через sudo или служба не
// отвечает. Сначала служба, потом правила (иначе сторож вернул бы их), потом файлы.
// Служба не остановилась — правила и файлы остаются: она продолжает защищать,
// удаление можно повторить.
func (in *Installer) Uninstall() error {
	if err := in.Systemd.Halt(paths.Unit); err != nil {
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

// unitFile — описание службы. Она стартует раньше сети (network-pre.target), а
// правила с закрытыми путями, сохранённые прошлым запуском, ставит ExecStartPre —
// ещё до неё самой: после перезагрузки защищённым адресам закрыто с первой секунды.
// Type=notify: сеть поднимается, только когда служба поставила правила и сказала
// «готово». Минус в начале ExecStartPre: файла нет на первом старте. Путь в
// append: — без кавычек: systemd берёт его как есть.
//
// Ставить службу после чего-то сетевого нельзя, даже после systemd-resolved: на
// Ubuntu 22.04 он идёт после networkd, тот — после network-pre, и получается цикл.
// Разрывая его, systemd молча выбрасывает запуск службы, и после перезагрузки защиты
// нет. Домены служба направляет на resolved сама и повторяет, пока он не поднимется.
func unitFile(L paths.Layout) []byte {
	return fmt.Appendf(nil, `[Unit]
Description=vpnlock: защищённые приложения выходят в сеть только через проверенный VPN
DefaultDependencies=no
After=local-fs.target
Before=network-pre.target shutdown.target
Wants=network-pre.target
Conflicts=shutdown.target
RequiresMountsFor=%s %s

[Service]
Type=notify
ExecStartPre=-nft -f %s
ExecStart=%s daemon
Restart=always
RestartSec=1
TimeoutStartSec=60
WatchdogSec=60
StandardOutput=append:%s
StandardError=append:%s

[Install]
WantedBy=multi-user.target
`, unitArg(L.AppDir), unitArg(L.LogDir), unitArg(L.ClosedRules), unitArg(L.Binary), L.LogFile, L.LogFile)
}

// taskFile — обновление каталога от имени того, кто ставил vpnlock.
func taskFile(L paths.Layout, a *Agent) []byte {
	return fmt.Appendf(nil, `[Unit]
Description=vpnlock: обновление каталога
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
User=%s
ExecStart=%s catalog sync %s
`, strconv.Itoa(a.UID), unitArg(L.Binary), unitArg(a.Clone))
}

// timerFile — раз в сутки и после загрузки: если компьютер был выключен, Persistent
// догонит пропущенный запуск.
func timerFile() []byte {
	return []byte(`[Unit]
Description=vpnlock: обновление каталога раз в сутки

[Timer]
OnBootSec=2min
OnCalendar=daily
RandomizedDelaySec=30min
Persistent=true

[Install]
WantedBy=timers.target
`)
}

// trayStartFile — автозапуск значка на любом рабочем столе, для всех пользователей.
func trayStartFile(L paths.Layout) []byte {
	return fmt.Appendf(nil, `[Desktop Entry]
Type=Application
Name=vpnlock
Comment=Значок службы vpnlock: есть значок — служба отвечает
Exec=%s tray
NoDisplay=true
Terminal=false
X-GNOME-Autostart-enabled=true
`, desktopArg(L.Binary))
}

// desktopArg — аргумент строки Exec= файла .desktop: в кавычках, с экранированием по
// спецификации Desktop Entry, процент удвоен.
func desktopArg(s string) string {
	s = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "`", "\\`", `$`, `\$`, `%`, `%%`).Replace(s)
	return strings.ReplaceAll(`"`+s+`"`, `\`, `\\`)
}

// unitArg — аргумент для файла юнита: в кавычках, без подстановок systemd.
func unitArg(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, `%`, `%%`, `$`, `$$`).Replace(s) + `"`
}
