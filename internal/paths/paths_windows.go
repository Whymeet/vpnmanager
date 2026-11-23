// Package paths — где установка держит свои файлы.
package paths

import (
	"path/filepath"

	"golang.org/x/sys/windows"
)

// ServiceName — имя службы в диспетчере служб Windows.
const ServiceName = "appguard"

// PlannedStop — своя команда службе (коды 128–255 задаёт служба): «следующую
// остановку начал сам appguard — обновление или удаление». Остановку без неё
// служба считает чужой и выходит с ошибкой, чтобы диспетчер служб запустил её
// снова по правилам восстановления.
const PlannedStop = 200

// Задачи планировщика. NotifyTask при входе любого пользователя запускает
// агента уведомлений в его сеансе, TrayTask — значок службы; CatalogTask раз в
// сутки и при входе того, кто ставил appguard, обновляет каталог из его клона.
const (
	NotifyTask  = "appguard-notify"
	TrayTask    = "appguard-tray"
	CatalogTask = "appguard-catalog"
)

// Layout — пути установки. Все они вне репозитория: настройки принадлежат
// службе, среди них будут адреса VPN-серверов, и закоммитить их нельзя даже
// случайно — git не добавляет файлы за пределами клона.
type Layout struct {
	AppDir     string // программа: Program Files\appguard, менять её может только администратор
	Binary     string // исполняемый файл службы и клиента; его папка — в системном PATH
	QuietExe   string // тот же appguard без окна консоли: его запускают задачи планировщика
	DataDir    string // данные службы: ProgramData\appguard
	StateDir   string // настройки и состояние службы, доступ только у службы и администраторов
	ConfigFile string
	LockFile   string // держит работающая служба: второй экземпляр не стартует
	Socket     string // локальный канал клиент ↔ служба — именованный канал
	LogDir     string
	LogFile    string // вывод службы: старт, остановка, ошибки
	CloneFile  string // из какого клона поставлен appguard: оттуда его обновляет `appguard update`
	ExitsUI    string // окно «Мои VPN» (exits.ps1): в папке программы, менять может только администратор
}

// Traces — что остаётся на диске от установки: есть хоть одно — appguard
// установлен.
func (L Layout) Traces() []string { return []string{L.AppDir, L.DataDir} }

// System — раскладка на живой системе.
func System() Layout {
	return layout(known(windows.FOLDERID_ProgramFiles, `C:\Program Files`),
		known(windows.FOLDERID_ProgramData, `C:\ProgramData`), `\\.\pipe\appguard`)
}

// Under — та же раскладка внутри каталога root: тесты ставят и снимают
// установку во временной папке. Именованные каналы живут не в папках, поэтому
// у канала своё имя — чтобы не столкнуться с работающей службой.
func Under(root string) Layout {
	return layout(filepath.Join(root, "Program Files"), filepath.Join(root, "ProgramData"),
		`\\.\pipe\appguard-`+filepath.Base(root))
}

func layout(programFiles, programData, pipe string) Layout {
	app := filepath.Join(programFiles, "appguard")
	data := filepath.Join(programData, "appguard")
	state := filepath.Join(data, "state")
	logs := filepath.Join(data, "logs")
	return Layout{
		AppDir:     app,
		Binary:     filepath.Join(app, "bin", "appguard.exe"),
		QuietExe:   filepath.Join(app, "bin", "appguardw.exe"),
		DataDir:    data,
		StateDir:   state,
		ConfigFile: filepath.Join(state, "config.json"),
		LockFile:   filepath.Join(state, "daemon.lock"),
		Socket:     pipe,
		LogDir:     logs,
		LogFile:    filepath.Join(logs, "daemon.log"),
		CloneFile:  filepath.Join(app, "clone"),
		ExitsUI:    filepath.Join(app, "exits.ps1"),
	}
}

// known — системная папка по её идентификатору; не нашлась — обычное место.
func known(id *windows.KNOWNFOLDERID, fallback string) string {
	if p, err := windows.KnownFolderPath(id, windows.KF_FLAG_DEFAULT); err == nil && p != "" {
		return p
	}
	return fallback
}

// LegacySystem и LegacyUnder — где лежит установка под прежним именем vpnlock
// (до 0.23.0): её бинарник и настройки. Установка appguard забирает настройки и
// снимает её этим бинарником.
func LegacySystem() (binary, state string) {
	return legacy(known(windows.FOLDERID_ProgramFiles, `C:\Program Files`),
		known(windows.FOLDERID_ProgramData, `C:\ProgramData`))
}

func LegacyUnder(root string) (binary, state string) {
	return legacy(filepath.Join(root, "Program Files"), filepath.Join(root, "ProgramData"))
}

func legacy(programFiles, programData string) (binary, state string) {
	return filepath.Join(programFiles, "vpnlock", "bin", "vpnlock.exe"),
		filepath.Join(programData, "vpnlock", "state")
}
