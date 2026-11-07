// Package paths — где установка держит свои файлы.
package paths

import (
	"path/filepath"

	"golang.org/x/sys/windows"
)

// ServiceName — имя службы в диспетчере служб Windows.
const ServiceName = "vpnlock"

// PlannedStop — своя команда службе (коды 128–255 задаёт служба): «следующую
// остановку начал сам vpnlock — обновление или удаление». Остановку без неё
// служба считает чужой и выходит с ошибкой, чтобы диспетчер служб запустил её
// снова по правилам восстановления.
const PlannedStop = 200

// Задачи планировщика. NotifyTask при входе любого пользователя запускает
// агента уведомлений в его сеансе, TrayTask — значок службы; CatalogTask раз в
// сутки и при входе того, кто ставил vpnlock, обновляет каталог из его клона.
const (
	NotifyTask  = "vpnlock-notify"
	TrayTask    = "vpnlock-tray"
	CatalogTask = "vpnlock-catalog"
)

// Layout — пути установки. Все они вне репозитория: настройки принадлежат
// службе, среди них будут адреса VPN-серверов, и закоммитить их нельзя даже
// случайно — git не добавляет файлы за пределами клона.
type Layout struct {
	AppDir     string // программа: Program Files\vpnlock, менять её может только администратор
	Binary     string // исполняемый файл службы и клиента; его папка — в системном PATH
	QuietExe   string // тот же vpnlock без окна консоли: его запускают задачи планировщика
	DataDir    string // данные службы: ProgramData\vpnlock
	StateDir   string // настройки и состояние службы, доступ только у службы и администраторов
	ConfigFile string
	LockFile   string // держит работающая служба: второй экземпляр не стартует
	Socket     string // локальный канал клиент ↔ служба — именованный канал
	LogDir     string
	LogFile    string // вывод службы: старт, остановка, ошибки
	CloneFile  string // из какого клона поставлен vpnlock: оттуда его обновляет `vpnlock update`
}

// Traces — что остаётся на диске от установки: есть хоть одно — vpnlock
// установлен.
func (L Layout) Traces() []string { return []string{L.AppDir, L.DataDir} }

// System — раскладка на живой системе.
func System() Layout {
	return layout(known(windows.FOLDERID_ProgramFiles, `C:\Program Files`),
		known(windows.FOLDERID_ProgramData, `C:\ProgramData`), `\\.\pipe\vpnlock`)
}

// Under — та же раскладка внутри каталога root: тесты ставят и снимают
// установку во временной папке. Именованные каналы живут не в папках, поэтому
// у канала своё имя — чтобы не столкнуться с работающей службой.
func Under(root string) Layout {
	return layout(filepath.Join(root, "Program Files"), filepath.Join(root, "ProgramData"),
		`\\.\pipe\vpnlock-`+filepath.Base(root))
}

func layout(programFiles, programData, pipe string) Layout {
	app := filepath.Join(programFiles, "vpnlock")
	data := filepath.Join(programData, "vpnlock")
	state := filepath.Join(data, "state")
	logs := filepath.Join(data, "logs")
	return Layout{
		AppDir:     app,
		Binary:     filepath.Join(app, "bin", "vpnlock.exe"),
		QuietExe:   filepath.Join(app, "bin", "vpnlockw.exe"),
		DataDir:    data,
		StateDir:   state,
		ConfigFile: filepath.Join(state, "config.json"),
		LockFile:   filepath.Join(state, "daemon.lock"),
		Socket:     pipe,
		LogDir:     logs,
		LogFile:    filepath.Join(logs, "daemon.log"),
		CloneFile:  filepath.Join(app, "clone"),
	}
}

// known — системная папка по её идентификатору; не нашлась — обычное место.
func known(id *windows.KNOWNFOLDERID, fallback string) string {
	if p, err := windows.KnownFolderPath(id, windows.KF_FLAG_DEFAULT); err == nil && p != "" {
		return p
	}
	return fallback
}
