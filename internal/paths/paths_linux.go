// Package paths — где установка держит свои файлы.
package paths

import "path/filepath"

// Unit — служба vpnlock в systemd. CatalogTimer и CatalogService — ежедневное
// обновление каталога: системный таймер и задача от имени того, кто ставил.
const (
	Unit           = "vpnlock.service"
	CatalogTimer   = "vpnlock-catalog.timer"
	CatalogService = "vpnlock-catalog.service"
)

// Layout — пути установки. Все они вне репозитория: настройки принадлежат
// службе, среди них будут адреса VPN-серверов, и закоммитить их нельзя даже
// случайно — git не добавляет файлы за пределами клона.
type Layout struct {
	AppDir      string // корень установки, принадлежит root
	Binary      string // исполняемый файл службы и клиента
	StateDir    string // настройки и состояние службы, доступ только у root
	ConfigFile  string
	LockFile    string // держит работающая служба: второй экземпляр не стартует
	Socket      string // локальный канал клиент ↔ служба
	UnitFile    string // описание службы для systemd
	TimerFile   string // ежедневное обновление каталога: когда
	TaskFile    string // ежедневное обновление каталога: что и от чьего имени
	ClosedRules string // правила файрвола с закрытыми путями: их грузит старт службы
	TrayStart   string // автозапуск значка: один файл на всех пользователей и все рабочие столы
	LogDir      string
	LogFile     string // вывод службы: старт, остановка, ошибки
	CommandLink string // команда vpnlock в PATH пользователя
	CloneFile   string // из какого клона поставлен vpnlock: оттуда его обновляет `vpnlock update`
}

// Traces — что остаётся на диске от установки: есть хоть одно — vpnlock
// установлен.
func (L Layout) Traces() []string { return []string{L.UnitFile, L.AppDir} }

// System — раскладка на живой системе.
func System() Layout { return Under("/") }

// Under — та же раскладка внутри каталога root: тесты ставят и снимают
// установку во временной папке.
func Under(root string) Layout {
	at := func(elem ...string) string { return filepath.Join(append([]string{root}, elem...)...) }
	app := at("opt", "vpnlock")
	state := filepath.Join(app, "state")
	logs := at("var", "log", "vpnlock")
	units := at("etc", "systemd", "system")
	return Layout{
		AppDir:      app,
		Binary:      filepath.Join(app, "bin", "vpnlock"),
		StateDir:    state,
		ConfigFile:  filepath.Join(state, "config.json"),
		LockFile:    filepath.Join(state, "daemon.lock"),
		Socket:      at("run", "vpnlock.sock"),
		UnitFile:    filepath.Join(units, Unit),
		TimerFile:   filepath.Join(units, CatalogTimer),
		TaskFile:    filepath.Join(units, CatalogService),
		ClosedRules: filepath.Join(state, "closed.nft"),
		TrayStart:   at("etc", "xdg", "autostart", "vpnlock-tray.desktop"),
		LogDir:      logs,
		LogFile:     filepath.Join(logs, "daemon.log"),
		CommandLink: at("usr", "local", "bin", "vpnlock"),
		CloneFile:   filepath.Join(app, "clone"),
	}
}
