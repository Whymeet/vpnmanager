// Package paths — где установка держит свои файлы.
package paths

import "path/filepath"

// Label — имя службы в launchd.
const Label = "com.appguard.daemon"

// CatalogLabel — имя ежедневной задачи каталога в launchd: она работает в
// сеансе ученика, от его имени.
const CatalogLabel = "com.appguard.catalog"

// AgentPlist — описание ежедневной задачи каталога в домашнем каталоге home.
func AgentPlist(home string) string {
	return filepath.Join(home, "Library", "LaunchAgents", CatalogLabel+".plist")
}

// TrayLabel — имя значка службы в launchd: он работает в сеансе ученика.
const TrayLabel = "com.appguard.tray"

// TrayPlist — описание значка в домашнем каталоге home.
func TrayPlist(home string) string {
	return filepath.Join(home, "Library", "LaunchAgents", TrayLabel+".plist")
}

// TrayLog — вывод значка в домашнем каталоге home.
func TrayLog(home string) string {
	return filepath.Join(home, "Library", "Logs", "appguard-tray.log")
}

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
	Plist       string // описание службы для launchd
	LogDir      string
	LogFile     string // вывод службы: старт, остановка, ошибки
	CommandLink string // команда appguard в PATH пользователя
	AgentFile   string // чья ежедневная задача каталога стоит: для удаления
	CloneFile   string // из какого клона поставлен appguard: оттуда его обновляет `appguard update`
}

// Traces — что остаётся на диске от установки: есть хоть одно — appguard
// установлен.
func (L Layout) Traces() []string { return []string{L.Plist, L.AppDir} }

// System — раскладка на живой системе.
func System() Layout { return Under("/") }

// Under — та же раскладка внутри каталога root: тесты ставят и снимают
// установку во временной папке.
func Under(root string) Layout {
	at := func(elem ...string) string { return filepath.Join(append([]string{root}, elem...)...) }
	app := at("Library", "Application Support", "appguard")
	state := filepath.Join(app, "state")
	logs := at("Library", "Logs", "appguard")
	return Layout{
		AppDir:      app,
		Binary:      filepath.Join(app, "bin", "appguard"),
		StateDir:    state,
		ConfigFile:  filepath.Join(state, "config.json"),
		LockFile:    filepath.Join(state, "daemon.lock"),
		Socket:      at("var", "run", "appguard.sock"),
		Plist:       at("Library", "LaunchDaemons", Label+".plist"),
		LogDir:      logs,
		LogFile:     filepath.Join(logs, "daemon.log"),
		CommandLink: at("usr", "local", "bin", "appguard"),
		AgentFile:   filepath.Join(app, "catalog-agent.json"),
		CloneFile:   filepath.Join(app, "clone"),
	}
}

// LegacySystem и LegacyUnder — где лежит установка под прежним именем vpnlock
// (до 0.23.0): её бинарник и настройки. Установка appguard забирает настройки и
// снимает её этим бинарником.
func LegacySystem() (binary, state string) { return LegacyUnder("/") }

func LegacyUnder(root string) (binary, state string) {
	app := filepath.Join(root, "Library", "Application Support", "vpnlock")
	return filepath.Join(app, "bin", "vpnlock"), filepath.Join(app, "state")
}
