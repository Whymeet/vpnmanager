// Package apps — приложения: что установлено и как узнать приложение по пути
// (пакет .app или консольная программа на macOS, исполняемый файл на Windows,
// программа или служба systemd на Linux).
package apps

// PackagePrefix — так на Windows записывается приложение Store:
// package:<семейство пакета>.
const PackagePrefix = "package:"

// CommandPrefix — идентификатор консольной программы на macOS:
// cmd:<что защищается>.
const CommandPrefix = "cmd:"

// ServicePrefix — так на Linux записывается служба systemd:
// systemd:<имя>.service.
const ServicePrefix = "systemd:"

// App — приложение, как его видит пользователь.
type App struct {
	ID   string // macOS: CFBundleIdentifier, например notion.id; Windows: что защищается, строчными
	Name string // как в Finder или в меню «Пуск»: Notion
	// Path — пакет .app на macOS. На Windows — папка установки, exe или
	// package:<семейство>; в списке установленных — exe, на который ведёт ярлык.
	Path string
	// Instant — приложение защищено сразу, без обучения: на Windows фильтры
	// стоят на сам исполняемый файл, и учить его адреса не нужно.
	Instant bool
	// Exe — на Windows: имя исполняемого файла (Notion.exe), по нему приложение
	// находится в каталоге. У пакета Store пусто.
	Exe string
	// Command — консольная программа на macOS (Claude Code) и любая программа на
	// Linux: Path — папка её установки или сам файл (CommandTarget), Name — имя
	// команды (claude). Служба systemd — тоже: Path — systemd:<имя>.service.
	Command bool
}
