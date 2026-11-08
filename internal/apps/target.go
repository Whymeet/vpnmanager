package apps

import (
	"regexp"
	"strings"
)

// Folders — общие папки Windows: в них лежат разные программы, и защищать
// такую папку целиком нельзя. Пути — без «\» в конце.
type Folders struct {
	System   string   // C:\Windows: всё внутри — системное
	Programs []string // C:\Program Files, C:\Program Files (x86), C:\ProgramData
	Profiles string   // C:\Users: профили и их стандартные папки
}

// profileShared — стандартные папки внутри профиля пользователя. .local\bin —
// общая папка консольных программ: туда ставятся Claude Code, uv и другие, и
// защита одной не должна закрывать соседей.
var profileShared = []string{``, `AppData`, `AppData\Local`, `AppData\Local\Programs`, `AppData\Roaming`, `Desktop`, `Downloads`, `Documents`, `.local\bin`}

// squirrelVersion — папка версии у приложений на Squirrel (Discord, Slack):
// app-1.0.9035 рядом с Update.exe.
var squirrelVersion = regexp.MustCompile(`(?i)^app-[0-9.]+$`)

// InstallTarget — что защищать на Windows для программы exe: её папку
// установки — там же её вспомогательные программы, обновлятор и будущие
// версии, — или, если exe лежит в общей папке, только его самого.
func InstallTarget(exe string, f Folders) string {
	dir := winDir(exe)
	if squirrelVersion.MatchString(winBase(dir)) {
		dir = winDir(dir)
	}
	switch {
	case dir == "" || len(dir) <= 3: // нет папки или корень диска
		return exe
	case f.System != "" && (strings.EqualFold(dir, f.System) || hasPrefixFold(dir, f.System+`\`)):
		return exe
	}
	for _, p := range f.Programs {
		if strings.EqualFold(dir, p) {
			return exe
		}
	}
	if f.Profiles != "" && strings.EqualFold(dir, f.Profiles) {
		return exe
	}
	if f.Profiles != "" && hasPrefixFold(dir, f.Profiles+`\`) {
		// C:\Users\Имя\AppData\Local → «AppData\Local» после имени профиля.
		rest := dir[len(f.Profiles)+1:]
		_, inProfile, _ := strings.Cut(rest, `\`)
		for _, s := range profileShared {
			if strings.EqualFold(inProfile, s) {
				return exe
			}
		}
	}
	return dir
}

func winDir(p string) string {
	if i := strings.LastIndex(p, `\`); i > 0 {
		return p[:i]
	}
	return ""
}

func winBase(p string) string { return p[strings.LastIndex(p, `\`)+1:] }

func hasPrefixFold(s, prefix string) bool {
	return len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix)
}
