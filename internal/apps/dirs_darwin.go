package apps

import (
	"os"
	"os/user"
	"path/filepath"
)

// Dirs — папки «Программы»: системная и пользовательская. Пользовательская —
// у того, кто сел за компьютер: при запуске через sudo это не root.
func Dirs() []string {
	dirs := []string{"/Applications"}
	if home := userHome(); home != "" {
		dirs = append(dirs, filepath.Join(home, "Applications"))
	}
	return dirs
}

func userHome() string {
	if name := os.Getenv("SUDO_USER"); name != "" && os.Geteuid() == 0 {
		if u, err := user.Lookup(name); err == nil {
			return u.HomeDir
		}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return home
}
