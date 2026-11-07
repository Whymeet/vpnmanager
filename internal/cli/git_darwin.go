package cli

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// gitPath — git, который не позовёт установщик инструментов разработчика:
// /usr/bin/git без них показывает окно, а задача работает в фоне.
func gitPath() (string, error) {
	for _, p := range []string{"/opt/homebrew/bin/git", "/usr/local/bin/git"} {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	if out, err := exec.Command("/usr/bin/xcode-select", "-p").Output(); err == nil {
		if _, err := os.Stat(filepath.Join(strings.TrimSpace(string(out)), "usr", "bin", "git")); err == nil {
			return "/usr/bin/git", nil
		}
	}
	return "", errors.New("git не найден: нужны инструменты командной строки Xcode (xcode-select --install) или git из Homebrew")
}

// quiet — на macOS окон у git нет, делать нечего.
func quiet(*exec.Cmd) {}
