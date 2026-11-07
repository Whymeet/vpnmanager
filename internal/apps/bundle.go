package apps

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"howett.net/plist"
)

// ReadBundle читает приложение по пути: пакет .app или консольную программу.
// Идентификатор и имя пакета берутся из Info.plist внутри него: службе,
// которая работает от root, нельзя верить имени, присланному клиентом. Это Read
// на macOS; в файле без привязки к системе, потому что на нём держатся сценарии
// службы (servicetest) на любой системе.
func ReadBundle(path string) (App, error) {
	path = filepath.Clean(path)
	if !filepath.IsAbs(path) {
		return App{}, fmt.Errorf("%s — не путь к приложению (нужно вроде /Applications/Notion.app или ~/.local/bin/claude)", path)
	}
	if !strings.HasSuffix(path, ".app") {
		return readCommand(path)
	}
	fi, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return App{}, fmt.Errorf("приложения %s нет", path)
	}
	if err != nil {
		return App{}, err
	}
	if !fi.IsDir() {
		return App{}, fmt.Errorf("%s — не пакет приложения", path)
	}
	data, err := os.ReadFile(filepath.Join(path, "Contents", "Info.plist"))
	if err != nil {
		return App{}, fmt.Errorf("в %s нет Contents/Info.plist — это не приложение", path)
	}
	var info struct {
		ID          string `plist:"CFBundleIdentifier"`
		DisplayName string `plist:"CFBundleDisplayName"`
		Name        string `plist:"CFBundleName"`
	}
	if _, err := plist.Unmarshal(data, &info); err != nil {
		return App{}, fmt.Errorf("Info.plist приложения %s не читается: %w", path, err)
	}
	if info.ID == "" {
		return App{}, fmt.Errorf("у приложения %s нет идентификатора пакета", path)
	}
	// Имя файла пакета — то, что человек видит в Finder и в списке «Программы».
	name := strings.TrimSuffix(filepath.Base(path), ".app")
	if name == "" {
		name = firstNonEmpty(info.DisplayName, info.Name, info.ID)
	}
	return App{ID: info.ID, Name: name, Path: path}, nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
