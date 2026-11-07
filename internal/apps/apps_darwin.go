package apps

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// Read читает приложение по пути: пакет .app или консольную программу.
func Read(path string) (App, error) { return ReadBundle(path) }

// Scan находит приложения в папках dirs. В каждой папке смотрит сам список и
// ещё один уровень вглубь: некоторые приложения лежат в своей папке
// (/Applications/Adobe Photoshop 2025/Adobe Photoshop 2025.app). Дубли по
// идентификатору остаются одним приложением; список отсортирован по имени.
func Scan(dirs []string) []App {
	var found []App
	seen := map[string]bool{}
	for _, dir := range dirs {
		walk(dir, 2, func(path string) {
			if a, err := Read(path); err == nil && !seen[a.ID] {
				seen[a.ID] = true
				found = append(found, a)
			}
		})
	}
	slices.SortFunc(found, func(a, b App) int {
		if c := strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name)); c != 0 {
			return c
		}
		return strings.Compare(a.Path, b.Path)
	})
	return found
}

// walk зовёт visit для каждого пакета .app в dir и в папках глубиной до depth.
// Внутрь пакетов не заходит.
func walk(dir string, depth int, visit func(path string)) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		path := filepath.Join(dir, e.Name())
		if strings.HasSuffix(e.Name(), ".app") {
			visit(path)
			continue
		}
		if depth > 1 && isDir(path) && !strings.HasPrefix(e.Name(), ".") {
			walk(path, depth-1, visit)
		}
	}
}

// isDir — каталог, в том числе по символической ссылке (Safari лежит в
// /Applications ссылкой на системный том).
func isDir(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.IsDir()
}
