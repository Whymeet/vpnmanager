package install

import (
	"os"
	"path/filepath"
	"testing"
)

// Клон на Windows: Git для Windows по умолчанию кладёт файлы с CRLF. Без этого
// установка не запоминала клон, а `appguard update` и `appguard apply` его не
// находили даже из его же папки.
func TestIsCloneAcceptsWindowsLineEndings(t *testing.T) {
	for name, gomod := range map[string]string{
		"LF":   "module appguard\n\ngo 1.26\n",
		"CRLF": "module appguard\r\n\r\ngo 1.26\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0o644); err != nil {
				t.Fatal(err)
			}
			if IsClone(dir) {
				t.Fatal("без папки setup — не клон")
			}
			if err := os.Mkdir(filepath.Join(dir, "setup"), 0o755); err != nil {
				t.Fatal(err)
			}
			if !IsClone(dir) {
				t.Fatal("клон не узнан")
			}
		})
	}
	for name, gomod := range map[string]string{
		"другой модуль":      "module appguardx\r\n",
		"модуль не в начале": "// appguard\nmodule appguard\n",
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0o644)
			os.Mkdir(filepath.Join(dir, "setup"), 0o755)
			if IsClone(dir) {
				t.Fatal("чужая папка принята за клон")
			}
		})
	}
}
