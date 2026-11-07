package procs

import (
	"slices"
	"strings"
)

// Target — что защищается у приложения Windows (apps.InstallTarget): папка
// установки, сам exe или папки пакета Store.
type Target struct {
	Path        string
	Dir         bool     // Path — папка установки
	PackageDirs []string // папки установленных версий пакета Store
}

// Has — программа exe относится к приложению: лежит в папке установки или в
// папке пакета либо это сам exe. Регистр в путях Windows не важен.
func (t Target) Has(exe string) bool {
	under := func(dir string) bool {
		dir = strings.TrimRight(dir, `\`) + `\`
		return len(exe) > len(dir) && strings.EqualFold(exe[:len(dir)], dir)
	}
	switch {
	case len(t.PackageDirs) > 0:
		return slices.ContainsFunc(t.PackageDirs, under)
	case t.Dir:
		return under(t.Path)
	}
	return strings.EqualFold(exe, t.Path)
}
