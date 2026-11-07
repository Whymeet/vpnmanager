package apps

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"golang.org/x/sys/windows"
)

// Read узнаёт приложение по пути к его исполняемому файлу или по пакету
// Store (package:<семейство>). Защищается папка установки exe — там же его
// вспомогательные программы, обновлятор и будущие версии — или, если exe лежит
// в общей папке, только он сам. Приложение защищено сразу: фильтры ставятся
// на сами файлы и пакет.
func Read(path string) (App, error) {
	if fam, ok := strings.CutPrefix(path, PackagePrefix); ok {
		if !familyName.MatchString(fam) {
			return App{}, fmt.Errorf("%s — не пакет Store", path)
		}
		name, _, _ := strings.Cut(fam, "_")
		return App{ID: PackagePrefix + strings.ToLower(fam), Name: name, Path: PackagePrefix + fam, Instant: true}, nil
	}
	path = filepath.Clean(path)
	if !filepath.IsAbs(path) || !strings.EqualFold(filepath.Ext(path), ".exe") {
		return App{}, fmt.Errorf(`%s — не путь к программе (нужно вроде C:\Program Files\Notion\Notion.exe)`, path)
	}
	fi, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return App{}, fmt.Errorf("программы %s нет", path)
	}
	if err != nil {
		return App{}, err
	}
	if fi.IsDir() {
		return App{}, fmt.Errorf("%s — папка, а не программа", path)
	}
	target := InstallTarget(path, systemFolders())
	name := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	return App{ID: strings.ToLower(target), Name: name, Path: target, Instant: true, Exe: filepath.Base(path)}, nil
}

// Dirs — папки меню «Пуск»: общая и пользователя.
func Dirs() []string {
	var dirs []string
	for _, id := range []*windows.KNOWNFOLDERID{windows.FOLDERID_CommonPrograms, windows.FOLDERID_Programs} {
		if p, err := windows.KnownFolderPath(id, windows.KF_FLAG_DEFAULT); err == nil && p != "" {
			dirs = append(dirs, p)
		}
	}
	return dirs
}

// Scan — установленные программы: ярлыки меню «Пуск» в папках dirs и
// приложения Store. Path у программы из ярлыка — её exe, ID — то, что служба
// будет защищать, поэтому одна программа из двух ярлыков остаётся одной.
// Список отсортирован по имени.
func Scan(dirs []string) []App {
	var found []App
	seen := map[string]bool{}
	f := systemFolders()
	for _, dir := range dirs {
		filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.EqualFold(filepath.Ext(p), ".lnk") {
				return nil
			}
			name := strings.TrimSuffix(d.Name(), filepath.Ext(d.Name()))
			exe := shortcutTarget(p)
			if exe == "" || skipShortcut(name, exe, f) {
				return nil
			}
			id := strings.ToLower(InstallTarget(exe, f))
			if !seen[id] {
				seen[id] = true
				found = append(found, App{ID: id, Name: name, Path: exe, Instant: true})
			}
			return nil
		})
	}
	for _, a := range storeApps() {
		if !seen[a.ID] {
			seen[a.ID] = true
			found = append(found, a)
		}
	}
	slices.SortFunc(found, func(a, b App) int {
		if c := strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name)); c != 0 {
			return c
		}
		return strings.Compare(a.Path, b.Path)
	})
	return found
}

// shortcutTarget — exe, на который ведёт ярлык; пусто — не программа или её нет.
func shortcutTarget(lnk string) string {
	fi, err := os.Stat(lnk)
	if err != nil || fi.Size() > 1<<20 {
		return ""
	}
	data, err := os.ReadFile(lnk)
	if err != nil {
		return ""
	}
	l, err := ParseLink(data)
	if err != nil {
		return ""
	}
	for _, p := range []string{l.Target, expandEnv(l.EnvTarget)} {
		if p == "" || !strings.EqualFold(filepath.Ext(p), ".exe") {
			continue
		}
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p
		}
	}
	return ""
}

// skipShortcut — ярлыки, которые защищать незачем: удаление программ и
// системные инструменты Windows.
func skipShortcut(name, exe string, f Folders) bool {
	lower := strings.ToLower(name + " " + filepath.Base(exe))
	for _, w := range []string{"uninstall", "unins0", "удален", "удалить"} {
		if strings.Contains(lower, w) {
			return true
		}
	}
	return f.System != "" && hasPrefixFold(exe, f.System+`\`)
}

func expandEnv(s string) string {
	if s == "" {
		return ""
	}
	src, err := windows.UTF16PtrFromString(s)
	if err != nil {
		return ""
	}
	buf := make([]uint16, 1024)
	n, err := windows.ExpandEnvironmentStrings(src, &buf[0], uint32(len(buf)))
	if err != nil || n == 0 || int(n) > len(buf) {
		return ""
	}
	return windows.UTF16ToString(buf[:n])
}

// storeApps — приложения Store из меню «Пуск». Их отдаёт Get-StartApps: у
// приложения пакета AppID вида «семейство!приложение», а имя — то, что видно
// в «Пуске».
func storeApps() []App {
	sys, err := windows.GetSystemDirectory()
	if err != nil {
		return nil
	}
	ps := filepath.Join(sys, "WindowsPowerShell", "v1.0", "powershell.exe")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, ps, "-NoProfile", "-NonInteractive", "-Command",
		"[Console]::OutputEncoding=[Text.Encoding]::UTF8; Get-StartApps | Where-Object { $_.AppID -like '*!*' } | Select-Object Name,AppID | ConvertTo-Json -Compress").Output()
	if err != nil {
		return nil
	}
	return parseStartApps(out)
}

// systemFolders — общие папки этой системы.
func systemFolders() Folders {
	var f Folders
	f.System, _ = windows.GetWindowsDirectory()
	for _, id := range []*windows.KNOWNFOLDERID{windows.FOLDERID_ProgramFiles, windows.FOLDERID_ProgramFilesX86, windows.FOLDERID_ProgramData} {
		if p, err := windows.KnownFolderPath(id, windows.KF_FLAG_DEFAULT); err == nil && p != "" {
			f.Programs = append(f.Programs, p)
		}
	}
	f.Profiles, _ = windows.KnownFolderPath(windows.FOLDERID_UserProfiles, windows.KF_FLAG_DEFAULT)
	return f
}

// WindowsApps — где лежат пакеты Store.
func WindowsApps() string {
	pf, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, windows.KF_FLAG_DEFAULT)
	if err != nil || pf == "" {
		pf = `C:\Program Files`
	}
	return filepath.Join(pf, "WindowsApps")
}

// PackageDirs — папки установленных версий пакета: Имя_Версия_Архитектура_Ресурс_Издатель.
func PackageDirs(family string) []string {
	name, publisher, ok := strings.Cut(strings.ToLower(family), "_")
	if !ok {
		return nil
	}
	root := WindowsApps()
	entries, _ := os.ReadDir(root)
	var dirs []string
	for _, e := range entries {
		n := strings.ToLower(e.Name())
		if e.IsDir() && strings.HasPrefix(n, name+"_") && strings.HasSuffix(n, "_"+publisher) {
			dirs = append(dirs, filepath.Join(root, e.Name()))
		}
	}
	return dirs
}
