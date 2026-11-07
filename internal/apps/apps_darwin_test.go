package apps

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// bundle создаёт пакет приложения с Info.plist.
func bundle(t *testing.T, dir, folder, id string) string {
	t.Helper()
	path := filepath.Join(dir, folder+".app")
	if err := os.MkdirAll(filepath.Join(path, "Contents"), 0o755); err != nil {
		t.Fatal(err)
	}
	plist := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
	<key>CFBundleIdentifier</key><string>` + id + `</string>
	<key>CFBundleName</key><string>Внутреннее имя</string>
</dict></plist>`
	if err := os.WriteFile(filepath.Join(path, "Contents", "Info.plist"), []byte(plist), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestReadTakesIDFromThePackageAndNameFromFinder(t *testing.T) {
	path := bundle(t, t.TempDir(), "Notion", "notion.id")
	a, err := Read(path)
	if err != nil {
		t.Fatal(err)
	}
	if a.ID != "notion.id" || a.Name != "Notion" || a.Path != path {
		t.Fatalf("%+v", a)
	}
}

func TestReadRefusesWhatIsNotAnApp(t *testing.T) {
	dir := t.TempDir()
	noPlist := filepath.Join(dir, "Empty.app")
	os.MkdirAll(noPlist, 0o755)
	file := filepath.Join(dir, "File.app")
	os.WriteFile(file, []byte("x"), 0o644)
	os.WriteFile(filepath.Join(dir, "readme"), []byte("x"), 0o644) // не исполняемый
	for path, want := range map[string]string{
		"relative/Notion.app":                  "не путь к приложению",
		filepath.Join(dir, "notes.txt"):        "программы",
		filepath.Join(dir, "readme"):           "не программа",
		filepath.Join(dir, "Missing.app"):      "нет",
		file:                                   "не пакет приложения",
		noPlist:                                "это не приложение",
		filepath.Join(dir, "x", "..", "A.app"): "нет",
	} {
		if _, err := Read(path); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: ошибка %v, ждали со словами %q", path, err, want)
		}
	}
}

func TestScanFindsAppsInFoldersAndSkipsDuplicates(t *testing.T) {
	sys, user := t.TempDir(), t.TempDir()
	bundle(t, sys, "Zoom", "us.zoom.xos")
	bundle(t, sys, "notion", "notion.id")
	bundle(t, filepath.Join(sys, "Adobe Photoshop 2025"), "Adobe Photoshop 2025", "com.adobe.Photoshop")
	bundle(t, filepath.Join(sys, "Utilities", "deep", "deeper"), "TooDeep", "too.deep")
	bundle(t, user, "Notion Copy", "notion.id") // тот же идентификатор в пользовательской папке
	os.MkdirAll(filepath.Join(sys, "Plain Folder"), 0o755)
	// Внутрь пакетов не заходим: приложение во вложении — не отдельное приложение.
	bundle(t, filepath.Join(sys, "Zoom.app", "Contents", "Frameworks"), "Helper", "us.zoom.helper")

	var names []string
	for _, a := range Scan([]string{sys, user, filepath.Join(sys, "нет такой")}) {
		names = append(names, a.Name)
	}
	want := "Adobe Photoshop 2025, notion, Zoom"
	if got := strings.Join(names, ", "); got != want {
		t.Fatalf("найдено %q, ждали %q", got, want)
	}
}

func TestScanFollowsSymlinkedApps(t *testing.T) {
	real, apps := t.TempDir(), t.TempDir()
	target := bundle(t, real, "Safari", "com.apple.Safari")
	if err := os.Symlink(target, filepath.Join(apps, "Safari.app")); err != nil {
		t.Fatal(err)
	}
	found := Scan([]string{apps})
	if len(found) != 1 || found[0].ID != "com.apple.Safari" {
		t.Fatalf("%+v", found)
	}
}

// Настоящая система автора: приложения читаются, и у Notion — его идентификатор.
func TestScanOnThisMac(t *testing.T) {
	if _, err := os.Stat("/Applications/Notion.app"); err != nil {
		t.Skip("Notion не установлен")
	}
	for _, a := range Scan([]string{"/Applications"}) {
		if a.Name == "Notion" {
			t.Logf("Notion: %+v", a)
			return
		}
	}
	t.Fatal("Notion установлен, но в списке его нет")
}

// Консольная программа по ссылке, как Claude Code: имя — как её вызывают,
// защищается папка версий, куда ложатся и следующие версии.
func TestReadCommandByLink(t *testing.T) {
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	versions := filepath.Join(home, ".local", "share", "claude", "versions")
	bin := filepath.Join(home, ".local", "bin")
	os.MkdirAll(versions, 0o755)
	os.MkdirAll(bin, 0o755)
	if err := os.WriteFile(filepath.Join(versions, "2.1.301"), []byte("\xcf\xfa\xed\xfe"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(bin, "claude")
	if err := os.Symlink(filepath.Join(versions, "2.1.301"), link); err != nil {
		t.Fatal(err)
	}
	a, err := Read(link)
	if err != nil {
		t.Fatal(err)
	}
	if a.Name != "claude" || a.Path != versions || a.ID != CommandPrefix+versions || !a.Command {
		t.Fatalf("%+v", a)
	}
}
