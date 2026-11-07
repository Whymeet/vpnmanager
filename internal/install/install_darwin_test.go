package install

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"vpnlock/internal/paths"
)

// fakeLaunchd записывает вызовы вместо настоящего launchd. bootoutErr — что
// ответит остановка службы.
type fakeLaunchd struct {
	calls      []string
	bootoutErr error
	// userErr — что ответит загрузка в сеанс пользователя для такого plist.
	userErr func(plist string) error
}

func (f *fakeLaunchd) Bootstrap(plist string) error {
	f.calls = append(f.calls, "bootstrap "+plist)
	return nil
}
func (f *fakeLaunchd) Bootout(label string) error {
	f.calls = append(f.calls, "bootout "+label)
	return f.bootoutErr
}
func (f *fakeLaunchd) BootoutDetached(label string) error {
	f.calls = append(f.calls, "bootout-detached "+label)
	return nil
}
func (f *fakeLaunchd) Enable(label string) error {
	f.calls = append(f.calls, "enable "+label)
	return nil
}
func (f *fakeLaunchd) BootstrapUser(uid int, plist string) error {
	f.calls = append(f.calls, fmt.Sprintf("bootstrap gui/%d %s", uid, plist))
	if f.userErr != nil {
		return f.userErr(plist)
	}
	return nil
}
func (f *fakeLaunchd) BootoutUser(uid int, label string) error {
	f.calls = append(f.calls, fmt.Sprintf("bootout gui/%d/%s", uid, label))
	return nil
}

func setup(t *testing.T) (*Installer, *fakeLaunchd, string) {
	t.Helper()
	root := t.TempDir()
	src := filepath.Join(root, "clone", "bin", "vpnlock")
	os.MkdirAll(filepath.Dir(src), 0o755)
	os.WriteFile(src, []byte("сборка 1"), 0o755)
	l := &fakeLaunchd{}
	return &Installer{Layout: paths.Under(root), Launchd: l}, l, src
}

func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

func mode(t *testing.T, path string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm()
}

func TestInstallPutsServiceInPlace(t *testing.T) {
	in, l, src := setup(t)
	L := in.Layout
	if err := in.Install(src); err != nil {
		t.Fatal(err)
	}

	if data, _ := os.ReadFile(L.Binary); string(data) != "сборка 1" {
		t.Fatalf("в установке не тот файл: %q", data)
	}
	if m := mode(t, L.Binary); m != 0o755 {
		t.Fatalf("права исполняемого файла %v", m)
	}
	if m := mode(t, L.StateDir); m != 0o700 {
		t.Fatalf("каталог настроек %v, ждали 0700", m)
	}
	if target, err := os.Readlink(L.CommandLink); err != nil || target != L.Binary {
		t.Fatalf("команда vpnlock ведёт на %q (%v)", target, err)
	}

	plist, _ := os.ReadFile(L.Plist)
	for _, want := range []string{paths.Label, L.Binary, "<string>daemon</string>", "RunAtLoad", "KeepAlive"} {
		if !strings.Contains(string(plist), want) {
			t.Fatalf("в plist нет %q:\n%s", want, plist)
		}
	}
	if out, err := exec.Command("plutil", "-lint", L.Plist).CombinedOutput(); err != nil {
		t.Fatalf("launchd не примет plist: %s", out)
	}

	want := []string{"bootout " + paths.Label, "enable " + paths.Label, "bootstrap " + L.Plist}
	if !slices.Equal(l.calls, want) {
		t.Fatalf("launchd: %v, ждали %v", l.calls, want)
	}
}

func TestReinstallUpdatesBinaryAndKeepsSettings(t *testing.T) {
	in, _, src := setup(t)
	L := in.Layout
	if err := in.Install(src); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(L.ConfigFile, []byte(`{"schema": 1}`), 0o600)

	os.WriteFile(src, []byte("сборка 2"), 0o755)
	if err := in.Install(src); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(L.Binary); string(data) != "сборка 2" {
		t.Fatalf("исполняемый файл не обновился: %q", data)
	}
	if data, _ := os.ReadFile(L.ConfigFile); string(data) != `{"schema": 1}` {
		t.Fatalf("повторная установка тронула настройки: %q", data)
	}
}

func TestInstallLeavesForeignCommandAndChangesNothing(t *testing.T) {
	in, l, src := setup(t)
	L := in.Layout
	os.MkdirAll(filepath.Dir(L.CommandLink), 0o755)
	os.WriteFile(L.CommandLink, []byte("чужой скрипт"), 0o755)

	err := in.Install(src)
	if err == nil || !strings.Contains(err.Error(), L.CommandLink) {
		t.Fatalf("ошибка %v, ждали с путём %s", err, L.CommandLink)
	}
	if data, _ := os.ReadFile(L.CommandLink); string(data) != "чужой скрипт" {
		t.Fatal("чужой файл перезаписан")
	}
	if exists(L.AppDir) || exists(L.Plist) || len(l.calls) > 0 {
		t.Fatalf("установка начала менять систему: каталог %v, plist %v, launchd %v", exists(L.AppDir), exists(L.Plist), l.calls)
	}
}

func TestUninstallRemovesEverythingAndReinstallIsClean(t *testing.T) {
	in, l, src := setup(t)
	L := in.Layout
	if err := in.Install(src); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(L.ConfigFile, []byte(`{"schema": 1}`), 0o600)
	os.WriteFile(L.LogFile, []byte("лог"), 0o644)
	l.calls = nil

	if err := in.Uninstall(); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{L.Plist, L.AppDir, L.LogDir, L.CommandLink} {
		if exists(p) {
			t.Fatalf("после удаления осталось %s", p)
		}
	}
	if !exists(filepath.Dir(L.CommandLink)) {
		t.Fatal("удалён системный каталог команды — он не наш")
	}
	if !slices.Contains(l.calls, "bootout "+paths.Label) {
		t.Fatalf("служба не снята с launchd: %v", l.calls)
	}

	if err := in.Install(src); err != nil {
		t.Fatalf("повторная установка после удаления: %v", err)
	}
	if exists(L.ConfigFile) {
		t.Fatal("после удаления и новой установки всплыли старые настройки")
	}
}

func TestDisabledReadsLaunchctlOutput(t *testing.T) {
	out := `disabled services = {
		"com.apple.ftpd" => disabled
		"com.vpnlock.daemon" => enabled
		"com.example.old" => true
	}
`
	for label, want := range map[string]bool{
		"com.apple.ftpd":     true,
		"com.vpnlock.daemon": false,
		"com.example.old":    true,
		"com.absent":         false,
	} {
		if got := disabled(out, label); got != want {
			t.Errorf("%s: запрещена %v, ждали %v", label, got, want)
		}
	}
}

func TestRemoveKeepsForeignCommand(t *testing.T) {
	in, _, src := setup(t)
	L := in.Layout
	if err := in.Install(src); err != nil {
		t.Fatal(err)
	}
	os.Remove(L.CommandLink)
	os.Symlink("/opt/elsewhere/vpnlock", L.CommandLink)

	if err := in.Remove(); err != nil {
		t.Fatal(err)
	}
	if target, _ := os.Readlink(L.CommandLink); target != "/opt/elsewhere/vpnlock" {
		t.Fatal("удаление сняло чужую команду")
	}
}

func TestInstallBringsTheCloneCatalog(t *testing.T) {
	in, _, src := setup(t)
	repo := filepath.Dir(filepath.Dir(src)) // src — <клон>/bin/vpnlock
	os.MkdirAll(filepath.Join(repo, "catalog"), 0o755)
	cat := filepath.Join(repo, "catalog", "catalog.json")
	os.WriteFile(cat, []byte(`{"format": 1, "updated": "2026-10-15", "apps": [{"name": "Notion", "macos": {"id": "notion.id"}}]}`), 0o644)

	if err := in.Install(src); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(in.Layout.StateDir, "catalog.json"))
	if err != nil || !strings.Contains(string(got), "notion.id") || !strings.Contains(in.Note, "1 приложение") {
		t.Fatalf("каталог не установлен: %v %q", err, in.Note)
	}
	if m := mode(t, filepath.Join(in.Layout.StateDir, "catalog.json")); m != 0o600 {
		t.Fatalf("права каталога службы %v", m)
	}

	// Каталог новее формата не ставится: служба остаётся на прежнем.
	os.WriteFile(cat, []byte(`{"format": 99, "apps": []}`), 0o644)
	if err := in.Install(src); err != nil {
		t.Fatal(err)
	}
	if again, _ := os.ReadFile(filepath.Join(in.Layout.StateDir, "catalog.json")); string(again) != string(got) || !strings.Contains(in.Note, "обнови инструмент") {
		t.Fatalf("каталог новее формата поставлен: %q", in.Note)
	}
}

func TestInstallPutsCatalogAgentForTheSudoUser(t *testing.T) {
	in, l, src := setup(t)
	home := t.TempDir()
	in.Agent = &Agent{UID: 501, GID: 20, Home: home}
	if err := in.Install(src); err != nil {
		t.Fatal(err)
	}
	plist := filepath.Join(home, "Library", "LaunchAgents", paths.CatalogLabel+".plist")
	data, err := os.ReadFile(plist)
	if err != nil {
		t.Fatal(err)
	}
	clone := filepath.Dir(filepath.Dir(src))
	for _, want := range []string{paths.CatalogLabel, in.Layout.Binary, "<string>catalog</string>", "<string>sync</string>", "<string>" + clone + "</string>", "<integer>86400</integer>", "RunAtLoad"} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("в задаче нет %q:\n%s", want, data)
		}
	}
	if !slices.Contains(l.calls, "bootstrap gui/501 "+plist) {
		t.Fatalf("задача не загружена в сеанс пользователя: %v", l.calls)
	}
	if !strings.Contains(in.Note, "Ежедневное обновление каталога поставлено") {
		t.Fatalf("заметка: %q", in.Note)
	}

	// Удаление снимает задачу.
	if err := in.Uninstall(); err != nil {
		t.Fatal(err)
	}
	if exists(plist) || exists(in.Layout.AgentFile) {
		t.Fatal("задача каталога осталась после удаления")
	}
	if !slices.Contains(l.calls, "bootout gui/501/"+paths.CatalogLabel) {
		t.Fatalf("задача не выгружена: %v", l.calls)
	}
}

// sudo vpnlock uninstall: правила снимаются после остановки службы (иначе сторож
// вернул бы их) и до удаления файлов — токен pf лежит в каталоге службы, и
// без него pf осталась бы ссылка vpnlock.
func TestUninstallClearsRulesBetweenStopAndFiles(t *testing.T) {
	in, l, src := setup(t)
	L := in.Layout
	if err := in.Install(src); err != nil {
		t.Fatal(err)
	}
	token := filepath.Join(L.StateDir, "pf.token")
	os.WriteFile(token, []byte("123\n"), 0o600)
	l.calls = nil
	cleared := false
	in.Clear = func() error {
		cleared = true
		if !slices.Contains(l.calls, "bootout "+paths.Label) || !exists(token) || exists(L.Plist) {
			t.Errorf("правила снимаются не вовремя: launchd %v, токен %v, plist %v", l.calls, exists(token), exists(L.Plist))
		}
		return nil
	}
	if err := in.Uninstall(); err != nil {
		t.Fatal(err)
	}
	if !cleared || exists(L.AppDir) {
		t.Fatalf("правила сняты: %v, каталог службы остался: %v", cleared, exists(L.AppDir))
	}
}

// Служба не остановилась — правила и файлы на месте: она продолжает защищать,
// удаление можно повторить. Описание службы уже снято: после перезагрузки она
// не стартует.
func TestUninstallKeepsRulesWhenServiceDoesNotStop(t *testing.T) {
	in, l, src := setup(t)
	L := in.Layout
	if err := in.Install(src); err != nil {
		t.Fatal(err)
	}
	l.bootoutErr = errors.New("5: Input/output error")
	in.Clear = func() error {
		t.Error("правила сняты, хотя служба работает")
		return nil
	}
	if err := in.Uninstall(); err == nil {
		t.Fatal("удаление прошло, хотя служба не остановилась")
	}
	if !exists(L.AppDir) || exists(L.Plist) {
		t.Fatalf("каталог службы %v, plist %v", exists(L.AppDir), exists(L.Plist))
	}
}

func TestInstallWithoutSudoUserSaysNoAgent(t *testing.T) {
	in, _, src := setup(t)
	if err := in.Install(src); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(in.Note, "Ежедневное обновление каталога не поставлено") {
		t.Fatalf("заметка: %q", in.Note)
	}
}

func TestInstallPutsTrayForTheSudoUser(t *testing.T) {
	in, l, src := setup(t)
	home := t.TempDir()
	in.Agent = &Agent{UID: 501, GID: 20, Home: home}
	if err := in.Install(src); err != nil {
		t.Fatal(err)
	}
	plist := paths.TrayPlist(home)
	data, err := os.ReadFile(plist)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, want := range []string{
		paths.TrayLabel, in.Layout.Binary, "<string>tray</string>", "RunAtLoad", "KeepAlive",
		"<key>LimitLoadToSessionType</key>\n\t<string>Aqua</string>", filepath.Join(home, "Library", "Logs", "vpnlock-tray.log"),
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("в значке нет %q:\n%s", want, text)
		}
	}
	// С AbandonProcessGroup osascript пережил бы vpnlock tray и значок врал бы.
	for _, wrong := range []string{"AbandonProcessGroup", "Background"} {
		if strings.Contains(text, wrong) {
			t.Fatalf("в значке %q:\n%s", wrong, text)
		}
	}
	if out, err := exec.Command("plutil", "-lint", plist).CombinedOutput(); err != nil {
		t.Fatalf("launchd не примет plist: %s", out)
	}
	if !slices.Contains(l.calls, "bootstrap gui/501 "+plist) {
		t.Fatalf("значок не загружен в сеанс пользователя: %v", l.calls)
	}
	if !strings.Contains(in.Note, "Значок vpnlock — в строке меню") {
		t.Fatalf("заметка: %q", in.Note)
	}
}

// Повторная установка снимает прежний значок раньше, чем ставит новый: иначе launchd
// откажет, а работал бы старый файл.
func TestReinstallReplacesTrayWithoutDuplicates(t *testing.T) {
	in, l, src := setup(t)
	home := t.TempDir()
	in.Agent = &Agent{UID: 501, GID: 20, Home: home}
	if err := in.Install(src); err != nil {
		t.Fatal(err)
	}
	l.calls = nil
	if err := in.Install(src); err != nil {
		t.Fatal(err)
	}
	load := "bootstrap gui/501 " + paths.TrayPlist(home)
	unload := "bootout gui/501/" + paths.TrayLabel
	if slices.Index(l.calls, unload) < 0 || slices.Index(l.calls, unload) > slices.Index(l.calls, load) {
		t.Fatalf("прежний значок не снят первым: %v", l.calls)
	}
	loads := 0
	for _, c := range l.calls {
		if c == load {
			loads++
		}
	}
	if loads != 1 {
		t.Fatalf("значок загружен %d раз: %v", loads, l.calls)
	}
	entries, err := os.ReadDir(filepath.Dir(paths.TrayPlist(home)))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("в LaunchAgents %d файлов: %v", len(entries), entries)
	}
}

func TestUninstallRemovesTray(t *testing.T) {
	for name, uninstall := range map[string]func(in *Installer) error{
		"на месте":     (*Installer).Uninstall,
		"через службу": (*Installer).Remove,
	} {
		t.Run(name, func(t *testing.T) {
			in, l, src := setup(t)
			home := t.TempDir()
			in.Agent = &Agent{UID: 501, GID: 20, Home: home}
			if err := in.Install(src); err != nil {
				t.Fatal(err)
			}
			log := paths.TrayLog(home)
			os.MkdirAll(filepath.Dir(log), 0o755)
			os.WriteFile(log, []byte("вывод"), 0o644)
			l.calls = nil
			if err := uninstall(in); err != nil {
				t.Fatal(err)
			}
			if exists(paths.TrayPlist(home)) || exists(log) {
				t.Fatal("значок остался после удаления")
			}
			if !slices.Contains(l.calls, "bootout gui/501/"+paths.TrayLabel) {
				t.Fatalf("значок не выгружен: %v", l.calls)
			}
		})
	}
}

// Установка до появления значка записала файл задачи без него: удаление снимает её
// как обычно и о значке не спотыкается.
func TestUninstallOfOldInstallationWithoutTray(t *testing.T) {
	in, _, src := setup(t)
	home := t.TempDir()
	in.Agent = &Agent{UID: 501, GID: 20, Home: home}
	if err := in.Install(src); err != nil {
		t.Fatal(err)
	}
	os.Remove(paths.TrayPlist(home))
	if err := in.Uninstall(); err != nil {
		t.Fatal(err)
	}
}

func TestTrayFailureDoesNotStopInstall(t *testing.T) {
	t.Run("нет сеанса", func(t *testing.T) {
		in, l, src := setup(t)
		home := t.TempDir()
		in.Agent = &Agent{UID: 501, GID: 20, Home: home}
		l.userErr = func(plist string) error {
			if plist == paths.TrayPlist(home) {
				return errors.New("нет сеанса")
			}
			return nil
		}
		if err := in.Install(src); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(in.Note, "после следующего входа") || !strings.Contains(in.Note, "Ежедневное обновление каталога поставлено") {
			t.Fatalf("заметка: %q", in.Note)
		}
		if !exists(paths.TrayPlist(home)) {
			t.Fatal("значок не загрузится и при следующем входе: файла нет")
		}
	})
	t.Run("файл не записать", func(t *testing.T) {
		in, _, src := setup(t)
		home := t.TempDir()
		in.Agent = &Agent{UID: 501, GID: 20, Home: home}
		os.MkdirAll(filepath.Join(home, "Library"), 0o755)
		os.WriteFile(filepath.Join(home, "Library", "LaunchAgents"), []byte("файл вместо папки"), 0o644)
		if err := in.Install(src); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(in.Note, "Значок не поставлен") || !strings.Contains(in.Note, "Защита работает и без него") {
			t.Fatalf("заметка: %q", in.Note)
		}
		if !exists(in.Layout.Binary) {
			t.Fatal("служба не поставлена")
		}
	})
	t.Run("не через sudo", func(t *testing.T) {
		in, _, src := setup(t)
		if err := in.Install(src); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(in.Note, "Значок не поставлен") {
			t.Fatalf("заметка: %q", in.Note)
		}
	})
}
