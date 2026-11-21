package install

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"appguard/internal/paths"
)

type fakeSystemd struct {
	calls []string
	fail  map[string]error
}

func (f *fakeSystemd) do(call string) error {
	f.calls = append(f.calls, call)
	return f.fail[call]
}
func (f *fakeSystemd) Reload() error                  { return f.do("reload") }
func (f *fakeSystemd) Start(unit string) error        { return f.do("start " + unit) }
func (f *fakeSystemd) Halt(unit string) error         { return f.do("halt " + unit) }
func (f *fakeSystemd) StopDetached(unit string) error { return f.do("stop-detached " + unit) }
func (f *fakeSystemd) Disable(unit string) error      { return f.do("disable " + unit) }
func (f *fakeSystemd) Forget(unit string)             { f.do("forget " + unit) }

// clone заводит клон с собранным файлом, как после prepare.sh.
func clone(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for name, data := range map[string]string{
		"bin/appguard": "#!/bin/sh\n",
		"go.mod":       "module appguard\n\ngo 1.27\n",
		"setup/.keep":  "",
	} {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(data), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func installer(t *testing.T) (*Installer, *fakeSystemd) {
	t.Helper()
	sd := &fakeSystemd{}
	return &Installer{Layout: paths.Under(t.TempDir()), Systemd: sd, Agent: &Agent{UID: 1000, GID: 1000, Home: "/home/ivan"}}, sd
}

func TestInstallStartsServiceAndTimer(t *testing.T) {
	in, sd := installer(t)
	src := clone(t)
	if err := in.Install(filepath.Join(src, "bin", "appguard")); err != nil {
		t.Fatal(err)
	}
	want := []string{"halt appguard.service", "reload", "start appguard.service", "reload", "start appguard-catalog.timer"}
	if !slices.Equal(sd.calls, want) {
		t.Errorf("%q", sd.calls)
	}
	L := in.Layout
	for _, f := range []string{L.Binary, L.UnitFile, L.TimerFile, L.TaskFile, L.CommandLink} {
		if _, err := os.Lstat(f); err != nil {
			t.Error(err)
		}
	}
	if data, _ := os.ReadFile(L.CloneFile); string(data) != src {
		t.Errorf("клон записан как %q", data)
	}
	if !strings.Contains(in.Note, "раз в сутки git pull в клоне "+src) {
		t.Errorf("%q", in.Note)
	}
	task, _ := os.ReadFile(L.TaskFile)
	if !strings.Contains(string(task), "User=1000\n") || !strings.Contains(string(task), `catalog sync "`+src+`"`) {
		t.Errorf("%s", task)
	}
}

func TestInstallStopsBeforeChangesWhenSystemCannot(t *testing.T) {
	in, sd := installer(t)
	in.Preflight = func() error { return errors.New("в ядре нет net_cls") }
	err := in.Install(filepath.Join(clone(t), "bin", "appguard"))
	if err == nil || !strings.Contains(err.Error(), "ничего не изменено") {
		t.Fatal(err)
	}
	if len(sd.calls) != 0 {
		t.Errorf("%q", sd.calls)
	}
	if _, err := os.Stat(in.Layout.AppDir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("установка оставила след: %v", err)
	}
}

// Обновление, упавшее на полпути, возвращает прежнюю службу, а не оставляет компьютер
// без неё и без автозапуска.
func TestInstallFailureRestartsPreviousService(t *testing.T) {
	in, sd := installer(t)
	if err := in.Install(filepath.Join(clone(t), "bin", "appguard")); err != nil {
		t.Fatal(err)
	}
	sd.calls = nil
	err := in.Install(filepath.Join(t.TempDir(), "нет такого файла"))
	if err == nil {
		t.Fatal("обновление без файла прошло")
	}
	if !slices.Equal(sd.calls, []string{"halt appguard.service", "start appguard.service"}) {
		t.Errorf("%q", sd.calls)
	}
}

// Переустановка установленной командой: задача должна смотреть в клон, а не в /opt.
func TestInstallFromInstalledBinaryKeepsClone(t *testing.T) {
	in, _ := installer(t)
	src := clone(t)
	if err := in.Install(filepath.Join(src, "bin", "appguard")); err != nil {
		t.Fatal(err)
	}
	if err := in.Install(in.Layout.Binary); err != nil {
		t.Fatal(err)
	}
	if in.Agent.Clone != src {
		t.Errorf("клон %q вместо %q", in.Agent.Clone, src)
	}
}

func TestInstallLeavesForeignCommandAlone(t *testing.T) {
	in, sd := installer(t)
	link := in.Layout.CommandLink
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(link, []byte("чужой"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := in.Install(filepath.Join(clone(t), "bin", "appguard")); err == nil {
		t.Fatal("установка перезаписала чужой файл")
	}
	if len(sd.calls) != 0 {
		t.Errorf("%q", sd.calls)
	}
}

func TestInstallWithoutSudoUserStillWorks(t *testing.T) {
	in, sd := installer(t)
	in.Agent = nil
	if err := in.Install(filepath.Join(clone(t), "bin", "appguard")); err != nil {
		t.Fatal(err)
	}
	if slices.Contains(sd.calls, "start appguard-catalog.timer") {
		t.Error("задача каталога без пользователя")
	}
	if !strings.Contains(in.Note, "не поставлено") {
		t.Errorf("%q", in.Note)
	}
}

func TestUninstallOrder(t *testing.T) {
	in, sd := installer(t)
	src := filepath.Join(clone(t), "bin", "appguard")
	if err := in.Install(src); err != nil {
		t.Fatal(err)
	}
	sd.calls = nil
	cleared := false
	in.Clear = func() error {
		if !slices.Contains(sd.calls, "halt appguard.service") {
			t.Error("правила снимаются при живом стороже")
		}
		if _, err := os.Stat(in.Layout.AppDir); err != nil {
			t.Error("файлы удалены раньше правил")
		}
		cleared = true
		return nil
	}
	if err := in.Uninstall(); err != nil {
		t.Fatal(err)
	}
	if !cleared {
		t.Error("правила не сняты")
	}
	for _, p := range append(in.Layout.Traces(), in.Layout.TimerFile, in.Layout.TaskFile, in.Layout.CommandLink, in.Layout.LogDir) {
		if _, err := os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("остался след: %s", p)
		}
	}
}

// Удаление через службу не может её остановить, но автозапуск снять обязано: иначе в
// multi-user.target.wants осталась бы ссылка в никуда.
func TestRemoveFromServiceDisablesItWithoutStopping(t *testing.T) {
	in, sd := installer(t)
	if err := in.Install(filepath.Join(clone(t), "bin", "appguard")); err != nil {
		t.Fatal(err)
	}
	sd.calls = nil
	if err := in.Remove(); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(sd.calls, "disable appguard.service") {
		t.Errorf("автозапуск не снят: %q", sd.calls)
	}
	if slices.Contains(sd.calls, "halt appguard.service") {
		t.Errorf("служба остановила саму себя посреди удаления: %q", sd.calls)
	}
}

func TestUninstallKeepsRulesWhenServiceSurvives(t *testing.T) {
	in, sd := installer(t)
	if err := in.Install(filepath.Join(clone(t), "bin", "appguard")); err != nil {
		t.Fatal(err)
	}
	sd.fail = map[string]error{"halt appguard.service": errors.New("не остановилась")}
	in.Clear = func() error {
		t.Error("правила сняты при работающей службе")
		return nil
	}
	if err := in.Uninstall(); err == nil {
		t.Fatal("удаление прошло")
	}
	if _, err := os.Stat(in.Layout.Binary); err != nil {
		t.Error("файлы удалены при работающей службе")
	}
}

func TestUnitArgEscapesSystemdSubstitutions(t *testing.T) {
	if got := unitArg(`/home/a b/100%$x"\`); got != `"/home/a b/100%%$$x\"\\"` {
		t.Error(got)
	}
}

func TestUnitStartsBeforeNetworkAndLoadsClosedRulesFirst(t *testing.T) {
	text := string(unitFile(paths.Under("/")))
	for _, want := range []string{
		"DefaultDependencies=no", "Before=network-pre.target", "Wants=network-pre.target",
		"Type=notify", `ExecStartPre=-nft -f "/opt/appguard/state/closed.nft"`, `ExecStart="/opt/appguard/bin/appguard" daemon`,
		"Restart=always", "WatchdogSec=60", "WantedBy=multi-user.target",
		"StandardOutput=append:/var/log/appguard/daemon.log", "StandardError=append:/var/log/appguard/daemon.log",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("нет %q:\n%s", want, text)
		}
	}
	// На Ubuntu 22.04 это цикл, и systemd выбрасывает запуск службы.
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "After=") && (strings.Contains(line, "resolved") || strings.Contains(line, "network") || strings.Contains(line, "dbus")) {
			t.Errorf("служба стоит после сети: %s", line)
		}
	}
}

func TestInstallPutsTrayAutostart(t *testing.T) {
	in, sd := installer(t)
	if err := in.Install(filepath.Join(clone(t), "bin", "appguard")); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(in.Layout.TrayStart)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, want := range []string{"[Desktop Entry]\n", "Type=Application\n", `Exec="` + in.Layout.Binary + `" tray` + "\n", "NoDisplay=true\n"} {
		if !strings.Contains(text, want) {
			t.Errorf("нет %q:\n%s", want, text)
		}
	}
	if slices.ContainsFunc(sd.calls, func(c string) bool { return strings.Contains(c, "tray") }) {
		t.Errorf("значок — не служба systemd: %q", sd.calls)
	}
	if !strings.Contains(in.Note, "Значок службы") {
		t.Errorf("%q", in.Note)
	}
	if fi, _ := os.Stat(in.Layout.TrayStart); fi.Mode().Perm() != 0o644 {
		t.Errorf("права %v: файл читают все пользователи", fi.Mode().Perm())
	}
}

func TestReinstallKeepsOneTrayAutostart(t *testing.T) {
	in, _ := installer(t)
	src := filepath.Join(clone(t), "bin", "appguard")
	for range 2 {
		if err := in.Install(src); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := os.ReadDir(filepath.Dir(in.Layout.TrayStart))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("в автозапуске %v", entries)
	}
}

func TestUninstallRemovesTrayAutostart(t *testing.T) {
	for name, uninstall := range map[string]func(in *Installer) error{
		"на месте":     (*Installer).Uninstall,
		"через службу": (*Installer).Remove,
	} {
		t.Run(name, func(t *testing.T) {
			in, _ := installer(t)
			if err := in.Install(filepath.Join(clone(t), "bin", "appguard")); err != nil {
				t.Fatal(err)
			}
			if err := uninstall(in); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Lstat(in.Layout.TrayStart); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("автозапуск остался: %v", err)
			}
			if _, err := os.Stat(filepath.Dir(in.Layout.TrayStart)); err != nil {
				t.Errorf("удалён каталог автозапуска — он не наш: %v", err)
			}
		})
	}
}

func TestTrayFailureDoesNotStopInstall(t *testing.T) {
	in, sd := installer(t)
	dir := filepath.Dir(in.Layout.TrayStart)
	if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir, []byte("файл вместо папки"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := in.Install(filepath.Join(clone(t), "bin", "appguard")); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(in.Note, "Значок не поставлен") || !strings.Contains(in.Note, "Защита работает и без него") {
		t.Errorf("%q", in.Note)
	}
	if !slices.Contains(sd.calls, "start appguard.service") || !slices.Contains(sd.calls, "start appguard-catalog.timer") {
		t.Errorf("%q", sd.calls)
	}
}

// Кавычка в аргументе экранируется в Exec= и ещё раз как строка файла .desktop.
func TestDesktopArgFollowsTheSpec(t *testing.T) {
	for in, want := range map[string]string{
		"/opt/appguard/bin/appguard": `"/opt/appguard/bin/appguard"`,
		`/opt/a b/x`:                 `"/opt/a b/x"`,
		`/opt/100%`:                  `"/opt/100%%"`,
		`/a"b`:                       `"/a\\"b"`,
		`/a$b`:                       `"/a\\$b"`,
		"/a`b":                       "\"/a\\\\`b\"",
		`/a\b`:                       `"/a\\\\b"`,
	} {
		if got := desktopArg(in); got != want {
			t.Errorf("%q: %s, ждали %s", in, got, want)
		}
	}
}
