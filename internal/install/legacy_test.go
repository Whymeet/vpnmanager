package install

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"appguard/internal/paths"
)

// oldInstall раскладывает прежний vpnlock во временном корне: бинарник и
// настройки, среди которых токен pf — он остаётся прежнему бинарнику.
func oldInstall(t *testing.T, root string) *Legacy {
	t.Helper()
	bin, state := paths.LegacyUnder(root)
	files := map[string]string{
		bin:                                  "старый vpnlock",
		filepath.Join(state, "config.json"):  `{"rule":"mine"}`,
		filepath.Join(state, "catalog.json"): `{"format":1}`,
		filepath.Join(state, "journal", "2026-11-20"): "событие\n",
		filepath.Join(state, "pf.token"):              "123",
	}
	for p, data := range files {
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return &Legacy{Binary: bin, StateDir: state}
}

func TestNoLegacyMeansNothingToTake(t *testing.T) {
	root := t.TempDir()
	bin, state := paths.LegacyUnder(root)
	called := false
	in := &Installer{Layout: paths.Under(root), Legacy: &Legacy{Binary: bin, StateDir: state,
		Uninstall: func(string) error { called = true; return nil }}}
	carry, err := in.takeLegacy()
	if err != nil || carry != "" || called {
		t.Fatalf("прежнего нет, а перенос идёт: %q %v %v", carry, err, called)
	}
	if note, err := in.restoreLegacy(carry); note != "" || err != nil {
		t.Fatalf("переносить нечего, а сказано %q %v", note, err)
	}
}

func TestLegacySettingsMoveAndOldIsRemovedByItsOwnBinary(t *testing.T) {
	root := t.TempDir()
	lg := oldInstall(t, root)
	var ranWith string
	lg.Uninstall = func(bin string) error {
		ranWith = bin
		if data, _ := os.ReadFile(bin); string(data) != "старый vpnlock" {
			t.Fatalf("снимает не прежний бинарник: %q", data)
		}
		// Прежний сам стирает свою папку — вместе с бинарником.
		return os.RemoveAll(filepath.Dir(filepath.Dir(lg.Binary)))
	}
	in := &Installer{Layout: paths.Under(root), Legacy: lg}
	carry, err := in.takeLegacy()
	if err != nil || carry == "" {
		t.Fatalf("перенос не начался: %q %v", carry, err)
	}
	if ranWith == lg.Binary {
		t.Fatal("прежний снимается из своей папки — на Windows он не сотрёт сам себя")
	}

	// Папку настроек создаёт установка; там уже свой каталог — он главнее.
	state := in.Layout.StateDir
	os.MkdirAll(state, 0o700)
	os.WriteFile(filepath.Join(state, "catalog.json"), []byte(`{"format":2}`), 0o600)
	note, err := in.restoreLegacy(carry)
	if err != nil || note != legacyNote {
		t.Fatalf("перенос: %q %v", note, err)
	}
	want := map[string]string{
		"config.json":                          `{"rule":"mine"}`,
		"catalog.json":                         `{"format":2}`,
		filepath.Join("journal", "2026-11-20"): "событие\n",
	}
	for name, data := range want {
		if got, _ := os.ReadFile(filepath.Join(state, name)); string(got) != data {
			t.Fatalf("%s: %q, ждали %q", name, got, data)
		}
	}
	if present(filepath.Join(state, "pf.token")) {
		t.Fatal("токен pf прежней службы уехал в новую")
	}
	if present(carry) {
		t.Fatal("папка переноса осталась")
	}
}

func TestLegacyThatDoesNotUninstallChangesNothing(t *testing.T) {
	root := t.TempDir()
	lg := oldInstall(t, root)
	lg.Uninstall = func(string) error { return errors.New("служба не остановилась") }
	in := &Installer{Layout: paths.Under(root), Legacy: lg}
	carry, err := in.takeLegacy()
	if err == nil || carry != "" {
		t.Fatalf("прежний не снялся, а установка идёт дальше: %q %v", carry, err)
	}
	if !present(lg.Binary) || !present(filepath.Join(lg.StateDir, "config.json")) {
		t.Fatal("прежняя установка тронута")
	}
	if present(in.Layout.StateDir) {
		t.Fatal("новая установка начата")
	}
}

func present(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
