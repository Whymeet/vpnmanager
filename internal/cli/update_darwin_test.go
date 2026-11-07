package cli_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"vpnlock/internal/cli"
)

// fakeClone — папка, похожая на клон vpnlock.
func fakeClone(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module vpnlock\n\ngo 1.26.0\n"), 0o644)
	os.MkdirAll(filepath.Join(dir, "setup"), 0o755)
	return dir
}

func TestUpdateNeedsAdminRights(t *testing.T) {
	r := vpnlock(cli.Env{Layout: emptyLayout(t)}, "", "update")
	if r.code != 1 || !strings.Contains(r.err, "sudo vpnlock update") || !strings.Contains(r.err, "git pull") {
		t.Fatalf("%+v", r)
	}
}

func TestUpdateRebuildsFromTheClone(t *testing.T) {
	clone := fakeClone(t)
	var got string
	env := cli.Env{Layout: emptyLayout(t), Root: true, Update: func(c string) error { got = c; return nil }}
	if r := vpnlock(env, "", "update", clone); r.code != 0 || got != clone || !strings.Contains(r.out, "Обновляю vpnlock из "+clone) {
		t.Fatalf("%+v, обновлялся %q", r, got)
	}

	// Без пути, не из клона — клон, из которого ставили.
	t.Chdir(t.TempDir())
	os.MkdirAll(filepath.Dir(env.Layout.CloneFile), 0o755)
	os.WriteFile(env.Layout.CloneFile, []byte(clone+"\n"), 0o644)
	got = ""
	if r := vpnlock(env, "", "update"); r.code != 0 || got != clone {
		t.Fatalf("%+v, обновлялся %q", r, got)
	}
}

func TestUpdateRefusesWhatIsNotAClone(t *testing.T) {
	called := false
	env := cli.Env{Layout: emptyLayout(t), Root: true, Update: func(string) error { called = true; return nil }}
	if r := vpnlock(env, "", "update", t.TempDir()); r.code != 1 || called || !strings.Contains(r.err, "Не нашёл клон vpnlock") {
		t.Fatalf("%+v", r)
	}
}

func TestFailedUpdateKeepsThePreviousVersion(t *testing.T) {
	env := cli.Env{Layout: emptyLayout(t), Root: true, Update: func(string) error { return errors.New("сборка не прошла") }}
	r := vpnlock(env, "", "update", fakeClone(t))
	if r.code != 1 || !strings.Contains(r.err, "сборка не прошла") || !strings.Contains(r.err, "Работает прежняя версия") {
		t.Fatalf("%+v", r)
	}
}
