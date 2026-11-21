//go:build live && darwin

// Живая проверка сканера на этом маке: tools/go test -tags live -v ./internal/procs
// Нужен запущенный Notion. Свои процессы видны и без root.

package procs

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"appguard/internal/apps"
)

func TestLiveScanNotion(t *testing.T) {
	apps := []AppRef{
		{ID: "notion.id", Path: "/Applications/Notion.app"},
		{ID: "no.such.app", Path: "/Applications/No Such App.app"},
	}
	start := time.Now()
	got, err := System{}.Scan(context.Background(), apps)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("скан занял %v", time.Since(start).Round(time.Millisecond))
	if act := got["no.such.app"]; act.Running || len(act.Remotes) != 0 {
		t.Fatalf("несуществующее приложение «запущено»: %+v", act)
	}
	n := got["notion.id"]
	if !n.Running {
		t.Skip("Notion не запущен")
	}
	t.Logf("Notion запущен, соединений: %d", len(n.Remotes))
	for _, r := range n.Remotes {
		t.Logf("  %s %s:%d", r.Proto, r.Addr, r.Port)
	}
	if len(n.Remotes) == 0 {
		t.Fatal("у запущенного Notion нет ни одного исходящего соединения")
	}
}

// Claude Code: ps показывает его как «claude», процесс узнаётся по пути от
// ядра. Нужен запущенный Claude Code — например, эта сессия агента.
func TestLiveScanClaudeCode(t *testing.T) {
	home, _ := os.UserHomeDir()
	real, err := filepath.EvalSymlinks(filepath.Join(home, ".local", "bin", "claude"))
	if err != nil {
		t.Skip("Claude Code не установлен")
	}
	target, _ := apps.CommandTarget(real)
	start := time.Now()
	got, err := System{}.Scan(context.Background(), []AppRef{{ID: "cmd:claude", Path: target, Command: true}})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("скан занял %v, защищается %s", time.Since(start).Round(time.Millisecond), target)
	c := got["cmd:claude"]
	if !c.Running {
		t.Fatal("Claude Code запущен, но его процессов не нашлось")
	}
	for _, r := range c.Remotes {
		t.Logf("  %s %s:%d", r.Proto, r.Addr, r.Port)
	}
}
