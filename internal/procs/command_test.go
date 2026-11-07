package procs

import (
	"bytes"
	"encoding/binary"
	"slices"
	"testing"
)

func TestMatchCommand(t *testing.T) {
	links := map[string]string{
		"/Users/me/.local/bin/claude": "/Users/me/.local/share/claude/versions/2.1.301",
		"/opt/homebrew/bin/codex":     "/opt/homebrew/lib/node_modules/@openai/codex/bin/codex.js",
		"/opt/homebrew/bin/node":      "/opt/homebrew/Cellar/node/22.1.0/bin/node",
	}
	missing := map[string]bool{"/Users/me/.local/share/claude/versions/nosuch": true}
	resolve := func(p string) (string, bool) {
		if r, ok := links[p]; ok {
			return r, true
		}
		return p, !missing[p]
	}
	claude := "/Users/me/.local/share/claude/versions"
	codex := "/opt/homebrew/lib/node_modules/@openai/codex"
	for _, c := range []struct {
		target, exe string
		argv        []string
		want        bool
	}{
		// Claude Code запущен по ссылке и по настоящему пути; новая версия — тоже его.
		{claude, "/Users/me/.local/bin/claude", []string{"claude"}, true},
		{claude, "/Users/me/.local/share/claude/versions/2.1.302", []string{"claude"}, true},
		// Скрипт node: процесс — интерпретатор, программа — путь в аргументах.
		{codex, "/opt/homebrew/bin/node", []string{"node", "/opt/homebrew/bin/codex", "exec"}, true},
		{codex, "/opt/homebrew/bin/node", []string{"node", "--no-warnings", "/opt/homebrew/bin/codex"}, true},
		// Свой исполняемый файл пакета (вендорный бинарь codex).
		{codex, codex + "/vendor/aarch64-apple-darwin/codex/codex", []string{"codex"}, true},
		// Чужие процессы.
		{claude, "/usr/bin/git", []string{"git", "/Users/me/.local/share/claude/versions/2.1.301"}, false},
		{codex, "/opt/homebrew/bin/node", []string{"node", "/Users/me/other.js"}, false},
		{codex, "/opt/homebrew/bin/node", []string{"node"}, false},
		{claude, "claude", []string{"claude"}, false}, // путь не абсолютный — не узнать
		// Аргументы процесс задаёт сам: путь, которого нет, не засчитывается.
		{claude, "/opt/homebrew/bin/node", []string{"node", "/Users/me/.local/share/claude/versions/nosuch"}, false},
		// Соседняя папка с тем же началом имени — не та.
		{claude, "/Users/me/.local/share/claude/versions-old/x", nil, false},
	} {
		if got := MatchCommand(c.target, c.exe, c.argv, resolve); got != c.want {
			t.Errorf("%s в %s %v: %v, ждали %v", c.exe, c.target, c.argv, got, c.want)
		}
	}
}

func TestParseProcArgs(t *testing.T) {
	var buf bytes.Buffer
	binary.Write(&buf, binary.NativeEndian, uint32(3))
	buf.WriteString("/opt/homebrew/bin/node\x00\x00\x00\x00")
	buf.WriteString("node\x00/opt/homebrew/bin/codex\x00exec\x00")
	buf.WriteString("HOME=/Users/me\x00PATH=/usr/bin\x00")
	exe, argv, ok := ParseProcArgs(buf.Bytes())
	if !ok || exe != "/opt/homebrew/bin/node" || !slices.Equal(argv, []string{"node", "/opt/homebrew/bin/codex", "exec"}) {
		t.Fatalf("%v %q %q", ok, exe, argv)
	}
	for _, bad := range [][]byte{nil, {1, 0}, {1, 0, 0, 0, 0}} {
		if _, _, ok := ParseProcArgs(bad); ok {
			t.Errorf("%v разобрано", bad)
		}
	}
}
