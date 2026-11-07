package procs

import (
	"os"
	"path/filepath"
	"testing"
)

// Ядро отдаёт путь и аргументы своего процесса и без root.
func TestProcArgsOfOwnProcess(t *testing.T) {
	exe, argv, ok := procArgs(os.Getpid())
	if !ok || len(argv) == 0 {
		t.Fatalf("%v %q %q", ok, exe, argv)
	}
	want, _ := os.Executable()
	if r, _ := filepath.EvalSymlinks(exe); r != want {
		if w, _ := filepath.EvalSymlinks(want); r != w {
			t.Fatalf("путь от ядра %q, а исполняемый файл %q", exe, want)
		}
	}
}

// Процесс, который ps показывает просто именем, узнаётся по пути от ядра. Тот,
// кто подставил себе argv[0] из папки программы, — нет: ядро знает его файл.
func TestOwnFindsCommandByKernelPath(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	versions := filepath.Join(root, "claude", "versions")
	codex := filepath.Join(root, "node_modules", "@openai", "codex")
	for _, f := range []string{filepath.Join(versions, "2.1.301"), filepath.Join(codex, "bin", "codex.js")} {
		os.MkdirAll(filepath.Dir(f), 0o755)
		if err := os.WriteFile(f, []byte("x"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	claudeExe := filepath.Join(versions, "2.1.301")
	procs := []Proc{{PID: 10, Path: "claude"}, {PID: 11, Path: "/Applications/Notion.app/Contents/MacOS/Notion"},
		{PID: 12, Path: "node"}, {PID: 13, Path: "zsh"}, {PID: 14, Path: claudeExe}, {PID: 15, Path: "/usr/sbin/cfprefsd"}}
	kernel := map[int][]string{
		10: {claudeExe, "claude"},
		12: {"/opt/homebrew/bin/node", "node", filepath.Join(codex, "bin", "codex.js")},
		13: {"/bin/zsh", "-zsh"},
		14: {"/usr/bin/curl", claudeExe},
	}
	asked := map[int]bool{}
	args := func(pid int) (string, []string, bool) {
		asked[pid] = true
		k, ok := kernel[pid]
		if !ok {
			return "", nil, false
		}
		return k[0], k[1:], true
	}
	apps := []AppRef{
		{ID: "notion.id", Path: "/Applications/Notion.app"},
		{ID: "cmd:claude", Path: versions, Command: true},
		{ID: "cmd:codex", Path: codex, Command: true},
	}
	pidApp, pids := own(procs, apps, args)
	if pidApp[10] != "cmd:claude" || pidApp[11] != "notion.id" || pidApp[12] != "cmd:codex" || pidApp[13] != "" || pidApp[14] != "" || len(pids) != 3 {
		t.Fatalf("%v %v", pidApp, pids)
	}
	if asked[15] || asked[11] {
		t.Fatalf("ядро спрошено зря: %v", asked)
	}
}
