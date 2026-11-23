package cli

import (
	"os/exec"
	"testing"
)

// Что отвечает git, когда доступа к репозиторию курса больше нет.
func TestAccessDeniedIsRecognized(t *testing.T) {
	for _, out := range []string{
		"remote: Repository not found.\nfatal: repository 'https://github.com/XoDefender/appguard.git/' not found",
		"git@github.com: Permission denied (publickey).\nfatal: Could not read from remote repository.",
		"fatal: could not read Username for 'https://github.com': terminal prompts disabled",
		"remote: Write access to repository not granted.\nfatal: unable to access 'https://github.com/x/y.git/': The requested URL returned error: 403",
	} {
		if !denied(out) {
			t.Fatalf("не распознан отказ в доступе: %q", out)
		}
	}
	if denied("fatal: unable to access 'https://github.com/x/y.git/': Could not resolve host: github.com") {
		t.Fatal("нет сети — это не закрытый доступ")
	}
	if got := firstLine("fatal: unable to access 'x': Could not resolve host: github.com\nmore"); got != "unable to access 'x': Could not resolve host: github.com" {
		t.Fatalf("%q", got)
	}
}

// Внутренний проект без своего сервера: у ветки нет вышестоящей, а remote
// upstream (исходный appguard) есть. Задача не ходит в сеть и ничего не тянет.
func TestNoUpstreamBranchSyncsNothing(t *testing.T) {
	git, err := gitPath()
	if err != nil {
		t.Skip("нет git")
	}
	dir := t.TempDir()
	for _, args := range [][]string{
		{"init", "-q", "-b", "main"},
		{"-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "--allow-empty", "-m", "x"},
		{"remote", "add", "upstream", "https://invalid.invalid/appguard.git"},
	} {
		if out, err := exec.Command(git, append([]string{"-C", dir}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
	if p := pull(dir); p != "" {
		t.Fatalf("без вышестоящей ветки обновлять нечего, а получено: %q", p)
	}
}
