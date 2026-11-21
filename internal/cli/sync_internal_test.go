package cli

import "testing"

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
