package apps

import "testing"

func TestSnapName(t *testing.T) {
	for _, c := range []struct {
		path, want string
		ok         bool
	}{
		{"/snap/bin/firefox", "firefox", true},
		{"/snap/bin/firefox.geckodriver", "firefox", true},
		{"/snap/bin/", "", false},
		{"/snap/bin/a/b", "", false},
		{"/snap/firefox/current/bin/firefox", "", false},
		{"/usr/bin/firefox", "", false},
	} {
		if got, ok := snapName(c.path); got != c.want || ok != c.ok {
			t.Errorf("%s: %q %v", c.path, got, ok)
		}
	}
}

// Обёртка из пакета firefox на Ubuntu: снят с настоящего файла.
func TestSnapExecFindsWrapperTarget(t *testing.T) {
	script := `#!/bin/sh
if ! [ -x /snap/bin/firefox ]; then
    echo "Command '$0' requires the firefox snap to be installed." >&2
    exit 1
fi

exec /snap/bin/firefox "$@"
`
	m := snapExec.FindStringSubmatch(script)
	if m == nil || m[1] != "/snap/bin/firefox" {
		t.Errorf("%q", m)
	}
	if snapExec.MatchString("#!/bin/sh\n# exec /snap/bin/firefox\nexec /usr/lib/x/x\n") {
		t.Error("комментарий — не запуск")
	}
}

func TestBinRoot(t *testing.T) {
	for _, c := range []struct{ real, want string }{
		{"/usr/share/code/bin/code", "/usr/share/code"},
		{"/usr/lib/llvm-18/bin/clang", "/usr/lib/llvm-18"},
		{"/opt/foo/bin/foo", "/opt/foo"},
		{"/home/ivan/apps/foo/bin/foo", "/home/ivan/apps/foo"},
		{"/usr/bin/curl", ""},
		{"/usr/local/bin/foo", ""},
		{"/opt/bin/foo", ""},
		{"/home/ivan/bin/tool", ""},
		{"/home/ivan/.local/bin/tool", ""},
		{"/opt/foo/foo", ""},
	} {
		if got := binRoot(c.real); got != c.want {
			t.Errorf("%s: %q", c.real, got)
		}
	}
}

func TestLauncher(t *testing.T) {
	for _, p := range []string{"/usr/bin/python3.12", "/usr/bin/dash", "/usr/bin/flatpak", "/usr/bin/snap", "/usr/lib/snapd/snapd", "/usr/bin/env", "/usr/lib/jvm/x/bin/java"} {
		if !Launcher(p) {
			t.Errorf("%s запускает чужое", p)
		}
	}
	for _, p := range []string{"/usr/bin/curl", "/opt/Telegram/Telegram", "/tmp/tickpy", "/usr/bin/snapshot", "/usr/bin/nodeapp"} {
		if Launcher(p) {
			t.Errorf("%s — обычная программа", p)
		}
	}
}
