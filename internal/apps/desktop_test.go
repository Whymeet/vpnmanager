package apps

import (
	"slices"
	"testing"
)

func TestParseDesktop(t *testing.T) {
	d, ok := ParseDesktop([]byte(`[Desktop Entry]
Type=Application
Name=Telegram
Name[ru]=Телеграм
Exec=env QT_SCALE=1 "/opt/Telegram/Telegram" -- %u
[Desktop Action new]
Name=Новое окно
Exec=/opt/other
`))
	if !ok || d.Name != "Телеграм" || d.Exec != "/opt/Telegram/Telegram" {
		t.Errorf("%+v %v", d, ok)
	}
	for _, text := range []string{
		"[Desktop Entry]\nName=X\nExec=x\nNoDisplay=true\n",
		"[Desktop Entry]\nName=X\nExec=x\nHidden=true\n",
		"[Desktop Entry]\nType=Link\nName=X\nURL=http://x\n",
		"[Desktop Entry]\nName=X\n",
		"Name=X\nExec=x\n",
	} {
		if d, ok := ParseDesktop([]byte(text)); ok {
			t.Errorf("%q — не приложение: %+v", text, d)
		}
	}
}

// Значение переменной бывает путём: так пишет ярлыки snap.
func TestParseDesktopSnapEntry(t *testing.T) {
	d, ok := ParseDesktop([]byte("[Desktop Entry]\nName=Firefox\nExec=env BAMF_DESKTOP_FILE_HINT=/var/lib/snapd/desktop/applications/firefox_firefox.desktop /snap/bin/firefox %u\n"))
	if !ok || d.Exec != "/snap/bin/firefox" {
		t.Errorf("%+v %v", d, ok)
	}
}

func TestExecPaths(t *testing.T) {
	got := ExecPaths(`ExecStartPre={ path=/usr/sbin/nginx ; argv[]=/usr/sbin/nginx -t -q ; ignore_errors=no ; start_time=[n/a] }
ExecStart={ path=/usr/sbin/nginx ; argv[]=/usr/sbin/nginx -g daemon on; ; ignore_errors=no }
`)
	if !slices.Equal(got, []string{"/usr/sbin/nginx", "/usr/sbin/nginx"}) {
		t.Errorf("%q", got)
	}
}

func TestUnitNames(t *testing.T) {
	got := UnitNames("nginx.service enabled enabled\nfoo@.service enabled enabled\nbar.service disabled enabled\nbaz.timer enabled enabled\n")
	if !slices.Equal(got, []string{"nginx.service"}) {
		t.Errorf("%q", got)
	}
}

func TestCommandTargetOnLinux(t *testing.T) {
	for _, c := range []struct {
		real, want string
		dir        bool
	}{
		{"/home/ivan/.local/share/claude/versions/2.1.301", "/home/ivan/.local/share/claude/versions", true},
		{"/usr/bin/curl", "/usr/bin/curl", false},
		{"/usr/sbin/nginx", "/usr/sbin/nginx", false},
		{"/home/ivan/bin/tool", "/home/ivan/bin/tool", false},
		{"/home/ivan/tool", "/home/ivan/tool", false},
		{"/root/tool", "/root/tool", false},
		{"/opt/Telegram/Telegram", "/opt/Telegram", true},
		{"/opt/tool", "/opt/tool", false},
		{"/snap/bin/firefox", "/snap/bin/firefox", false},
		{"/home/ivan/.nvm/versions/node/v22.1.0/lib/node_modules/@openai/codex/bin/codex.js", "/home/ivan/.nvm/versions/node/v22.1.0/lib/node_modules/@openai/codex", true},
	} {
		if got, dir := CommandTarget(c.real); got != c.want || dir != c.dir {
			t.Errorf("CommandTarget(%s) = %s %v, а нужно %s %v", c.real, got, dir, c.want, c.dir)
		}
	}
}
