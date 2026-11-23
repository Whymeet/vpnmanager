package tray

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Скрипт — текст внутри Go: опечатку в нём увидела бы только живая проверка.
func TestScriptCompiles(t *testing.T) {
	src := filepath.Join(t.TempDir(), "tray.js")
	if err := os.WriteFile(src, []byte(script), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("/usr/bin/osacompile", "-l", "JavaScript", "-o", filepath.Join(t.TempDir(), "tray.scpt"), src).CombinedOutput()
	if err != nil {
		t.Fatalf("osacompile: %v: %s", err, out)
	}
	for _, want := range []string{
		"setActivationPolicy(1)", "setTemplate(true)",
		"NSStatusItem Preferred Position appguard", "autosaveName = $('appguard')", // у часов, а не левее всех
		"lock.shield.fill", "shield.slash.fill", // открыто и закрыто
		"$('" + NotifyItem + "')", "NSSwitch", "notify.action = 'toggle:'", "toggle\\n", // переключатель и что он пишет
		"const width = 220", "preferredMaxLayoutWidth", // меню узкое, длинная причина переносится
		"readInBackgroundAndNotify", "Number(data.length) === 0", // новые виды из stdin, конец stdin — выход
		"'vpn:'", "vpn\\n", "argv[1] === 'vpn'", // пункт «Мои VPN…»
		"app.run",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("в скрипте нет %q", want)
		}
	}
}

// Вид уходит скрипту одной строкой ASCII и читается обратно тем же.
func TestLineIsOneASCIILine(t *testing.T) {
	v := View{Open: true, Title: "Приложения в сети", Detail: "Выход 185.1.2.3, Германия \"🛡\"\n", Notify: true}
	l := line(v)
	for _, r := range l {
		if r >= 0x80 || r == '\n' {
			t.Fatalf("в строке %q", r)
		}
	}
	var back struct {
		Open   bool   `json:"open"`
		Title  string `json:"title"`
		Detail string `json:"detail"`
		Notify bool   `json:"notify"`
		Tip    string `json:"tip"`
	}
	if err := json.Unmarshal([]byte(l), &back); err != nil {
		t.Fatal(err)
	}
	if back.Open != v.Open || back.Title != v.Title || back.Detail != v.Detail || back.Notify != v.Notify || back.Tip != v.Tip() {
		t.Fatalf("обратно %+v", back)
	}
}
