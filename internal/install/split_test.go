package install

import (
	"os"
	"strings"
	"testing"
)

// Установки Windows и macOS разделены: каждая берёт только свой конфиг и свой
// установщик — правка одной не задевает другую.
func TestInstallersAreSplit(t *testing.T) {
	read := func(p string) string {
		b, err := os.ReadFile("../../" + p)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	win, mac := read("setup/windows/install.ps1"), read("setup/macos/install.sh")
	if !strings.Contains(win, `configs\claude-vpn.conf`) || strings.Contains(win, "claude-vpn-macos") {
		t.Error("install.ps1 должен брать только configs\\claude-vpn.conf")
	}
	if !strings.Contains(mac, "configs/claude-vpn-macos.conf") || strings.Contains(mac, "claude-vpn.conf\"") {
		t.Error("macos/install.sh должен брать только configs/claude-vpn-macos.conf")
	}
	if w := read("install-windows.cmd"); !strings.Contains(w, `setup\windows\install.ps1`) || strings.Contains(w, "macos") {
		t.Error("install-windows.cmd запускает не установку Windows")
	}
	if m := read("install-mac.command"); !strings.Contains(m, "setup/macos/install.sh") || !strings.Contains(m, `"Darwin"`) || strings.Contains(m, "windows\\") {
		t.Error("install-mac.command запускает не установку macOS или без проверки системы")
	}
}
