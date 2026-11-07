package install

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// Установка одной командой спрашивает пароль. Без терминала (так её запустил
// бы агент) она отказывается до любых шагов: ничего не собирает и не ставит.
func TestInstallScriptNeedsTerminal(t *testing.T) {
	cmd := exec.Command("../../setup/macos/install.sh")
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	err := cmd.Run()
	if err == nil {
		t.Fatal("установка без терминала прошла")
	}
	if out.Len() != 0 {
		t.Errorf("до отказа пошли шаги: %q", out.String())
	}
	if msg := errOut.String(); !strings.Contains(msg, "«Терминал»") || !strings.Contains(msg, "ничего не изменено") {
		t.Errorf("отказ без подсказки: %q", msg)
	}
}

// install.cmd в корне — один файл на все системы: sh по первой строке уходит
// в setup/install.sh, тот — в установку своей системы (здесь она отказывает без
// терминала), cmd.exe запускает установку Windows из того же клона.
func TestInstallCmdLeadsToEachSystemsScript(t *testing.T) {
	for _, shell := range []string{"sh", "zsh", "bash"} {
		cmd := exec.Command(shell, "-c", "./install.cmd")
		cmd.Dir = "../.."
		var errOut bytes.Buffer
		cmd.Stderr = &errOut
		if err := cmd.Run(); err == nil || !strings.Contains(errOut.String(), "setup/macos/install.sh") {
			t.Errorf("%s: %v %q", shell, err, errOut.String())
		}
	}
	data, err := os.ReadFile("../../install.cmd")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `-File "%~dp0setup\windows\install.ps1"`) {
		t.Fatal("cmd.exe не запускает setup\\windows\\install.ps1")
	}
	if _, err := os.Stat("../../setup/windows/install.ps1"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "\r") {
		t.Fatal("в install.cmd переводы строк CRLF: sh на маке споткнётся о первую строку")
	}
}
