package install

import (
	"bytes"
	"os/exec"
	"strings"
	"testing"
)

// Установка спрашивает пароль. Без терминала (так её запустил бы агент) она
// отказывается до любых шагов: ничего не собирает и не ставит.
func TestInstallScriptNeedsTerminal(t *testing.T) {
	cmd := exec.Command("../../setup/linux/install.sh")
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	if err := cmd.Run(); err == nil {
		t.Fatal("установка без терминала прошла")
	}
	if out.Len() != 0 {
		t.Errorf("до отказа пошли шаги: %q", out.String())
	}
	if msg := errOut.String(); !strings.Contains(msg, "в терминале") || !strings.Contains(msg, "ничего не изменено") {
		t.Errorf("отказ без подсказки: %q", msg)
	}
}

// sh по первой строке install.cmd уходит в setup/install.sh, а тот — в установку
// Linux, которая здесь отказывает без терминала.
func TestInstallCmdLeadsToLinuxScript(t *testing.T) {
	for _, shell := range []string{"sh", "bash"} {
		cmd := exec.Command(shell, "-c", "./install.cmd")
		cmd.Dir = "../.."
		var errOut bytes.Buffer
		cmd.Stderr = &errOut
		if err := cmd.Run(); err == nil || !strings.Contains(errOut.String(), "install.cmd") {
			t.Errorf("%s: %v %q", shell, err, errOut.String())
		}
	}
}
