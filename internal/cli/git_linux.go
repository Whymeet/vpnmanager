package cli

import (
	"errors"
	"os/exec"
)

// gitPath — git из PATH.
func gitPath() (string, error) {
	p, err := exec.LookPath("git")
	if err != nil {
		return "", errors.New("git не найден: поставь его пакетом git")
	}
	return p, nil
}

// quiet — на Linux окон у git нет, делать нечего.
func quiet(*exec.Cmd) {}
