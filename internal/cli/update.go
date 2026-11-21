package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	installer "appguard/internal/install"
)

// update — «Обновить»: после git pull пересобрать appguard из клона и поставить
// новую версию поверх прежней. Служба перезапускается с теми же настройками;
// правила файрвола всё это время остаются в системе. Как и установку, команду
// запускает человек с правами администратора.
func update(env Env, args []string) int {
	if len(args) > 1 {
		fmt.Fprintln(env.Err, "«update» принимает только путь к клону: appguard update [клон]")
		return 2
	}
	if !env.Root {
		if runtime.GOOS == "windows" {
			fmt.Fprintln(env.Err, "Обновление запускают из PowerShell от имени администратора: appguard update. Перед ним — git pull в клоне. Ничего не изменено.")
		} else {
			fmt.Fprintln(env.Err, "Обновление запускают с sudo: sudo appguard update. Перед ним — git pull в клоне. Ничего не изменено.")
		}
		return 1
	}
	clone, ok := findClone(env, args)
	if !ok {
		fmt.Fprintln(env.Err, "Не нашёл клон appguard: запусти команду из папки клона или укажи её — appguard update <клон>. Ничего не изменено.")
		return 1
	}
	fmt.Fprintf(env.Out, "· Обновляю appguard из %s\n", clone)
	if err := env.Update(clone); err != nil {
		fmt.Fprintf(env.Err, "✗ Обновление не удалось: %v\n  Работает прежняя версия, настройки и защита на месте.\n", err)
		return 1
	}
	return 0
}

// findClone — откуда обновлять: указанная папка, текущая папка (или папка
// выше) или клон, из которого appguard ставили.
func findClone(env Env, args []string) (string, bool) {
	var candidates []string
	if len(args) == 1 {
		candidates = append(candidates, args[0])
	} else {
		if wd, err := os.Getwd(); err == nil {
			for dir := wd; ; dir = filepath.Dir(dir) {
				candidates = append(candidates, dir)
				if filepath.Dir(dir) == dir {
					break
				}
			}
		}
		if data, err := os.ReadFile(env.Layout.CloneFile); err == nil {
			candidates = append(candidates, strings.TrimSpace(string(data)))
		}
	}
	for _, c := range candidates {
		if abs, err := filepath.Abs(c); err == nil && installer.IsClone(abs) {
			return abs, true
		}
	}
	return "", false
}
