package install

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Legacy — установка под прежним именем vpnlock (до 0.23.0). Установка
// appguard забирает её настройки и снимает её её же бинарником: только он знает
// свои службы, правила файрвола и резолверы. Без этого на компьютере остались
// бы две защиты сразу.
type Legacy struct {
	Binary   string // бинарник прежней установки
	StateDir string // её настройки
	// Uninstall снимает прежнюю установку бинарником bin. nil — запуск
	// `bin uninstall --yes`: установка и так идёт с правами администратора.
	Uninstall func(bin string) error
}

// legacyState — что переезжает из настроек прежней установки: настройки,
// каталог и журнал. Токен pf, состояние фильтров WFP и метки запуска остаются:
// по ним прежний бинарник снимает свои правила.
var legacyState = []string{"config.json", "catalog.json", "journal"}

// takeLegacy, если прежняя установка есть, копирует её настройки во временную
// папку и снимает её. Возвращает эту папку (пусто — прежней установки нет);
// restoreLegacy кладёт настройки на место, когда папки новой установки готовы.
// Не снялась — ошибка, и в системе ничего не изменено: работает прежняя.
func (in *Installer) takeLegacy() (string, error) {
	lg := in.Legacy
	if lg == nil {
		return "", nil
	}
	if _, err := os.Stat(lg.Binary); errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	carry, err := os.MkdirTemp("", "appguard-from-vpnlock-")
	if err != nil {
		return "", err
	}
	for _, name := range legacyState {
		if err := copyTree(filepath.Join(lg.StateDir, name), filepath.Join(carry, name)); err != nil {
			os.RemoveAll(carry)
			return "", fmt.Errorf("настройки прежнего vpnlock не скопировались: %w. Ничего не изменено", err)
		}
	}
	// Удаление стирает и сам бинарник, а на Windows работающий файл не
	// удалить: снимаем копией из временной папки.
	bin := filepath.Join(carry, "bin", filepath.Base(lg.Binary))
	if err := copyTree(lg.Binary, bin); err != nil {
		os.RemoveAll(carry)
		return "", fmt.Errorf("бинарник прежнего vpnlock не скопировался: %w. Ничего не изменено", err)
	}
	uninstall := lg.Uninstall
	if uninstall == nil {
		uninstall = runUninstall
	}
	if err := uninstall(bin); err != nil {
		os.RemoveAll(carry)
		return "", fmt.Errorf("прежний vpnlock не снялся: %w. Работает он, appguard не поставлен; удалить вручную — sudo vpnlock uninstall (на Windows — vpnlock uninstall в PowerShell от имени администратора), затем повтори установку", err)
	}
	os.RemoveAll(filepath.Dir(bin))
	return carry, nil
}

// restoreLegacy кладёт перенесённые настройки в папку новой установки — только
// те, которых там ещё нет: настройки appguard главнее. Папка переноса после
// этого удаляется. Возвращает, что сказать человеку.
func (in *Installer) restoreLegacy(carry string) (string, error) {
	if carry == "" {
		return "", nil
	}
	for _, name := range legacyState {
		src, dst := filepath.Join(carry, name), filepath.Join(in.Layout.StateDir, name)
		if _, err := os.Stat(dst); err == nil {
			continue
		}
		if err := copyTree(src, dst); err != nil {
			return "", fmt.Errorf("настройки прежнего vpnlock не перенеслись: %w. Они лежат в %s", err, carry)
		}
	}
	os.RemoveAll(carry)
	return legacyNote, nil
}

// legacyNote — что сказать после переноса с vpnlock.
const legacyNote = "Прежний vpnlock снят, его настройки перенесены. Команда теперь — appguard."

func runUninstall(bin string) error {
	out, err := exec.Command(bin, "uninstall", "--yes").CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// copyTree копирует файл или папку целиком; нет источника — копировать нечего.
func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if errors.Is(err, fs.ErrNotExist) && path == src {
			return nil
		}
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		to := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(to, 0o700)
		}
		if !d.Type().IsRegular() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(to), 0o700); err != nil {
			return err
		}
		return copyFile(path, to, info.Mode().Perm())
	})
}
