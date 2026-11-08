// Package install — установка и снятие vpnlock: файлы, команда в PATH, служба
// системы (launchd на macOS, диспетчер служб на Windows).
package install

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"vpnlock/internal/catalog"
	"vpnlock/internal/core"
)

// installCatalog кладёт службе каталог из клона (catalog/catalog.json рядом с
// bin/). Каталог новее поддерживаемого формата не ставится: служба остаётся на
// прежнем, а человек узнаёт, что пора обновить инструмент.
func (in *Installer) installCatalog(src string) (string, error) {
	path := filepath.Join(filepath.Dir(filepath.Dir(src)), "catalog", "catalog.json")
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	c, _, err := catalog.Parse(data)
	if errors.Is(err, catalog.ErrNewer) {
		return "Каталог в клоне новее этой версии vpnlock и не установлен — обнови инструмент.", nil
	}
	if err != nil {
		return fmt.Sprintf("Каталог в клоне повреждён и не установлен: %v", err), nil
	}
	if err := writeFile(filepath.Join(in.Layout.StateDir, "catalog.json"), data, 0o600); err != nil {
		return "", err
	}
	return fmt.Sprintf("Каталог установлен: %d %s.", len(c.Apps), core.Plural(len(c.Apps), "приложение", "приложения", "приложений")), nil
}

// rememberClone записывает, из какого клона поставлен vpnlock: `vpnlock update`
// пересобирает его оттуда. Если ставят установленной командой (src лежит в
// папке установки), клона рядом нет и запись остаётся прежней.
func (in *Installer) rememberClone(src string) error {
	clone := filepath.Dir(filepath.Dir(src))
	if !IsClone(clone) {
		return nil
	}
	return writeFile(in.Layout.CloneFile, []byte(clone), 0o644)
}

// IsClone — в папке клон репозитория vpnlock: модуль vpnlock и папка setup.
// Git для Windows по умолчанию (core.autocrlf) кладёт файлы с CRLF — первая
// строка go.mod сверяется без \r.
func IsClone(dir string) bool {
	data, err := os.ReadFile(filepath.Join(dir, "go.mod"))
	if err != nil {
		return false
	}
	if first, _, _ := strings.Cut(string(data), "\n"); strings.TrimSuffix(first, "\r") != "module vpnlock" {
		return false
	}
	fi, err := os.Stat(filepath.Join(dir, "setup"))
	return err == nil && fi.IsDir()
}

func joinNotes(a, b string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	}
	return a + "\n" + b
}

// copyFile копирует src в dst атомарно. Если это один и тот же файл (установку
// запустили установленной командой), копировать нечего.
func copyFile(src, dst string, mode fs.FileMode) error {
	if a, err := os.Stat(src); err == nil {
		if b, err := os.Stat(dst); err == nil && os.SameFile(a, b) {
			return nil
		}
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	return writeAtomic(dst, mode, func(w io.Writer) error {
		_, err := io.Copy(w, in)
		return err
	})
}

func writeFile(path string, data []byte, mode fs.FileMode) error {
	return writeAtomic(path, mode, func(w io.Writer) error {
		_, err := w.Write(data)
		return err
	})
}

// writeAtomic пишет во временный файл рядом и переименовывает его на место:
// работающая служба и launchd никогда не видят полфайла.
func writeAtomic(path string, mode fs.FileMode, fill func(io.Writer) error) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	err = fill(tmp)
	if err == nil {
		err = tmp.Chmod(mode)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = own(tmp.Name())
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
