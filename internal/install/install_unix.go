//go:build darwin || linux

package install

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// commandFree — место команды appguard свободно или уже занято ею. Чужой файл с
// тем же именем установка не перезаписывает.
func (in *Installer) commandFree() error {
	ours, err := in.commandIsOurs()
	switch {
	case ours, errors.Is(err, fs.ErrNotExist):
		return nil
	case err == nil:
		return fmt.Errorf("%s уже есть, и это не команда appguard. Убери его и запусти установку ещё раз — в системе ничего не изменено", in.Layout.CommandLink)
	}
	return err
}

// linkCommand кладёт команду appguard в /usr/local/bin.
func (in *Installer) linkCommand() error {
	if ours, _ := in.commandIsOurs(); ours {
		return nil
	}
	if err := in.commandFree(); err != nil {
		return err
	}
	link := in.Layout.CommandLink
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		return err
	}
	return os.Symlink(in.Layout.Binary, link)
}

// commandIsOurs — команда в PATH ведёт на исполняемый файл установки. Ошибка
// fs.ErrNotExist значит, что на её месте ничего нет.
func (in *Installer) commandIsOurs() (bool, error) {
	if _, err := os.Lstat(in.Layout.CommandLink); err != nil {
		return false, err
	}
	target, err := os.Readlink(in.Layout.CommandLink)
	return err == nil && target == in.Layout.Binary, nil
}

// mkdir создаёт каталог установки с правами mode. Под root владельцем становится
// root:wheel: на macOS новый каталог иначе наследует группу родителя (admin у
// /Library/Application Support).
func mkdir(path string, mode fs.FileMode) error {
	if err := os.MkdirAll(path, mode); err != nil {
		return err
	}
	if err := os.Chmod(path, mode); err != nil {
		return err
	}
	return own(path)
}

// own делает root:wheel владельцем установленных файлов. Не под root (тесты)
// владельца менять незачем и нельзя.
func own(path string) error {
	if os.Geteuid() != 0 {
		return nil
	}
	return os.Lchown(path, 0, 0)
}
