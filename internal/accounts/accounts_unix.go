//go:build unix

// Package accounts — учётные записи компьютера: кто вправе менять настройки.
package accounts

import (
	"os"
	"os/user"
	"slices"
	"strconv"
	"syscall"

	"appguard/internal/ipc"
)

// System — учётные записи этой системы.
type System struct{}

// IsAdmin — root или участник группы администраторов. Ошибка поиска — отказ:
// неизвестный пользователь настройки не меняет.
func (System) IsAdmin(p ipc.Peer) (bool, error) {
	uid := p.UID
	if uid == 0 {
		return true, nil
	}
	u, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		return false, err
	}
	gids, err := u.GroupIds()
	if err != nil {
		return false, err
	}
	for _, name := range adminGroups {
		// Такой группы в этой системе может не быть: на Ubuntu нет wheel.
		if g, err := user.LookupGroup(name); err == nil && slices.Contains(gids, g.Gid) {
			return true, nil
		}
	}
	return false, nil
}

// Owns — путь path принадлежит пользователю на другом конце канала.
func (System) Owns(p ipc.Peer, path string) (bool, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && p.UID >= 0 && st.Uid == uint32(p.UID), nil
}

// Name — имя пользователя для сообщений.
func (System) Name(p ipc.Peer) string {
	uid := p.UID
	if u, err := user.LookupId(strconv.Itoa(uid)); err == nil {
		return u.Username
	}
	return "uid " + strconv.Itoa(uid)
}
