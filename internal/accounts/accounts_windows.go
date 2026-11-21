// Package accounts — учётные записи компьютера: кто вправе менять настройки.
package accounts

import (
	"strconv"

	"golang.org/x/sys/windows"

	"appguard/internal/ipc"
)

// System — учётные записи этой системы.
type System struct{}

// IsAdmin — клиент пришёл по каналу администратора. Права проверила Windows,
// когда пускала его в этот канал: туда попадают только программы, запущенные от
// имени администратора.
func (System) IsAdmin(p ipc.Peer) (bool, error) { return p.Admin, nil }

// Owns — владелец пути path — учётная запись процесса на другом конце канала.
// Повышен процесс или нет, не важно: так задача каталога, которая работает без
// повышения, показывает, что клон её.
func (System) Owns(p ipc.Peer, path string) (bool, error) {
	if p.PID <= 0 {
		return false, nil
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(p.PID))
	if err != nil {
		return false, err
	}
	defer windows.CloseHandle(h)
	var tok windows.Token
	if err := windows.OpenProcessToken(h, windows.TOKEN_QUERY, &tok); err != nil {
		return false, err
	}
	defer tok.Close()
	u, err := tok.GetTokenUser()
	if err != nil {
		return false, err
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return false, err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return false, err
	}
	return owner.Equals(u.User.Sid), nil
}

// Name — кто это, для журнала службы. На Windows права решает запуск от имени
// администратора, а не учётная запись, поэтому служба называет процесс.
func (System) Name(p ipc.Peer) string {
	if p.PID > 0 {
		return "процесс " + strconv.Itoa(p.PID)
	}
	return "клиент"
}
