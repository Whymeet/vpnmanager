package accounts

import (
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"testing"

	"appguard/internal/ipc"
)

// Решение о правах сверяется с самой macOS: dsmemberutil — её ответ на вопрос
// «состоит ли пользователь в группе admin».
func TestAdminMatchesSystem(t *testing.T) {
	var a System
	if ok, err := a.IsAdmin(ipc.Peer{UID: 0}); !ok || err != nil {
		t.Fatalf("root не администратор: %v", err)
	}

	me, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("dsmemberutil", "checkmembership", "-U", me.Username, "-G", adminGroups[0]).Output()
	if err != nil {
		t.Skipf("dsmemberutil недоступен: %v", err)
	}
	want := strings.TrimSpace(string(out)) == "user is a member of the group"
	if got, err := a.IsAdmin(ipc.Peer{UID: os.Getuid()}); got != want || err != nil {
		t.Fatalf("%s: служба решила %v (%v), а macOS говорит %v", me.Username, got, err, want)
	}

	// Системная учётная запись daemon в группе admin не состоит.
	d, err := user.Lookup("daemon")
	if err != nil {
		t.Skip("нет учётной записи daemon")
	}
	uid, _ := strconv.Atoi(d.Uid)
	if ok, _ := a.IsAdmin(ipc.Peer{UID: uid}); ok {
		t.Fatal("daemon признан администратором")
	}
}
