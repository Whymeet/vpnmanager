//go:build live

// Живая проверка исполнителя на стенде Windows — из PowerShell от имени
// администратора: go test -tags live -v -run WFP ./internal/enforce
// Под фильтры ставится копия curl.exe во временной папке, системный curl и
// остальные программы не трогаются.

package enforce

import (
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"vpnlock/internal/netwatch"
)

func TestLiveWFPLetsAppOutOnlyFromOpenAddrs(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("нужен PowerShell от имени администратора")
	}
	sys, err := windows.GetSystemDirectory()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(sys, "curl.exe"))
	if err != nil {
		t.Skipf("нет curl.exe: %v", err)
	}
	exe := filepath.Join(t.TempDir(), "vpnlock-live-curl.exe")
	if err := os.WriteFile(exe, data, 0o755); err != nil {
		t.Fatal(err)
	}
	// Адрес физического адаптера играет роль адреса проверенного туннеля.
	name, index, ok := netwatch.Physical()
	if !ok {
		t.Skip("нет физического адаптера")
	}
	local := ipv4Of(t, index)
	t.Logf("физический адаптер %s, адрес %s", name, local)

	get := func() error {
		out, err := exec.Command(exe, "-sS", "-m", "5", "-o", os.DevNull, "https://1.1.1.1/cdn-cgi/trace").CombinedOutput()
		if err != nil {
			t.Logf("curl: %v: %s", err, out)
		}
		return err
	}
	if err := get(); err != nil {
		t.Fatal("без фильтров копия curl не выходит в сеть — проверять нечего")
	}

	w := &WFP{StateFile: filepath.Join(t.TempDir(), "wfp.json"), Logf: t.Logf}
	t.Cleanup(func() {
		if err := w.Clear(); err != nil {
			t.Errorf("Clear: %v", err)
		}
	})
	closed := Rules{Apps: []string{exe}}
	if err := w.Apply(closed); err != nil {
		t.Fatal(err)
	}
	if err := w.Verify(closed); err != nil {
		t.Fatalf("Verify сразу после Apply: %v", err)
	}
	if get() == nil {
		t.Fatal("под запретом копия curl вышла в сеть")
	}

	open := Rules{Apps: []string{exe}, OpenAddrs: []netip.Addr{local}}
	if err := w.Apply(open); err != nil {
		t.Fatal(err)
	}
	if err := get(); err != nil {
		t.Fatalf("с разрешением адреса %s копия curl не вышла в сеть", local)
	}

	if err := w.Apply(closed); err != nil {
		t.Fatal(err)
	}
	if get() == nil {
		t.Fatal("разрешение снято, а копия curl вышла в сеть")
	}

	if err := w.Clear(); err != nil {
		t.Fatal(err)
	}
	if err := get(); err != nil {
		t.Fatal("после Clear копия curl не выходит в сеть")
	}
	if w.Verify(closed) == nil {
		t.Fatal("после Clear Verify не заметил, что фильтров нет")
	}
}

// Новая программа в папке защищённого приложения встаёт под запрет, как
// только появится: так обновление не снимает защиту.
func TestLiveWFPPicksUpNewExeInAppFolder(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("нужен PowerShell от имени администратора")
	}
	sys, err := windows.GetSystemDirectory()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(sys, "curl.exe"))
	if err != nil {
		t.Skipf("нет curl.exe: %v", err)
	}
	app := filepath.Join(t.TempDir(), "VpnlockLiveApp")
	os.MkdirAll(app, 0o755)
	old := filepath.Join(app, "app.exe")
	os.WriteFile(old, data, 0o755)
	get := func(exe string) error {
		return exec.Command(exe, "-sS", "-m", "5", "-o", os.DevNull, "https://1.1.1.1/cdn-cgi/trace").Run()
	}
	w := &WFP{StateFile: filepath.Join(t.TempDir(), "wfp.json"), Logf: t.Logf}
	t.Cleanup(func() { w.Clear() })
	if err := w.Apply(Rules{Apps: []string{app}}); err != nil {
		t.Fatal(err)
	}
	if get(old) == nil {
		t.Fatal("программа из папки приложения вышла в сеть")
	}
	// «Обновление»: новая версия в своей папке.
	newer := filepath.Join(app, "app-2.0", "app.exe")
	os.MkdirAll(filepath.Dir(newer), 0o755)
	os.WriteFile(newer, data, 0o755)
	time.Sleep(settleChanges + 2*time.Second)
	if get(newer) == nil {
		t.Fatal("новая версия вышла в сеть: фильтр на неё не встал")
	}
}

// Адрес защищённого сервиса закрыт для любой программы, кроме соединений с
// адреса проверенного туннеля: так сайт сервиса не откроется в браузере.
func TestLiveWFPClosesServiceAddressForAllPrograms(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("нужен PowerShell от имени администратора")
	}
	sys, err := windows.GetSystemDirectory()
	if err != nil {
		t.Fatal(err)
	}
	curl := filepath.Join(sys, "curl.exe")
	get := func() error {
		return exec.Command(curl, "-sS", "-m", "5", "-o", os.DevNull, "https://1.1.1.1/cdn-cgi/trace").Run()
	}
	if get() != nil {
		t.Skip("без фильтров curl не выходит в сеть — проверять нечего")
	}
	_, index, ok := netwatch.Physical()
	if !ok {
		t.Skip("нет физического адаптера")
	}
	local := ipv4Of(t, index)
	service := netip.MustParseAddr("1.1.1.1")
	w := &WFP{StateFile: filepath.Join(t.TempDir(), "wfp.json"), Logf: t.Logf}
	t.Cleanup(func() { w.Clear() })

	closed := Rules{V4: []netip.Addr{service}}
	if err := w.Apply(closed); err != nil {
		t.Fatal(err)
	}
	if err := w.Verify(closed); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if get() == nil {
		t.Fatal("адрес сервиса закрыт, а системный curl до него дошёл")
	}
	// Адрес физического адаптера — в роли проверенного туннеля.
	if err := w.Apply(Rules{V4: []netip.Addr{service}, OpenAddrs: []netip.Addr{local}}); err != nil {
		t.Fatal(err)
	}
	if err := get(); err != nil {
		t.Fatalf("с проверенного адреса curl до сервиса не дошёл: %v", err)
	}
	// Сервер VPN на адресе сервиса открыт и без туннеля.
	if err := w.Apply(Rules{V4: []netip.Addr{service}, Servers: []netip.Addr{service}}); err != nil {
		t.Fatal(err)
	}
	if err := get(); err != nil {
		t.Fatalf("сервер VPN на адресе сервиса закрыт: %v", err)
	}
}

func ipv4Of(t *testing.T, index int) netip.Addr {
	t.Helper()
	ifi, err := net.InterfaceByIndex(index)
	if err != nil {
		t.Fatal(err)
	}
	addrs, _ := ifi.Addrs()
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(ipn.IP); ok && ip.Unmap().Is4() {
				return ip.Unmap()
			}
		}
	}
	t.Fatalf("у адаптера %s нет IPv4", ifi.Name)
	return netip.Addr{}
}
