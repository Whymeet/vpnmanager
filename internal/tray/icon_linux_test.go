package tray

import (
	"bufio"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
)

// bus поднимает настоящий dbus-daemon сеанса. Нет его в системе — тест пропускается:
// на шине проверяется то, что читают настоящие хосты.
func bus(t *testing.T) (address string, kill func()) {
	t.Helper()
	path, err := exec.LookPath("dbus-daemon")
	if err != nil {
		t.Skip("нет dbus-daemon")
	}
	cmd := exec.Command(path, "--session", "--nofork", "--nopidfile", "--print-address=1",
		"--address=unix:path="+filepath.Join(t.TempDir(), "bus"))
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	kill = func() {
		once.Do(func() {
			cmd.Process.Kill()
			cmd.Wait()
		})
	}
	t.Cleanup(kill)
	line, err := bufio.NewReader(out).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(line), kill
}

// session — сеанс с шиной и своим XDG_RUNTIME_DIR.
func session(t *testing.T) (addr string, kill func()) {
	t.Helper()
	addr, kill = bus(t)
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", addr)
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	return addr, kill
}

// watcher — хост: наблюдатель значков, каким его выставляет панель или расширение.
type watcher struct {
	seen chan string
}

func (w *watcher) RegisterStatusNotifierItem(service string) *dbus.Error {
	w.seen <- service
	return nil
}

func startWatcher(t *testing.T, addr string) (*watcher, *dbus.Conn) {
	t.Helper()
	conn, err := dbus.Connect(addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	w := &watcher{seen: make(chan string, 4)}
	if err := conn.Export(w, watcherPath, watcherName); err != nil {
		t.Fatal(err)
	}
	if r, err := conn.RequestName(watcherName, dbus.NameFlagDoNotQueue); err != nil || r != dbus.RequestNameReplyPrimaryOwner {
		t.Fatalf("имя наблюдателя: %v %v", r, err)
	}
	return w, conn
}

func registered(t *testing.T, w *watcher) string {
	t.Helper()
	select {
	case s := <-w.seen:
		return s
	case <-time.After(3 * time.Second):
		t.Fatal("значок не зарегистрировался у наблюдателя")
		return ""
	}
}

func hasOwner(t *testing.T, conn *dbus.Conn, name string) bool {
	t.Helper()
	var has bool
	if err := conn.BusObject().Call("org.freedesktop.DBus.NameHasOwner", 0, name).Store(&has); err != nil {
		t.Fatal(err)
	}
	return has
}

func TestNoSessionWithoutRuntimeDir(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "")
	if _, err := System(); !errors.Is(err, ErrNoSession) {
		t.Fatal(err)
	}
}

// Вход по SSH на сервер: шины нет. Значок выходит, а не заводит её через dbus-launch.
func TestNoSessionWithoutBus(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "")
	icon, err := System()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := icon.Show(); !errors.Is(err, ErrNoSession) {
		t.Fatalf("показ без шины: %v", err)
	}
}

// Шина сеанса исчезла, а значок, запущенный из install.sh, ещё жив: он выходит.
func TestDeadBusEndsSession(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path="+filepath.Join(t.TempDir(), "нет"))
	icon, err := System()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := icon.Show(); !errors.Is(err, ErrNoSession) {
		t.Fatalf("показ на мёртвой шине: %v", err)
	}
}

func TestSecondInstanceIsRefused(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	first, err := System()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := System(); !errors.Is(err, ErrBusy) {
		t.Fatalf("второй экземпляр: %v", err)
	}
	// Первый не тронут: блокировка всё ещё его.
	if _, err := System(); !errors.Is(err, ErrBusy) {
		t.Fatalf("после второго: %v", err)
	}
	// Первый ушёл — ядро сняло блокировку, следующий вход ставит значок.
	first.(*sni).lock.Close()
	if _, err := System(); err != nil {
		t.Fatal(err)
	}
}

func TestRegistersWithHost(t *testing.T) {
	addr, _ := session(t)
	w, conn := startWatcher(t, addr)
	icon, err := System()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := icon.Show(); err != nil {
		t.Fatal(err)
	}
	defer icon.Hide()
	name := registered(t, w)
	if !strings.HasPrefix(name, "org.kde.StatusNotifierItem-") || !strings.HasSuffix(name, "-1") {
		t.Fatalf("имя %q", name)
	}
	if !hasOwner(t, conn, name) {
		t.Fatal("значок зарегистрирован, а имя никому не принадлежит")
	}
}

// Хоста ещё нет — значок ждёт молча; пришёл — регистрируется; перезапустился —
// регистрируется снова.
func TestWaitsForHostAndFollowsItsRestart(t *testing.T) {
	addr, _ := session(t)
	icon, err := System()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := icon.Show(); err != nil {
		t.Fatalf("без хоста: %v", err)
	}
	defer icon.Hide()
	w, conn := startWatcher(t, addr)
	name := registered(t, w)
	conn.Close()
	w2, _ := startWatcher(t, addr)
	if again := registered(t, w2); again != name {
		t.Fatalf("после перезапуска хоста %q", again)
	}
}

// То, что читает хост. Типы проверяются подписями на шине: GNOME и KDE разбирают
// значения по ним, и ошибка здесь значит пустое место вместо значка.
func TestPropertiesAsHostsReadThem(t *testing.T) {
	addr, _ := session(t)
	w, _ := startWatcher(t, addr)
	icon, err := System()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := icon.Show(); err != nil {
		t.Fatal(err)
	}
	defer icon.Hide()
	name := registered(t, w)

	host, err := dbus.Connect(addr)
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	item := host.Object(name, itemPath)
	all := item.Call("org.freedesktop.DBus.Properties.GetAll", 0, itemIface)
	if all.Err != nil {
		t.Fatal(all.Err)
	}
	// Тело ответа как оно пришло: Store заворачивает значения заново и теряет подпись.
	props := all.Body[0].(map[string]dbus.Variant)
	for prop, sig := range map[string]string{
		"Id": "s", "Title": "s", "Category": "s", "Status": "s", "ItemIsMenu": "b",
		"IconPixmap": "a(iiay)", "ToolTip": "(sa(iiay)ss)", "Menu": "o",
	} {
		if got := props[prop].Signature().String(); got != sig {
			t.Errorf("%s: подпись %q, ждали %q", prop, got, sig)
		}
	}
	if props["Id"].Value() != "vpnlock" || props["Status"].Value() != "Active" || props["Category"].Value() != "SystemServices" {
		t.Errorf("%v", props)
	}
	if props["ItemIsMenu"].Value() != false {
		t.Error("значок объявлен меню")
	}
	// Без Menu расширение GNOME считает значок неготовым, /NO_DBUSMENU для него то же.
	if path, _ := props["Menu"].Value().(dbus.ObjectPath); path == "" || path == "/NO_DBUSMENU" {
		t.Errorf("Menu = %q", path)
	}

	var pixmaps []pixmap
	if err := dbus.Store([]any{props["IconPixmap"].Value()}, &pixmaps); err != nil {
		t.Fatal(err)
	}
	if len(pixmaps) != 1 || pixmaps[0].Width != 64 || pixmaps[0].Height != 64 || len(pixmaps[0].Pixels) != 64*64*4 {
		t.Fatalf("значок: %d штук", len(pixmaps))
	}
	// ARGB в сетевом порядке: альфа — первым байтом. Так читает расширение GNOME
	// (pixmapsUtils.js: src[j] — альфа, src[j+1] — красный).
	px := pixmaps[0].Pixels
	if px[0] != 0 {
		t.Errorf("альфа угла %d", px[0])
	}
	at := func(x, y int) []byte { return px[(y*64+x)*4 : (y*64+x)*4+4] }
	if a := at(32, 28); a[0] != 255 || a[1] != 255 || a[2] != 255 || a[3] != 255 {
		t.Errorf("скважина %v", a)
	}
	if a := at(14, 30); a[0] != 255 || a[2] <= a[1] || a[2] <= a[3] {
		t.Errorf("щит не зелёный: %v", a)
	}

	var introspection string
	if err := item.Call("org.freedesktop.DBus.Introspectable.Introspect", 0).Store(&introspection); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(introspection, itemIface) || !strings.Contains(introspection, "Activate") {
		t.Errorf("описание объекта: %s", introspection)
	}
	if err := item.Call(itemIface+".Activate", 0, int32(1), int32(2)).Err; err != nil {
		t.Errorf("Activate: %v", err)
	}
}

// Меню есть только для хоста: пунктов в нём нет, поэтому щелчок ничего не открывает.
func TestMenuIsEmpty(t *testing.T) {
	addr, _ := session(t)
	w, _ := startWatcher(t, addr)
	icon, err := System()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := icon.Show(); err != nil {
		t.Fatal(err)
	}
	defer icon.Hide()
	name := registered(t, w)

	host, err := dbus.Connect(addr)
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	menu := host.Object(name, menuPath)
	call := menu.Call(menuIface+".GetLayout", 0, int32(0), int32(-1), []string{"type", "children-display"})
	if call.Err != nil {
		t.Fatal(call.Err)
	}
	var (
		revision uint32
		layout   menuNode
	)
	if err := call.Store(&revision, &layout); err != nil {
		t.Fatal(err)
	}
	if layout.ID != 0 || len(layout.Children) != 0 {
		t.Fatalf("меню не пустое: %+v", layout)
	}
	if err := menu.Call(menuIface+".GetGroupProperties", 0, []int32{0}, []string{}).Err; err != nil {
		t.Error(err)
	}
	if err := menu.Call(menuIface+".AboutToShow", 0, int32(0)).Err; err != nil {
		t.Error(err)
	}
	if err := menu.Call(menuIface+".Event", 0, int32(0), "opened", dbus.MakeVariant(""), uint32(0)).Err; err != nil {
		t.Error(err)
	}
	var version dbus.Variant
	if err := menu.Call("org.freedesktop.DBus.Properties.Get", 0, menuIface, "Version").Store(&version); err != nil {
		t.Fatal(err)
	}
	if version.Value() != uint32(3) {
		t.Errorf("Version = %v", version)
	}
}

// Скрыть значок — закрыть соединение; хост видит, что имя ушло. Показать снова можно.
func TestHideDropsNameAndShowReturnsIt(t *testing.T) {
	addr, _ := session(t)
	w, conn := startWatcher(t, addr)
	icon, err := System()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := icon.Show(); err != nil {
		t.Fatal(err)
	}
	name := registered(t, w)
	icon.Hide()
	deadline := time.Now().Add(2 * time.Second)
	for hasOwner(t, conn, name) {
		if time.Now().After(deadline) {
			t.Fatal("имя осталось после скрытия")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if _, err := icon.Show(); err != nil {
		t.Fatal(err)
	}
	defer icon.Hide()
	if again := registered(t, w); again != name {
		t.Fatalf("после нового показа %q", again)
	}
}

// Шина умерла под показанным значком: это конец сеанса, а не повод стучаться в неё.
func TestLostBusEndsSession(t *testing.T) {
	_, kill := session(t)
	icon, err := System()
	if err != nil {
		t.Fatal(err)
	}
	died, err := icon.Show()
	if err != nil {
		t.Fatal(err)
	}
	kill()
	select {
	case err := <-died:
		if !errors.Is(err, ErrNoSession) {
			t.Fatalf("причина: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("значок не заметил смерти шины")
	}
	if _, err := os.Stat(strings.TrimPrefix(os.Getenv("DBUS_SESSION_BUS_ADDRESS"), "unix:path=")); err == nil {
		// Файл сокета может остаться, важно, что подключиться нельзя.
		if _, err := icon.Show(); !errors.Is(err, ErrNoSession) {
			t.Fatalf("новый показ: %v", err)
		}
	}
}
