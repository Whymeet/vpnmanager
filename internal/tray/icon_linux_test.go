package tray

import (
	"bufio"
	"errors"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
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

var closedView = View{Title: "Приложения без сети", Detail: "VPN выключен", Notify: true}

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
	if _, err := icon.Show(closedView, func() {}); !errors.Is(err, ErrNoSession) {
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
	if _, err := icon.Show(closedView, func() {}); !errors.Is(err, ErrNoSession) {
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
	if _, err := icon.Show(closedView, func() {}); err != nil {
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
	if _, err := icon.Show(closedView, func() {}); err != nil {
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
	if _, err := icon.Show(closedView, func() {}); err != nil {
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
	if props["Id"].Value() != "appguard" || props["Status"].Value() != "Active" || props["Category"].Value() != "SystemServices" {
		t.Errorf("%v", props)
	}
	// Значок — только меню: левый щелчок его открывает и в KDE, и в GNOME.
	if props["ItemIsMenu"].Value() != true {
		t.Error("значок не объявлен меню")
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
	// Сервисы закрыты — перечёркнутый щит: черта красная, щит серый.
	if a := at(32, 32); a[0] != 255 || a[1] < 180 || a[2] > 90 || a[3] > 90 {
		t.Errorf("черта %v", a)
	}
	if a := at(44, 22); a[0] != 255 || a[1] != a[2] || a[2] != a[3] {
		t.Errorf("щит не серый: %v", a)
	}
	var tip toolTip
	if err := dbus.Store([]any{props["ToolTip"].Value()}, &tip); err != nil {
		t.Fatal(err)
	}
	if tip.Title != "appguard" || tip.Text != "Приложения без сети. VPN выключен" {
		t.Errorf("подсказка %+v", tip)
	}

	// Без Activate в описании GNOME открывает меню левым щелчком сразу, а не ждёт
	// двойного (indicatorStatusIcon.js).
	var introspection string
	if err := item.Call("org.freedesktop.DBus.Introspectable.Introspect", 0).Store(&introspection); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(introspection, itemIface) || strings.Contains(introspection, `"Activate"`) {
		t.Errorf("описание объекта: %s", introspection)
	}
}

// shown — значок с хостом; toggles считает выборы «Уведомления».
func shown(t *testing.T) (icon Icon, host *dbus.Conn, name string, toggles *int32) {
	t.Helper()
	addr, _ := session(t)
	w, _ := startWatcher(t, addr)
	icon, err := System()
	if err != nil {
		t.Fatal(err)
	}
	toggles = new(int32)
	if _, err := icon.Show(closedView, func() { atomic.AddInt32(toggles, 1) }); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(icon.Hide)
	name = registered(t, w)
	host, err = dbus.Connect(addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { host.Close() })
	return icon, host, name, toggles
}

// layout — раскладка меню, как её спрашивает GNOME: только type и children-display.
func layout(t *testing.T, menu dbus.BusObject) map[int32]map[string]any {
	t.Helper()
	call := menu.Call(menuIface+".GetLayout", 0, int32(0), int32(-1), []string{"type", "children-display"})
	if call.Err != nil {
		t.Fatal(call.Err)
	}
	var (
		revision uint32
		root     menuNode
	)
	if err := call.Store(&revision, &root); err != nil {
		t.Fatal(err)
	}
	if root.ID != 0 || root.Props["children-display"].Value() != "submenu" {
		t.Fatalf("корень %+v", root)
	}
	items := map[int32]map[string]any{}
	var order []int32
	for _, c := range root.Children {
		var n menuNode
		if err := dbus.Store([]any{c.Value()}, &n); err != nil {
			t.Fatal(err)
		}
		props := map[string]any{}
		for k, v := range n.Props {
			props[k] = v.Value()
		}
		items[n.ID] = props
		order = append(order, n.ID)
	}
	if len(order) != 4 {
		t.Fatalf("пункты %v", order)
	}
	return items
}

// Меню: заголовок и строка под ним (не нажимаются), черта и «Уведомления» с отметкой. Подписи
// приходят и в раскладке: GNOME спрашивает её только с type, но берёт всё, что в ней.
func TestMenuAsHostsReadIt(t *testing.T) {
	_, host, name, toggles := shown(t)
	menu := host.Object(name, menuPath)
	items := layout(t, menu)
	if p := items[itemTitle]; p["label"] != closedView.Title || p["enabled"] != false {
		t.Errorf("заголовок %v", p)
	}
	if p := items[itemDetail]; p["label"] != closedView.Detail || p["enabled"] != false || p["visible"] != true {
		t.Errorf("строка под заголовком %v", p)
	}
	if p := items[itemLine]; p["type"] != "separator" {
		t.Errorf("черта %v", p)
	}
	if p := items[itemNotify]; p["label"] != NotifyItem || p["toggle-type"] != "checkmark" || p["toggle-state"] != int32(1) {
		t.Errorf("уведомления %v", p)
	}

	var props []menuProps
	if err := menu.Call(menuIface+".GetGroupProperties", 0, []int32{itemNotify}, []string{"label"}).Store(&props); err != nil {
		t.Fatal(err)
	}
	if len(props) != 1 || props[0].ID != itemNotify || len(props[0].Props) != 1 || props[0].Props["label"].Value() != NotifyItem {
		t.Errorf("свойства %+v", props)
	}
	if err := menu.Call(menuIface+".AboutToShow", 0, int32(0)).Err; err != nil {
		t.Error(err)
	}
	if err := menu.Call(menuIface+".Event", 0, int32(0), "opened", dbus.MakeVariant(""), uint32(0)).Err; err != nil {
		t.Error(err)
	}
	if n := atomic.LoadInt32(toggles); n != 0 {
		t.Fatalf("меню открыли — а уведомления переключились %d раз", n)
	}
	// Так щелчок шлёт GNOME (dbusMenu.js): «clicked» с числом 0.
	if err := menu.Call(menuIface+".Event", 0, itemNotify, "clicked", dbus.MakeVariant(int32(0)), uint32(0)).Err; err != nil {
		t.Fatal(err)
	}
	var missing []int32
	err := menu.Call(menuIface+".EventGroup", 0, []menuEvent{{itemNotify, "clicked", dbus.MakeVariant(int32(0)), 0}, {42, "clicked", dbus.MakeVariant(int32(0)), 0}}).Store(&missing)
	if err != nil || len(missing) != 1 || missing[0] != 42 {
		t.Errorf("EventGroup: %v %v", missing, err)
	}
	if n := atomic.LoadInt32(toggles); n != 2 {
		t.Fatalf("выбор «Уведомления» дошёл %d раз из 2", n)
	}
	var version dbus.Variant
	if err := menu.Call("org.freedesktop.DBus.Properties.Get", 0, menuIface, "Version").Store(&version); err != nil {
		t.Fatal(err)
	}
	if version.Value() != uint32(3) {
		t.Errorf("Version = %v", version)
	}
}

// Новый вид: картинка, подсказка и меню меняются, а хост узнаёт об этом сигналами
// NewIcon, NewToolTip и ItemsPropertiesUpdated.
func TestUpdateTellsTheHost(t *testing.T) {
	icon, host, name, _ := shown(t)
	signals := make(chan *dbus.Signal, 16)
	host.Signal(signals)
	if err := host.AddMatchSignal(dbus.WithMatchSender(name)); err != nil {
		t.Fatal(err)
	}
	open := View{Open: true, Title: "Приложения в сети", Detail: "Выход 185.1.2.3, Германия", Notify: false}
	icon.Update(open)
	want := map[string]bool{itemIface + ".NewIcon": false, itemIface + ".NewToolTip": false, menuIface + ".ItemsPropertiesUpdated": false}
	var updated []menuProps
	for deadline := time.After(3 * time.Second); slices.Contains(slices.Collect(maps.Values(want)), false); {
		select {
		case sig := <-signals:
			if _, ok := want[sig.Name]; ok {
				want[sig.Name] = true
			}
			if sig.Name == menuIface+".ItemsPropertiesUpdated" {
				if err := dbus.Store(sig.Body[:1], &updated); err != nil {
					t.Fatal(err)
				}
			}
		case <-deadline:
			t.Fatalf("сигналы %v", want)
		}
	}
	got := map[int32]map[string]dbus.Variant{}
	for _, u := range updated {
		got[u.ID] = u.Props
	}
	if got[itemTitle]["label"].Value() != open.Title || got[itemDetail]["label"].Value() != open.Detail || got[itemNotify]["toggle-state"].Value() != int32(0) {
		t.Errorf("ItemsPropertiesUpdated %v", updated)
	}

	item := host.Object(name, itemPath)
	var pixmaps []pixmap
	v, err := item.GetProperty(itemIface + ".IconPixmap")
	if err != nil {
		t.Fatal(err)
	}
	if err := dbus.Store([]any{v.Value()}, &pixmaps); err != nil {
		t.Fatal(err)
	}
	// Открыто — зелёный щит, без черты.
	if a := pixmaps[0].Pixels[(30*64+14)*4:][:4]; a[0] != 255 || a[2] <= a[1] || a[2] <= a[3] {
		t.Errorf("щит не зелёный: %v", a)
	}
	items := layout(t, host.Object(name, menuPath))
	if items[itemTitle]["label"] != open.Title || items[itemDetail]["label"] != open.Detail || items[itemNotify]["toggle-state"] != int32(0) {
		t.Errorf("раскладка после смены %v", items)
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
	if _, err := icon.Show(closedView, func() {}); err != nil {
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
	if _, err := icon.Show(closedView, func() {}); err != nil {
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
	died, err := icon.Show(closedView, func() {})
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
		if _, err := icon.Show(closedView, func() {}); !errors.Is(err, ErrNoSession) {
			t.Fatalf("новый показ: %v", err)
		}
	}
}
