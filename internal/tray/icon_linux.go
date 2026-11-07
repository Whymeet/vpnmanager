package tray

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/introspect"
	"github.com/godbus/dbus/v5/prop"
)

const (
	watcherName = "org.kde.StatusNotifierWatcher"
	watcherPath = dbus.ObjectPath("/StatusNotifierWatcher")
	itemIface   = "org.kde.StatusNotifierItem"
	itemPath    = dbus.ObjectPath("/StatusNotifierItem")
	menuIface   = "com.canonical.dbusmenu"
	menuPath    = dbus.ObjectPath("/StatusNotifierItem/Menu")
	iconSize    = 64
)

// pixmap — значок в свойстве IconPixmap (iiay): ARGB32 в сетевом порядке байт.
type pixmap struct {
	Width, Height int32
	Pixels        []byte
}

// toolTip — подсказка (sa(iiay)ss): значок по имени, значок картинкой, заголовок, текст.
type toolTip struct {
	IconName string
	Icons    []pixmap
	Title    string
	Text     string
}

// sni показывает значок по протоколу StatusNotifierItem. Показан значок — открыто
// соединение с шиной сеанса: хост сам уберёт его, когда соединение закроется.
type sni struct {
	lock *os.File // держится открытым: первый экземпляр жив, пока жив этот файл
	conn *dbus.Conn
}

// System — показ значка в этом сеансе. Один экземпляр на пользователя: flock файла в
// XDG_RUNTIME_DIR, его снимает ядро, как бы процесс ни завершился.
func System() (Icon, error) {
	dir := os.Getenv("XDG_RUNTIME_DIR")
	if dir == "" {
		return nil, ErrNoSession
	}
	f, err := os.OpenFile(filepath.Join(dir, "vpnlock-tray.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, ErrBusy
		}
		return nil, err
	}
	return &sni{lock: f}, nil
}

// busAddress — адрес шины сеанса; пусто — шины нет. dbus.ConnectSessionBus не годится:
// без адреса он сам запускает dbus-launch, а на сервере заводить шину незачем.
func busAddress() string {
	if a := os.Getenv("DBUS_SESSION_BUS_ADDRESS"); a != "" && a != "autolaunch:" {
		return a
	}
	if dir := os.Getenv("XDG_RUNTIME_DIR"); dir != "" {
		p := filepath.Join(dir, "bus")
		if fi, err := os.Stat(p); err == nil && fi.Mode()&fs.ModeSocket != 0 {
			return "unix:path=" + dbus.EscapeBusAddressValue(p)
		}
	}
	return ""
}

// Show не ждёт хоста: его может ещё не быть (расширение включили позже, GNOME Shell
// перезапускается). Сбой подключения к шине — тоже конец сеанса: запущенный из
// install.sh значок переживает выход из системы, и если бы он продолжал стучаться,
// при следующем входе рядом с автозапуском появился бы второй.
func (s *sni) Show() (<-chan error, error) {
	addr := busAddress()
	if addr == "" {
		return nil, ErrNoSession
	}
	conn, err := dbus.Connect(addr)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoSession, err)
	}
	name := fmt.Sprintf("org.kde.StatusNotifierItem-%d-1", os.Getpid())
	if err := export(conn, name); err != nil {
		conn.Close()
		return nil, err
	}
	signals := make(chan *dbus.Signal, 8)
	conn.Signal(signals)
	err = conn.AddMatchSignal(
		dbus.WithMatchSender("org.freedesktop.DBus"),
		dbus.WithMatchObjectPath("/org/freedesktop/DBus"),
		dbus.WithMatchInterface("org.freedesktop.DBus"),
		dbus.WithMatchMember("NameOwnerChanged"),
		dbus.WithMatchArg(0, watcherName))
	if err != nil {
		conn.Close()
		return nil, err
	}
	s.conn = conn
	died := make(chan error, 1)
	go follow(conn, name, signals, died)
	return died, nil
}

func (s *sni) Hide() {
	if s.conn != nil {
		s.conn.Close()
		s.conn = nil
	}
}

// follow регистрирует значок у хоста и заново — когда хост появляется. Закрытое
// соединение значит одно из двух: его закрыл Hide (тогда died уже никто не читает)
// или шины больше нет.
func follow(conn *dbus.Conn, name string, signals <-chan *dbus.Signal, died chan<- error) {
	register(conn, name)
	for {
		select {
		case <-conn.Context().Done():
			died <- ErrNoSession
			return
		case sig, ok := <-signals:
			if !ok {
				died <- ErrNoSession
				return
			}
			if hostAppeared(sig) {
				register(conn, name)
			}
		}
	}
}

// hostAppeared — у имени наблюдателя появился новый владелец.
func hostAppeared(sig *dbus.Signal) bool {
	if sig.Name != "org.freedesktop.DBus.NameOwnerChanged" || len(sig.Body) != 3 {
		return false
	}
	name, _ := sig.Body[0].(string)
	owner, _ := sig.Body[2].(string)
	return name == watcherName && owner != ""
}

// register молчит, если хоста нет: значок появится, когда он придёт.
func register(conn *dbus.Conn, name string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn.Object(watcherName, watcherPath).CallWithContext(ctx,
		watcherName+".RegisterStatusNotifierItem", dbus.FlagNoAutoStart, name)
}

// export выставляет значок на шину под именем name.
func export(conn *dbus.Conn, name string) error {
	icon := []pixmap{argb(iconSize)}
	constant := func(v any) *prop.Prop { return &prop.Prop{Value: v, Emit: prop.EmitConst} }
	_, err := prop.Export(conn, itemPath, prop.Map{itemIface: {
		"Id":         constant("vpnlock"),
		"Title":      constant("vpnlock"),
		"Category":   constant("SystemServices"),
		"Status":     constant("Active"),
		"WindowId":   constant(int32(0)),
		"IconName":   constant(""),
		"IconPixmap": constant(icon),
		"ToolTip":    constant(toolTip{Title: "vpnlock работает", Icons: []pixmap{}}),
		"ItemIsMenu": constant(false),
		// Без Menu расширение GNOME считает значок неготовым и не показывает его
		// (appIndicator.js, _checkIfReady, версии 42, 46 и 58). Поэтому меню есть, но
		// пустое: щелчок по значку ничего не открывает.
		"Menu": constant(menuPath),
	}})
	if err != nil {
		return err
	}
	_, err = prop.Export(conn, menuPath, prop.Map{menuIface: {
		"Version":       constant(uint32(3)),
		"TextDirection": constant("ltr"),
		"Status":        constant("normal"),
		"IconThemePath": constant([]string{}),
	}})
	if err != nil {
		return err
	}
	if err := conn.Export(item{}, itemPath, itemIface); err != nil {
		return err
	}
	if err := conn.Export(emptyMenu{}, menuPath, menuIface); err != nil {
		return err
	}
	// Расширение GNOME узнаёт из описания объекта, есть ли у значка Activate.
	for _, o := range []struct {
		path  dbus.ObjectPath
		iface introspect.Interface
	}{
		{itemPath, introspect.Interface{Name: itemIface, Methods: introspect.Methods(item{})}},
		{menuPath, introspect.Interface{Name: menuIface, Methods: introspect.Methods(emptyMenu{})}},
	} {
		node := &introspect.Node{Name: string(o.path), Interfaces: []introspect.Interface{prop.IntrospectData, o.iface}}
		if err := conn.Export(introspect.NewIntrospectable(node), o.path, "org.freedesktop.DBus.Introspectable"); err != nil {
			return err
		}
	}
	reply, err := conn.RequestName(name, dbus.NameFlagDoNotQueue)
	if err != nil {
		return err
	}
	if reply != dbus.RequestNameReplyPrimaryOwner {
		return fmt.Errorf("имя %s занято", name)
	}
	return nil
}

// argb — значок со стороной size в формате IconPixmap.
func argb(size int) pixmap {
	img := shield(size)
	px := make([]byte, 0, size*size*4)
	for i := 0; i < len(img.Pix); i += 4 {
		px = append(px, img.Pix[i+3], img.Pix[i], img.Pix[i+1], img.Pix[i+2])
	}
	return pixmap{int32(size), int32(size), px}
}

// item — методы значка. Значок ничего не делает: это только индикатор.
type item struct{}

func (item) Activate(x, y int32) *dbus.Error          { return nil }
func (item) SecondaryActivate(x, y int32) *dbus.Error { return nil }
func (item) ContextMenu(x, y int32) *dbus.Error       { return nil }
func (item) Scroll(delta int32, how string) *dbus.Error {
	return nil
}

// menuNode — пункт меню dbusmenu (ia{sv}av): номер, свойства, дочерние пункты.
type menuNode struct {
	ID       int32
	Props    map[string]dbus.Variant
	Children []dbus.Variant
}

// menuProps — свойства пункта (ia{sv}).
type menuProps struct {
	ID    int32
	Props map[string]dbus.Variant
}

// emptyMenu — меню без пунктов: то, что хосты спрашивают у значка с Menu.
type emptyMenu struct{}

func rootProps() map[string]dbus.Variant {
	return map[string]dbus.Variant{"children-display": dbus.MakeVariant("submenu")}
}

func (emptyMenu) GetLayout(parent, depth int32, names []string) (uint32, menuNode, *dbus.Error) {
	return 1, menuNode{Props: rootProps(), Children: []dbus.Variant{}}, nil
}

func (emptyMenu) GetGroupProperties(ids []int32, names []string) ([]menuProps, *dbus.Error) {
	return []menuProps{{Props: rootProps()}}, nil
}

func (emptyMenu) AboutToShow(id int32) (bool, *dbus.Error) { return false, nil }

func (emptyMenu) Event(id int32, event string, data dbus.Variant, timestamp uint32) *dbus.Error {
	return nil
}
