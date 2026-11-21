package tray

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
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
	lock  *os.File // держится открытым: первый экземпляр жив, пока жив этот файл
	conn  *dbus.Conn
	props *prop.Properties
	menu  *menu
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
func (s *sni) Show(v View, toggle func()) (<-chan error, error) {
	addr := busAddress()
	if addr == "" {
		return nil, ErrNoSession
	}
	conn, err := dbus.Connect(addr)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoSession, err)
	}
	name := fmt.Sprintf("org.kde.StatusNotifierItem-%d-1", os.Getpid())
	m := &menu{conn: conn, toggle: toggle, view: v}
	props, err := export(conn, name, v, m)
	if err != nil {
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
	s.conn, s.props, s.menu = conn, props, m
	died := make(chan error, 1)
	go follow(conn, name, signals, died)
	return died, nil
}

// Update меняет картинку и подсказку и говорит об этом хосту сигналами: свойства
// значка хосты перечитывают по ним, а не по PropertiesChanged. Меню хост узнаёт из
// ItemsPropertiesUpdated.
func (s *sni) Update(v View) {
	if s.conn == nil {
		return
	}
	s.props.SetMust(itemIface, "IconPixmap", icons(v.Open))
	s.props.SetMust(itemIface, "ToolTip", tip(v))
	s.conn.Emit(itemPath, itemIface+".NewIcon")
	s.conn.Emit(itemPath, itemIface+".NewToolTip")
	s.menu.set(v)
}

func (s *sni) Hide() {
	if s.conn != nil {
		s.conn.Close()
		s.conn, s.props, s.menu = nil, nil, nil
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

// icons — картинка значка: щит или перечёркнутый щит.
func icons(open bool) []pixmap { return []pixmap{argb(iconSize, open)} }

// tip — подсказка: хосты показывают её при наведении.
func tip(v View) toolTip {
	text := v.Title
	if v.Detail != "" {
		text += ". " + v.Detail
	}
	return toolTip{Title: "vpnlock", Text: text, Icons: []pixmap{}}
}

// export выставляет значок с видом v и его меню m на шину под именем name.
func export(conn *dbus.Conn, name string, v View, m *menu) (*prop.Properties, error) {
	constant := func(v any) *prop.Prop { return &prop.Prop{Value: v, Emit: prop.EmitConst} }
	// Картинку и подсказку меняет Update, а хосту об этом говорят сигналы NewIcon и
	// NewToolTip: PropertiesChanged хосты значков не слушают.
	changing := func(v any) *prop.Prop { return &prop.Prop{Value: v, Emit: prop.EmitFalse} }
	props, err := prop.Export(conn, itemPath, prop.Map{itemIface: {
		"Id":         constant("vpnlock"),
		"Title":      constant("vpnlock"),
		"Category":   constant("SystemServices"),
		"Status":     constant("Active"),
		"WindowId":   constant(int32(0)),
		"IconName":   constant(""),
		"IconPixmap": changing(icons(v.Open)),
		"ToolTip":    changing(tip(v)),
		// Значок — только меню: KDE открывает его левым щелчком. GNOME открывает меню
		// левым щелчком сразу, если у значка нет Activate (indicatorStatusIcon.js), а
		// с Activate ждал бы двойного щелчка.
		"ItemIsMenu": constant(true),
		// Без Menu расширение GNOME считает значок неготовым и не показывает его
		// (appIndicator.js, _checkIfReady, версии 42, 46 и 58).
		"Menu": constant(menuPath),
	}})
	if err != nil {
		return nil, err
	}
	_, err = prop.Export(conn, menuPath, prop.Map{menuIface: {
		"Version":       constant(uint32(3)),
		"TextDirection": constant("ltr"),
		"Status":        constant("normal"),
		"IconThemePath": constant([]string{}),
	}})
	if err != nil {
		return nil, err
	}
	if err := conn.Export(item{}, itemPath, itemIface); err != nil {
		return nil, err
	}
	if err := conn.Export(m, menuPath, menuIface); err != nil {
		return nil, err
	}
	// Расширение GNOME узнаёт из описания объекта, есть ли у значка Activate.
	for _, o := range []struct {
		path  dbus.ObjectPath
		iface introspect.Interface
	}{
		{itemPath, introspect.Interface{Name: itemIface, Methods: introspect.Methods(item{})}},
		{menuPath, introspect.Interface{Name: menuIface, Methods: introspect.Methods(m)}},
	} {
		node := &introspect.Node{Name: string(o.path), Interfaces: []introspect.Interface{prop.IntrospectData, o.iface}}
		if err := conn.Export(introspect.NewIntrospectable(node), o.path, "org.freedesktop.DBus.Introspectable"); err != nil {
			return nil, err
		}
	}
	reply, err := conn.RequestName(name, dbus.NameFlagDoNotQueue)
	if err != nil {
		return nil, err
	}
	if reply != dbus.RequestNameReplyPrimaryOwner {
		return nil, fmt.Errorf("имя %s занято", name)
	}
	return props, nil
}

// argb — значок со стороной size в формате IconPixmap.
func argb(size int, open bool) pixmap {
	img := shield(size, open)
	px := make([]byte, 0, size*size*4)
	for i := 0; i < len(img.Pix); i += 4 {
		px = append(px, img.Pix[i+3], img.Pix[i], img.Pix[i+1], img.Pix[i+2])
	}
	return pixmap{int32(size), int32(size), px}
}

// item — методы значка. Activate нет: значок — только меню (ItemIsMenu).
type item struct{}

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

// menuRemoved — снятые свойства пункта (ias).
type menuRemoved struct {
	ID    int32
	Names []string
}

// menuEvent — событие пункта для EventGroup (isvu).
type menuEvent struct {
	ID        int32
	Event     string
	Data      dbus.Variant
	Timestamp uint32
}

// Пункты меню: заголовок и строка под ним (только для чтения), черта,
// «Уведомления». Переключателя в dbusmenu нет — отметка.
const (
	itemTitle int32 = iota + 1
	itemDetail
	itemLine
	itemNotify
)

var menuItems = []int32{itemTitle, itemDetail, itemLine, itemNotify}

// menu — меню значка по протоколу dbusmenu. Раскладка не меняется, поэтому номер
// ревизии один; новые подпись и отметку хост узнаёт из ItemsPropertiesUpdated.
type menu struct {
	conn   *dbus.Conn
	toggle func()
	mu     sync.Mutex
	view   View
}

func rootProps() map[string]dbus.Variant {
	return map[string]dbus.Variant{"children-display": dbus.MakeVariant("submenu")}
}

// label — подпись для dbusmenu: одиночное подчёркивание там — мнемоника.
func label(s string) dbus.Variant { return dbus.MakeVariant(strings.ReplaceAll(s, "_", "__")) }

// props — все свойства пункта id; nil — такого пункта нет. Вызывать под m.mu.
func (m *menu) props(id int32) map[string]dbus.Variant {
	switch id {
	case 0:
		return rootProps()
	case itemTitle:
		return map[string]dbus.Variant{"label": label(m.view.Title), "enabled": dbus.MakeVariant(false)}
	case itemDetail:
		return map[string]dbus.Variant{"label": label(m.view.Detail), "enabled": dbus.MakeVariant(false), "visible": dbus.MakeVariant(m.view.Detail != "")}
	case itemLine:
		return map[string]dbus.Variant{"type": dbus.MakeVariant("separator")}
	case itemNotify:
		state := int32(0)
		if m.view.Notify {
			state = 1
		}
		return map[string]dbus.Variant{"label": label(NotifyItem), "toggle-type": dbus.MakeVariant("checkmark"), "toggle-state": dbus.MakeVariant(state)}
	}
	return nil
}

// set — новый вид: заголовок, строка под ним и отметка у «Уведомления».
func (m *menu) set(v View) {
	m.mu.Lock()
	m.view = v
	updated := []menuProps{{itemTitle, m.props(itemTitle)}, {itemDetail, m.props(itemDetail)}, {itemNotify, m.props(itemNotify)}}
	m.mu.Unlock()
	m.conn.Emit(menuPath, menuIface+".ItemsPropertiesUpdated", updated, []menuRemoved{})
}

var errNoItem = dbus.NewError("com.canonical.dbusmenu.Error.NoSuchItem", []any{"нет такого пункта"})

// GetLayout отдаёт пункты со всеми свойствами, какие бы ни спросили: GNOME
// спрашивает раскладку только с type и children-display и подписи старых пунктов
// иначе не обновил бы.
func (m *menu) GetLayout(parent, depth int32, names []string) (uint32, menuNode, *dbus.Error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	props := m.props(parent)
	if props == nil {
		return 0, menuNode{}, errNoItem
	}
	node := menuNode{ID: parent, Props: props, Children: []dbus.Variant{}}
	if parent == 0 && depth != 0 {
		for _, id := range menuItems {
			node.Children = append(node.Children, dbus.MakeVariant(menuNode{ID: id, Props: m.props(id), Children: []dbus.Variant{}}))
		}
	}
	return 1, node, nil
}

func (m *menu) GetGroupProperties(ids []int32, names []string) ([]menuProps, *dbus.Error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(ids) == 0 {
		ids = append([]int32{0}, menuItems...)
	}
	out := []menuProps{}
	for _, id := range ids {
		props := m.props(id)
		if props == nil {
			continue
		}
		if len(names) > 0 {
			for k := range props {
				if !slices.Contains(names, k) {
					delete(props, k)
				}
			}
		}
		out = append(out, menuProps{id, props})
	}
	return out, nil
}

func (m *menu) GetProperty(id int32, name string) (dbus.Variant, *dbus.Error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.props(id)[name]
	if !ok {
		return dbus.Variant{}, errNoItem
	}
	return v, nil
}

// Event — человек выбрал пункт: «Уведомления» включает или выключает их.
func (m *menu) Event(id int32, event string, data dbus.Variant, timestamp uint32) *dbus.Error {
	if id == itemNotify && event == "clicked" {
		m.toggle()
	}
	return nil
}

func (m *menu) EventGroup(events []menuEvent) ([]int32, *dbus.Error) {
	missing := []int32{}
	for _, e := range events {
		if e.ID != 0 && !slices.Contains(menuItems, e.ID) {
			missing = append(missing, e.ID)
			continue
		}
		m.Event(e.ID, e.Event, e.Data, e.Timestamp)
	}
	return missing, nil
}

func (m *menu) AboutToShow(id int32) (bool, *dbus.Error) { return false, nil }

func (m *menu) AboutToShowGroup(ids []int32) ([]int32, []int32, *dbus.Error) {
	return []int32{}, []int32{}, nil
}
