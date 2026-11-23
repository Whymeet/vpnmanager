package tray

import (
	"errors"
	"fmt"
	"runtime"
	"sync"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Значок в области уведомлений: Shell_NotifyIconW, скрытое окно и цикл сообщений —
// через x/sys/windows, как привязки WFP в enforce/fwpm_windows.go, без библиотек.
// Структуры повторяют shellapi.h и winuser.h для 64-битной Windows (amd64 и arm64);
// размеры сверяются при сборке (ниже).

var (
	user32  = windows.NewLazySystemDLL("user32.dll")
	gdi32   = windows.NewLazySystemDLL("gdi32.dll")
	shell32 = windows.NewLazySystemDLL("shell32.dll")

	procRegisterClassExW       = user32.NewProc("RegisterClassExW")
	procCreateWindowExW        = user32.NewProc("CreateWindowExW")
	procDefWindowProcW         = user32.NewProc("DefWindowProcW")
	procDestroyWindow          = user32.NewProc("DestroyWindow")
	procPostMessageW           = user32.NewProc("PostMessageW")
	procPostQuitMessage        = user32.NewProc("PostQuitMessage")
	procGetMessageW            = user32.NewProc("GetMessageW")
	procDispatchMessageW       = user32.NewProc("DispatchMessageW")
	procRegisterWindowMessageW = user32.NewProc("RegisterWindowMessageW")
	procSetTimer               = user32.NewProc("SetTimer")
	procCreateIconIndirect     = user32.NewProc("CreateIconIndirect")
	procDestroyIcon            = user32.NewProc("DestroyIcon")
	procGetSystemMetrics       = user32.NewProc("GetSystemMetrics")
	procSetDpiAwarenessContext = user32.NewProc("SetProcessDpiAwarenessContext")
	procCreatePopupMenu        = user32.NewProc("CreatePopupMenu")
	procAppendMenuW            = user32.NewProc("AppendMenuW")
	procTrackPopupMenu         = user32.NewProc("TrackPopupMenu")
	procDestroyMenu            = user32.NewProc("DestroyMenu")
	procSetForegroundWindow    = user32.NewProc("SetForegroundWindow")
	procGetCursorPos           = user32.NewProc("GetCursorPos")
	procCreateBitmap           = gdi32.NewProc("CreateBitmap")
	procCreateDIBSection       = gdi32.NewProc("CreateDIBSection")
	procDeleteObject           = gdi32.NewProc("DeleteObject")
	procShellNotifyIconW       = shell32.NewProc("Shell_NotifyIconW")
)

const (
	wmNull      = 0x0000
	wmDestroy   = 0x0002
	wmClose     = 0x0010
	wmTimer     = 0x0113
	wmLButtonUp = 0x0202
	wmRButtonUp = 0x0205
	// Свои сообщения окна: щелчок по значку (его шлёт Explorer) и новый вид (его
	// шлёт Update из потока цикла — значок меняется только на потоке окна).
	wmTrayClick = 0x8000 + 1 // WM_APP+1
	wmTrayView  = 0x8000 + 2

	nimAdd     = 0
	nimModify  = 1
	nimDelete  = 2
	nifMessage = 0x1
	nifIcon    = 0x2
	nifTip     = 0x4

	mfString    = 0x0
	mfGrayed    = 0x1
	mfChecked   = 0x8
	mfSeparator = 0x800

	tpmRightButton = 0x2
	tpmBottomAlign = 0x20
	tpmNoNotify    = 0x80
	tpmReturnCmd   = 0x100

	menuTitle  = 1 // «Приложения в сети»: только для чтения
	menuDetail = 2 // выход или причина: только для чтения
	menuNotify = 3 // «Уведомления»
	menuVPN    = 4 // «Мои VPN…»

	smCxSmIcon = 49 // SM_CXSMICON: размер значка в области уведомлений
	dibRGB     = 0

	addTimer  = 1
	addRetry  = 5 * time.Second
	hideWait  = 5 * time.Second
	iconID    = 1
	className = "appguard-tray"
)

// perMonitorAwareV2 — DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2, то есть -4.
const perMonitorAwareV2 = ^uintptr(3)

type notifyIconData struct {
	Size        uint32
	Wnd         uintptr
	ID          uint32
	Flags       uint32
	CallbackMsg uint32
	Icon        uintptr
	Tip         [128]uint16
	State       uint32
	StateMask   uint32
	Info        [256]uint16
	Version     uint32
	InfoTitle   [64]uint16
	InfoFlags   uint32
	GUID        windows.GUID
	BalloonIcon uintptr
}

type wndClassEx struct {
	Size       uint32
	Style      uint32
	WndProc    uintptr
	ClsExtra   int32
	WndExtra   int32
	Instance   uintptr
	Icon       uintptr
	Cursor     uintptr
	Background uintptr
	MenuName   *uint16
	ClassName  *uint16
	IconSm     uintptr
}

type msg struct {
	Wnd     uintptr
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	X, Y    int32
	Private uint32
}

type iconInfo struct {
	IsIcon   int32
	XHotspot uint32
	YHotspot uint32
	Mask     uintptr
	Color    uintptr
}

type point struct{ X, Y int32 }

type bitmapInfoHeader struct {
	Size          uint32
	Width         int32
	Height        int32
	Planes        uint16
	BitCount      uint16
	Compression   uint32
	SizeImage     uint32
	XPelsPerMeter int32
	YPelsPerMeter int32
	ClrUsed       uint32
	ClrImportant  uint32
}

// Разойдётся с заголовками Windows — сборка упадёт, а не Explorer.
var (
	_ [unsafe.Sizeof(notifyIconData{}) - 976]byte
	_ [976 - unsafe.Sizeof(notifyIconData{})]byte
	_ [unsafe.Sizeof(wndClassEx{}) - 80]byte
	_ [80 - unsafe.Sizeof(wndClassEx{})]byte
	_ [unsafe.Sizeof(msg{}) - 48]byte
	_ [48 - unsafe.Sizeof(msg{})]byte
	_ [unsafe.Sizeof(iconInfo{}) - 32]byte
	_ [32 - unsafe.Sizeof(iconInfo{})]byte
	_ [unsafe.Sizeof(bitmapInfoHeader{}) - 40]byte
	_ [40 - unsafe.Sizeof(bitmapInfoHeader{})]byte
	_ [unsafe.Sizeof(point{}) - 8]byte
	_ [8 - unsafe.Sizeof(point{})]byte
)

// shown — значок, который сейчас показан. Его трогает только поток окна: окно
// принадлежит одному потоку, и все сообщения приходят на нём.
var shown *notifyIcon

// wndProc — один на процесс: обратных вызовов windows.NewCallback система не отпускает.
var wndProc = sync.OnceValue(func() uintptr { return windows.NewCallback(windowProc) })

// notifyIcon — значок. Мьютекс Local\appguard-tray держится до выхода процесса: второй
// экземпляр запускает schtasks /Run при обновлении, а Local\ действует в пределах
// сеанса, поэтому у каждого пользователя свой значок.
type notifyIcon struct {
	wnd            uintptr
	data           notifyIconData
	icons          [2]uintptr // перечёркнутый щит и щит с замком: индекс — открыта ли защита
	added          bool
	taskbarCreated uint32
	stopped        chan struct{}
	toggle         func()

	mu   sync.Mutex
	view View // что показать: пишет Update, читает поток окна
}

// System — показ значка в этом сеансе.
func System() (Icon, error) {
	name, err := windows.UTF16PtrFromString(`Local\appguard-tray`)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateMutex(nil, false, name)
	if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		windows.CloseHandle(h)
		return nil, ErrBusy
	}
	if err != nil {
		return nil, fmt.Errorf("мьютекс значка: %w", err)
	}
	return &notifyIcon{}, nil
}

func (n *notifyIcon) Show(v View, toggle func()) (<-chan error, error) {
	n.mu.Lock()
	n.view = v
	n.mu.Unlock()
	n.toggle = toggle
	ready := make(chan error, 1)
	died := make(chan error, 1)
	n.stopped = make(chan struct{})
	go n.pump(ready, died)
	if err := <-ready; err != nil {
		return nil, err
	}
	return died, nil
}

// Update отдаёт новый вид потоку окна.
func (n *notifyIcon) Update(v View) {
	n.mu.Lock()
	n.view = v
	n.mu.Unlock()
	procPostMessageW.Call(n.wnd, wmTrayView, 0, 0)
}

func (n *notifyIcon) Hide() {
	procPostMessageW.Call(n.wnd, wmClose, 0, 0)
	select {
	case <-n.stopped:
	case <-time.After(hideWait):
	}
}

// pump держит окно и цикл сообщений на закреплённом потоке, пока значок показан.
func (n *notifyIcon) pump(ready, died chan<- error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	defer close(n.stopped)

	// Иначе Windows рисует значок в 96 dpi и растягивает: на экране 150% он мылится.
	if procSetDpiAwarenessContext.Find() == nil {
		procSetDpiAwarenessContext.Call(perMonitorAwareV2)
	}
	for i, open := range []bool{false, true} {
		hicon, err := createIcon(open)
		if err != nil {
			ready <- fmt.Errorf("значок: %w", err)
			return
		}
		defer procDestroyIcon.Call(hicon)
		n.icons[i] = hicon
	}
	if err := n.createWindow(); err != nil {
		ready <- err
		return
	}
	ready <- nil

	var m msg
	for {
		r, _, err := procGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		switch int32(r) {
		case 0: // WM_QUIT: окно закрыто
			return
		case -1:
			died <- fmt.Errorf("цикл сообщений значка: %w", err)
			return
		}
		procDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
	}
}

// createWindow заводит скрытое окно и добавляет значок. Окно обычное, а не
// HWND_MESSAGE: сообщение TaskbarCreated рассылается только окнам верхнего уровня, а
// меню без своего окна на переднем плане не закрывается щелчком мимо него.
func (n *notifyIcon) createWindow() error {
	var instance windows.Handle
	if err := windows.GetModuleHandleEx(0, nil, &instance); err != nil {
		return fmt.Errorf("значок: %w", err)
	}
	class, err := windows.UTF16PtrFromString(className)
	if err != nil {
		return err
	}
	wc := wndClassEx{WndProc: wndProc(), Instance: uintptr(instance), ClassName: class}
	wc.Size = uint32(unsafe.Sizeof(wc))
	// Класс один на процесс: после Hide значок поднимается на том же классе.
	if r, _, err := procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc))); r == 0 && !errors.Is(err, windows.ERROR_CLASS_ALREADY_EXISTS) {
		return fmt.Errorf("класс окна значка: %w", err)
	}
	created, err := windows.UTF16PtrFromString("TaskbarCreated")
	if err != nil {
		return err
	}
	r, _, err := procRegisterWindowMessageW.Call(uintptr(unsafe.Pointer(created)))
	if r == 0 {
		return fmt.Errorf("сообщение TaskbarCreated: %w", err)
	}
	n.taskbarCreated = uint32(r)
	shown = n
	wnd, _, err := procCreateWindowExW.Call(0, uintptr(unsafe.Pointer(class)), uintptr(unsafe.Pointer(class)),
		0, 0, 0, 0, 0, 0, 0, uintptr(instance), 0)
	if wnd == 0 {
		return fmt.Errorf("окно значка: %w", err)
	}
	n.wnd = wnd
	n.data = notifyIconData{Wnd: wnd, ID: iconID, Flags: nifMessage | nifIcon | nifTip, CallbackMsg: wmTrayClick}
	n.data.Size = uint32(unsafe.Sizeof(n.data))
	n.setView()
	// При входе в систему панели задач может ещё не быть: значок встанет по
	// TaskbarCreated, а таймер — на случай, когда Explorer занят и не ответил.
	n.add()
	procSetTimer.Call(wnd, addTimer, uintptr(addRetry.Milliseconds()), 0)
	return nil
}

// add ставит значок. Shell_NotifyIconW отвечает FALSE и тогда, когда Explorer
// был занят и не ответил вовремя, а значок всё же встал: повторный NIM_ADD такого
// значка не ставит, и без NIM_MODIFY значок навсегда остался бы с первой
// картинкой (щит перечёркнут, хотя VPN давно проверен). Поэтому не встал —
// пробуем изменить уже стоящий.
func (n *notifyIcon) add() {
	if r, _, _ := procShellNotifyIconW.Call(nimAdd, uintptr(unsafe.Pointer(&n.data))); r != 0 {
		n.added = true
		return
	}
	r, _, _ := procShellNotifyIconW.Call(nimModify, uintptr(unsafe.Pointer(&n.data)))
	n.added = r != 0
}

// show отдаёт значку текущий вид: стоит — меняет, не стоит — ставит. Не вышло —
// повторит таймер.
func (n *notifyIcon) show() {
	if n.added {
		if r, _, _ := procShellNotifyIconW.Call(nimModify, uintptr(unsafe.Pointer(&n.data))); r != 0 {
			return
		}
		n.added = false
	}
	n.add()
}

// setView переносит вид в данные значка: картинку и подсказку. Значок, который
// встанет по TaskbarCreated, встанет уже с ним.
func (n *notifyIcon) setView() View {
	n.mu.Lock()
	v := n.view
	n.mu.Unlock()
	n.data.Icon = n.icons[0]
	if v.Open {
		n.data.Icon = n.icons[1]
	}
	n.data.Tip = [128]uint16{}
	copy(n.data.Tip[:len(n.data.Tip)-1], utf16Text(v.Tip()))
	return v
}

// menu показывает меню у курсора и ждёт выбора: заголовок и строка под ним,
// черта, «Уведомления» с отметкой. Переключателя в меню Windows нет.
func (n *notifyIcon) menu() {
	v := n.setView()
	h, _, _ := procCreatePopupMenu.Call()
	if h == 0 {
		return
	}
	defer procDestroyMenu.Call(h)
	title, item := utf16Text(v.Title+"\x00"), utf16Text(NotifyItem+"\x00")
	procAppendMenuW.Call(h, mfString|mfGrayed, menuTitle, uintptr(unsafe.Pointer(&title[0])))
	if v.Detail != "" {
		detail := utf16Text(v.Detail + "\x00")
		procAppendMenuW.Call(h, mfString|mfGrayed, menuDetail, uintptr(unsafe.Pointer(&detail[0])))
	}
	procAppendMenuW.Call(h, mfSeparator, 0, 0)
	flags := uintptr(mfString)
	if v.Notify {
		flags |= mfChecked
	}
	if OpenVPN != nil {
		vpn := utf16Text(VPNItem + "\x00")
		procAppendMenuW.Call(h, mfString, menuVPN, uintptr(unsafe.Pointer(&vpn[0])))
	}
	procAppendMenuW.Call(h, flags, menuNotify, uintptr(unsafe.Pointer(&item[0])))
	var pt point
	procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	// Окно значка — на передний план, а после меню — пустое сообщение: иначе меню не
	// закрывается щелчком мимо него и открывается со второго раза.
	procSetForegroundWindow.Call(n.wnd)
	r, _, _ := procTrackPopupMenu.Call(h, tpmReturnCmd|tpmNoNotify|tpmRightButton|tpmBottomAlign,
		uintptr(pt.X), uintptr(pt.Y), 0, n.wnd, 0)
	procPostMessageW.Call(n.wnd, wmNull, 0, 0)
	switch uint32(r) {
	case menuNotify:
		if n.toggle != nil {
			n.toggle()
		}
	case menuVPN:
		if OpenVPN != nil {
			OpenVPN()
		}
	}
}

// utf16Text — строка для Windows. Нулевой символ внутри (его в тексте службы не
// бывает) обрезал бы строку, а не ломал вызов.
func utf16Text(s string) []uint16 {
	return utf16.Encode([]rune(s))
}

func windowProc(wnd, message, wParam, lParam uintptr) uintptr {
	n := shown
	if n != nil && n.wnd == wnd {
		switch uint32(message) {
		case n.taskbarCreated: // Explorer перезапустился: прежний значок пропал вместе с ним
			n.add()
			return 0
		case wmTimer:
			// Раз в addRetry вид отдаётся заново: если Explorer пропустил
			// изменение, значок не застрянет на старой картинке.
			n.setView()
			n.show()
			return 0
		case wmTrayView:
			n.setView()
			n.show()
			return 0
		case wmTrayClick:
			// Без NIM_SETVERSION Explorer шлёт само сообщение мыши в lParam.
			switch uint32(lParam) {
			case wmLButtonUp, wmRButtonUp:
				n.menu()
			}
			return 0
		case wmClose:
			procDestroyWindow.Call(wnd)
			return 0
		case wmDestroy:
			procShellNotifyIconW.Call(nimDelete, uintptr(unsafe.Pointer(&n.data)))
			n.added = false
			procPostQuitMessage.Call(0)
			return 0
		}
	}
	r, _, _ := procDefWindowProcW.Call(wnd, message, wParam, lParam)
	return r
}

// createIcon строит HICON из shield.png в размере области уведомлений: open — щит,
// иначе — перечёркнутый щит.
func createIcon(open bool) (uintptr, error) {
	size, _, _ := procGetSystemMetrics.Call(smCxSmIcon)
	if size == 0 {
		size = 16
	}
	img := shield(int(size), open)

	hdr := bitmapInfoHeader{Width: int32(size), Height: -int32(size), Planes: 1, BitCount: 32, Compression: dibRGB}
	hdr.Size = uint32(unsafe.Sizeof(hdr))
	var bits unsafe.Pointer
	color, _, err := procCreateDIBSection.Call(0, uintptr(unsafe.Pointer(&hdr)), dibRGB, uintptr(unsafe.Pointer(&bits)), 0, 0)
	if color == 0 {
		return 0, fmt.Errorf("CreateDIBSection: %w", err)
	}
	defer procDeleteObject.Call(color)
	dst := unsafe.Slice((*byte)(bits), len(img.Pix))
	for i := 0; i < len(img.Pix); i += 4 { // BGRA
		dst[i], dst[i+1], dst[i+2], dst[i+3] = img.Pix[i+2], img.Pix[i+1], img.Pix[i], img.Pix[i+3]
	}
	// Маска нулевая: прозрачность задаёт альфа. CreateBitmap без данных оставил бы её
	// случайной, строки монохромного растра выровнены по 2 байта.
	zero := make([]byte, (int(size)+15)/16*2*int(size))
	mask, _, err := procCreateBitmap.Call(size, size, 1, 1, uintptr(unsafe.Pointer(&zero[0])))
	if mask == 0 {
		return 0, fmt.Errorf("CreateBitmap: %w", err)
	}
	defer procDeleteObject.Call(mask)
	info := iconInfo{IsIcon: 1, Mask: mask, Color: color}
	hicon, _, err := procCreateIconIndirect.Call(uintptr(unsafe.Pointer(&info)))
	if hicon == 0 {
		return 0, fmt.Errorf("CreateIconIndirect: %w", err)
	}
	return hicon, nil
}
