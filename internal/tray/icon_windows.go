package tray

import (
	"errors"
	"fmt"
	"runtime"
	"sync"
	"time"
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
	procCreateBitmap           = gdi32.NewProc("CreateBitmap")
	procCreateDIBSection       = gdi32.NewProc("CreateDIBSection")
	procDeleteObject           = gdi32.NewProc("DeleteObject")
	procShellNotifyIconW       = shell32.NewProc("Shell_NotifyIconW")
)

const (
	wmDestroy = 0x0002
	wmClose   = 0x0010
	wmTimer   = 0x0113

	nimAdd    = 0
	nimDelete = 2
	nifIcon   = 0x2
	nifTip    = 0x4

	smCxSmIcon = 49 // SM_CXSMICON: размер значка в области уведомлений
	dibRGB     = 0

	addTimer  = 1
	addRetry  = 5 * time.Second
	hideWait  = 5 * time.Second
	iconID    = 1
	className = "vpnlock-tray"
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
)

// shown — значок, который сейчас показан. Его трогает только поток окна: окно
// принадлежит одному потоку, и все сообщения приходят на нём.
var shown *notifyIcon

// wndProc — один на процесс: обратных вызовов windows.NewCallback система не отпускает.
var wndProc = sync.OnceValue(func() uintptr { return windows.NewCallback(windowProc) })

// notifyIcon — значок. Мьютекс Local\vpnlock-tray держится до выхода процесса: второй
// экземпляр запускает schtasks /Run при обновлении, а Local\ действует в пределах
// сеанса, поэтому у каждого пользователя свой значок.
type notifyIcon struct {
	wnd            uintptr
	data           notifyIconData
	added          bool
	taskbarCreated uint32
	stopped        chan struct{}
}

// System — показ значка в этом сеансе.
func System() (Icon, error) {
	name, err := windows.UTF16PtrFromString(`Local\vpnlock-tray`)
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

func (n *notifyIcon) Show() (<-chan error, error) {
	ready := make(chan error, 1)
	died := make(chan error, 1)
	n.stopped = make(chan struct{})
	go n.pump(ready, died)
	if err := <-ready; err != nil {
		return nil, err
	}
	return died, nil
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
	hicon, err := createIcon()
	if err != nil {
		ready <- fmt.Errorf("значок: %w", err)
		return
	}
	defer procDestroyIcon.Call(hicon)
	if err := n.createWindow(hicon); err != nil {
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
// HWND_MESSAGE: сообщение TaskbarCreated рассылается только окнам верхнего уровня.
func (n *notifyIcon) createWindow(hicon uintptr) error {
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
	n.data = notifyIconData{Wnd: wnd, ID: iconID, Flags: nifIcon | nifTip, Icon: hicon}
	n.data.Size = uint32(unsafe.Sizeof(n.data))
	tip, err := windows.UTF16FromString("vpnlock работает")
	if err != nil {
		return err
	}
	copy(n.data.Tip[:], tip)
	// При входе в систему панели задач может ещё не быть: значок встанет по
	// TaskbarCreated, а таймер — на случай, когда Explorer занят и не ответил.
	n.add()
	procSetTimer.Call(wnd, addTimer, uintptr(addRetry.Milliseconds()), 0)
	return nil
}

func (n *notifyIcon) add() {
	r, _, _ := procShellNotifyIconW.Call(nimAdd, uintptr(unsafe.Pointer(&n.data)))
	n.added = r != 0
}

func windowProc(wnd, message, wParam, lParam uintptr) uintptr {
	n := shown
	if n != nil && n.wnd == wnd {
		switch uint32(message) {
		case n.taskbarCreated: // Explorer перезапустился: прежний значок пропал вместе с ним
			n.add()
			return 0
		case wmTimer:
			if !n.added {
				n.add()
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

// createIcon строит HICON из shield.png в размере области уведомлений.
func createIcon() (uintptr, error) {
	size, _, _ := procGetSystemMetrics.Call(smCxSmIcon)
	if size == 0 {
		size = 16
	}
	img := shield(int(size))

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
