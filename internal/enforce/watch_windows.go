package enforce

import (
	"errors"

	"golang.org/x/sys/windows"
)

// dirWatch следит за папкой: появился или пропал файл или папка — зовёт
// changed. Чтение перекрытое: его можно отменить из другой горутины, не
// дожидаясь следующего изменения.
type dirWatch struct {
	dir  string
	h    windows.Handle
	stop windows.Handle // событие «хватит»
	done chan struct{}
}

func watchDir(dir string, subtree bool, changed func()) (*dirWatch, error) {
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(p, windows.FILE_LIST_DIRECTORY,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OVERLAPPED, 0)
	if err != nil {
		return nil, err
	}
	stop, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		windows.CloseHandle(h)
		return nil, err
	}
	io, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		windows.CloseHandle(h)
		windows.CloseHandle(stop)
		return nil, err
	}
	w := &dirWatch{dir: dir, h: h, stop: stop, done: make(chan struct{})}
	go w.loop(io, subtree, changed)
	return w, nil
}

func (w *dirWatch) loop(io windows.Handle, subtree bool, changed func()) {
	defer close(w.done)
	defer windows.CloseHandle(io)
	defer windows.CloseHandle(w.h)
	const mask = windows.FILE_NOTIFY_CHANGE_FILE_NAME | windows.FILE_NOTIFY_CHANGE_DIR_NAME
	buf := make([]byte, 16<<10)
	ov := &windows.Overlapped{HEvent: io}
	for {
		windows.ResetEvent(io)
		if err := windows.ReadDirectoryChanges(w.h, &buf[0], uint32(len(buf)), subtree, mask, nil, ov, 0); err != nil {
			return // папку удалили или она недоступна
		}
		ev, err := windows.WaitForMultipleObjects([]windows.Handle{io, w.stop}, false, windows.INFINITE)
		if err != nil || ev != windows.WAIT_OBJECT_0 {
			// Остановка: отменить чтение и дождаться, пока ядро отпустит буфер.
			windows.CancelIoEx(w.h, ov)
			var n uint32
			windows.GetOverlappedResult(w.h, ov, &n, true)
			return
		}
		// Перемен было больше, чем влезло в буфер, — это тоже перемена.
		var n uint32
		if err := windows.GetOverlappedResult(w.h, ov, &n, false); err != nil && !errors.Is(err, windows.ERROR_NOTIFY_ENUM_DIR) {
			return
		}
		changed()
	}
}

// close останавливает наблюдение и ждёт, пока оно закончится. Событие
// остановки закрывается только здесь: наблюдение могло кончиться и само
// (папку удалили), а дескриптор — уйти другому объекту.
func (w *dirWatch) close() {
	windows.SetEvent(w.stop)
	<-w.done
	windows.CloseHandle(w.stop)
}
