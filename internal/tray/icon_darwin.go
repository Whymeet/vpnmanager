package tray

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

// script — значок в строке меню: системный osascript, ничего ставить не надо.
// Показан значок — жив процесс. Цикл не крутит процессор: runUntilDate спит.
//
// Новый значок macOS ставит левее всех: среди чужих его не найти, а левые значки
// система скрывает первыми, когда меню приложения длинное. Позиция 0 ставит его
// правее всех сторонних, у часов. Задаётся один раз: дальше её помнит система, и
// значок, который человек перетащил с Cmd, остаётся там, куда его поставили.
const script = `ObjC.import('Cocoa');
function run() {
  const app = $.NSApplication.sharedApplication;
  app.setActivationPolicy(1); // Accessory: без значка в Dock
  app.finishLaunching;
  const defaults = $.NSUserDefaults.standardUserDefaults;
  const position = $('NSStatusItem Preferred Position vpnlock');
  if (defaults.objectForKey(position).js === undefined) defaults.setDoubleForKey(0, position);
  const item = $.NSStatusBar.systemStatusBar.statusItemWithLength(-2); // квадратный
  item.autosaveName = $('vpnlock');
  const image = $.NSImage.imageWithSystemSymbolNameAccessibilityDescription('lock.shield.fill', 'vpnlock');
  image.setTemplate(true);
  item.button.image = image;
  item.button.toolTip = $('vpnlock работает');
  for (;;) {
    $.NSRunLoop.currentRunLoop.runUntilDate($.NSDate.dateWithTimeIntervalSinceNow(3600));
  }
}
`

// statusItem показывает значок дочерним osascript. Если vpnlock tray умрёт сам,
// osascript уберёт launchd: задача без AbandonProcessGroup, и он снимает всю
// группу процессов.
type statusItem struct {
	cmd  *exec.Cmd
	gone chan struct{}
}

// System — показ значка в этом сеансе. Второй экземпляр на macOS не запускает
// launchd.
func System() (Icon, error) { return &statusItem{}, nil }

func (s *statusItem) Show() (<-chan error, error) {
	cmd := exec.Command("/usr/bin/osascript", "-l", "JavaScript", "-e", script)
	var errOut bytes.Buffer
	cmd.Stderr = &errOut
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	died := make(chan error, 1)
	gone := make(chan struct{})
	go func() {
		err := cmd.Wait()
		died <- fmt.Errorf("osascript завершился: %v: %s", err, strings.TrimSpace(errOut.String()))
		close(gone)
	}()
	s.cmd, s.gone = cmd, gone
	return died, nil
}

func (s *statusItem) Hide() {
	if s.cmd == nil {
		return
	}
	s.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-s.gone:
	case <-time.After(2 * time.Second):
		s.cmd.Process.Kill()
		<-s.gone
	}
	s.cmd = nil
}
