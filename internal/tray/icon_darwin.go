package tray

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf16"
)

// script — значок в строке меню: системный osascript, ничего ставить не надо.
// Показан значок — жив процесс. Первый вид приходит аргументом, следующие —
// строками JSON в stdin; закрытый stdin — значок больше не нужен. Переключатель
// «Уведомления» пишет строку toggle в stdout. Картинки системные и шаблонные:
// macOS сама красит их под светлую и тёмную строку меню.
//
// Меню узкое, как системные (Wi-Fi, Пункт управления): ширина задана, заголовок
// жирным, под ним мелко — выход или причина, длинная причина переносится, а не
// растягивает меню. Пункты — свои виды (NSMenuItem.view): переключатель NSSwitch
// в меню иначе не поставить, и щелчок по нему меню не закрывает.
//
// Новый значок macOS ставит левее всех: среди чужих его не найти, а левые значки
// система скрывает первыми, когда меню приложения длинное. Позиция 0 ставит его
// правее всех сторонних, у часов. Задаётся один раз: дальше её помнит система, и
// значок, который человек перетащил с Cmd, остаётся там, куда его поставили.
const script = `ObjC.import('Cocoa');
ObjC.import('stdlib');
function run(argv) {
  const app = $.NSApplication.sharedApplication;
  app.setActivationPolicy(1); // Accessory: без значка в Dock
  app.finishLaunching;
  const defaults = $.NSUserDefaults.standardUserDefaults;
  const position = $('NSStatusItem Preferred Position vpnlock');
  if (defaults.objectForKey(position).js === undefined) defaults.setDoubleForKey(0, position);
  const item = $.NSStatusBar.systemStatusBar.statusItemWithLength(-2); // квадратный
  item.autosaveName = $('vpnlock');
  const symbol = (name) => {
    const image = $.NSImage.imageWithSystemSymbolNameAccessibilityDescription(name, 'vpnlock');
    image.setTemplate(true);
    return image;
  };
  const images = {open: symbol('lock.shield.fill'), closed: symbol('shield.slash.fill')};
  const input = $.NSFileHandle.fileHandleWithStandardInput;
  const output = $.NSFileHandle.fileHandleWithStandardOutput;
  let pending = '';
  ObjC.registerSubclass({
    name: 'VpnlockTray',
    methods: {
      'toggle:': {types: ['void', ['id']], implementation: function (sender) {
        output.writeData($('toggle\n').dataUsingEncoding($.NSUTF8StringEncoding));
      }},
      'input:': {types: ['void', ['id']], implementation: function (note) {
        const data = note.userInfo.objectForKey($('NSFileHandleNotificationDataItem'));
        if (Number(data.length) === 0) $.exit(0); // vpnlock tray закрыл трубу; длина из моста — не число JS
        pending += $.NSString.alloc.initWithDataEncoding(data, $.NSUTF8StringEncoding).js;
        for (let i; (i = pending.indexOf('\n')) >= 0; pending = pending.slice(i + 1)) show(JSON.parse(pending.slice(0, i)));
        input.readInBackgroundAndNotify;
      }},
    },
  });
  const target = $.VpnlockTray.alloc.init;

  const width = 220, inset = 14, pad = 6, row = 28;
  const text = (font, color) => {
    const label = $.NSTextField.wrappingLabelWithString($(''));
    label.font = font;
    if (color) label.textColor = color;
    label.preferredMaxLayoutWidth = width - 2 * inset;
    return label;
  };
  const title = text($.NSFont.boldSystemFontOfSize(13), null);
  const detail = text($.NSFont.systemFontOfSize(11), $.NSColor.secondaryLabelColor);
  const head = $.NSView.alloc.initWithFrame($.NSMakeRect(0, 0, width, row));
  head.addSubview(title);
  head.addSubview(detail);
  const headItem = $.NSMenuItem.alloc.init;
  headItem.view = head;

  const line = $.NSView.alloc.initWithFrame($.NSMakeRect(0, 0, width, row));
  const name = $.NSTextField.labelWithString($('Уведомления'));
  name.font = $.NSFont.menuFontOfSize(0);
  name.sizeToFit;
  const notify = $.NSSwitch.alloc.initWithFrame($.NSMakeRect(0, 0, 0, 0));
  notify.controlSize = 1; // маленький, как в Пункте управления
  notify.sizeToFit;
  notify.target = target;
  notify.action = 'toggle:';
  notify.setAccessibilityLabel($('Уведомления'));
  const n = name.frame.size, s = notify.frame.size;
  name.frame = $.NSMakeRect(inset, (row - n.height) / 2, n.width, n.height);
  notify.frame = $.NSMakeRect(width - inset - s.width, (row - s.height) / 2, s.width, s.height);
  line.addSubview(name);
  line.addSubview(notify);
  const lineItem = $.NSMenuItem.alloc.init;
  lineItem.view = line;

  const menu = $.NSMenu.alloc.init;
  menu.autoenablesItems = false;
  menu.addItem(headItem);
  menu.addItem($.NSMenuItem.separatorItem);
  menu.addItem(lineItem);
  item.menu = menu;

  function show(v) {
    item.button.image = v.open ? images.open : images.closed;
    item.button.toolTip = $(v.tip);
    title.stringValue = $(v.title);
    detail.stringValue = $(v.detail);
    const th = title.fittingSize.height, dh = v.detail ? detail.fittingSize.height : 0;
    const h = pad + th + (dh ? 2 + dh : 0) + pad;
    head.frame = $.NSMakeRect(0, 0, width, h);
    title.frame = $.NSMakeRect(inset, h - pad - th, width - 2 * inset, th);
    detail.frame = $.NSMakeRect(inset, pad, width - 2 * inset, dh);
    notify.state = v.notify ? 1 : 0;
  }
  show(JSON.parse(argv[0]));
  $.NSNotificationCenter.defaultCenter.addObserverSelectorNameObject(target, 'input:', $('NSFileHandleReadCompletionNotification'), input);
  input.readInBackgroundAndNotify;
  app.run;
}
`

// statusItem показывает значок дочерним osascript. Если vpnlock tray умрёт сам,
// osascript уберёт launchd: задача без AbandonProcessGroup, и он снимает всю
// группу процессов. А stdin закроется — и скрипт выйдет сам.
type statusItem struct {
	mu   sync.Mutex
	cmd  *exec.Cmd
	in   io.WriteCloser
	gone chan struct{}
}

// System — показ значка в этом сеансе. Второй экземпляр на macOS не запускает
// launchd.
func System() (Icon, error) { return &statusItem{}, nil }

func (s *statusItem) Show(v View, toggle func()) (<-chan error, error) {
	cmd := exec.Command("/usr/bin/osascript", "-l", "JavaScript", "-e", script, line(v))
	var errOut bytes.Buffer
	cmd.Stderr = &errOut
	in, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	// Своя труба, а не StdoutPipe: Wait закрыл бы её, пока чтение ещё идёт.
	r, w, err := os.Pipe()
	if err != nil {
		in.Close()
		return nil, err
	}
	cmd.Stdout = w
	err = cmd.Start()
	w.Close()
	if err != nil {
		in.Close()
		r.Close()
		return nil, err
	}
	go func() {
		defer r.Close()
		sc := bufio.NewScanner(r)
		for sc.Scan() {
			if sc.Text() == "toggle" {
				toggle()
			}
		}
	}()
	died := make(chan error, 1)
	gone := make(chan struct{})
	go func() {
		err := cmd.Wait()
		died <- fmt.Errorf("osascript завершился: %v: %s", err, strings.TrimSpace(errOut.String()))
		close(gone)
	}()
	s.mu.Lock()
	s.cmd, s.in, s.gone = cmd, in, gone
	s.mu.Unlock()
	return died, nil
}

// Update отдаёт скрипту новый вид. Скрипт умер — запись не удастся, а о смерти
// цикл узнает из канала died.
func (s *statusItem) Update(v View) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.in != nil {
		io.WriteString(s.in, line(v)+"\n")
	}
}

func (s *statusItem) Hide() {
	s.mu.Lock()
	cmd, in, gone := s.cmd, s.in, s.gone
	s.cmd, s.in = nil, nil
	s.mu.Unlock()
	if cmd == nil {
		return
	}
	in.Close()
	cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-gone:
	case <-time.After(2 * time.Second):
		cmd.Process.Kill()
		<-gone
	}
}

// line — вид для скрипта: JSON в одну строку и только из ASCII. Скрипт склеивает
// куски трубы как текст, и буква, разрезанная между кусками, его не сломает.
func line(v View) string {
	b, err := json.Marshal(struct {
		Open   bool   `json:"open"`
		Title  string `json:"title"`
		Detail string `json:"detail"`
		Notify bool   `json:"notify"`
		Tip    string `json:"tip"`
	}{v.Open, v.Title, v.Detail, v.Notify, v.Tip()})
	if err != nil {
		panic(err) // строки и флаги кодируются всегда
	}
	var out strings.Builder
	for _, r := range string(b) {
		if r < 0x80 {
			out.WriteRune(r)
			continue
		}
		for _, u := range utf16.Encode([]rune{r}) {
			fmt.Fprintf(&out, `\u%04x`, u)
		}
	}
	return out.String()
}
