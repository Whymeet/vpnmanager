package enforce

import (
	"bytes"
	"cmp"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"

	"appguard/internal/core"
)

// Anchor — якорь pf с правилами appguard. Он вложен в com.apple: основной конфиг
// macOS (/etc/pf.conf) уже вызывает `anchor "com.apple/*"`, поэтому правила
// действуют без правки системного конфига. Основной набор правил мы не
// перезагружаем никогда: так пропали бы якоря, которые система вставляет на лету
// (общий доступ к интернету, NAT виртуальных машин). А когда основной конфиг
// перезагружает чужая программа, вложенные якоря остаются на месте. Номер 100
// ставит нас раньше якорей Apple (200.AirDrop, 250.ApplicationFirewall): вложенные
// якоря идут по алфавиту.
const Anchor = "com.apple/100.appguard"

// tables — имена таблиц внутри якоря (они видны только ему).
const (
	table4 = "appguard4"
	table6 = "appguard6"
)

const pfctl = "/sbin/pfctl"

// PF — исполнитель на встроенном файрволе pf. Требует root.
type PF struct {
	// TokenFile — где хранится токен, с которым appguard включил pf (`pfctl -E`).
	// Пока токен не возвращён, pf остаётся включённым, даже если его ссылку
	// отпустит кто-то другой. Удаление возвращает токен.
	TokenFile string

	mu sync.Mutex
}

// Apply грузит правила r в якорь, предварительно убедившись, что pf включён и
// основной набор правил вызывает якоря com.apple.
func (p *PF) Apply(r Rules) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.enable(); err != nil {
		return err
	}
	if err := hook(); err != nil {
		return err
	}
	if err := load(anchorRules(r)); err != nil {
		return err
	}
	// Содержимое таблиц задаётся отдельно и всегда целиком: при перезагрузке
	// якоря pf оставляет в persist-таблице старые адреса, если в объявлении их
	// нет, — и снятая защита продолжала бы закрывать сервис.
	if err := replaceTable(table4, r.V4); err != nil {
		return err
	}
	return replaceTable(table6, r.V6)
}

// replaceTable заменяет содержимое таблицы якоря на addrs (пустой — очищает).
func replaceTable(table string, addrs []netip.Addr) error {
	cmd := exec.Command(pfctl, "-a", Anchor, "-t", table, "-T", "replace", "-f", "-")
	cmd.Stdin = strings.NewReader(tableInput(addrs))
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("таблица %s: %w: %s", table, err, bytes.TrimSpace(out))
	}
	return nil
}

// tableInput — адреса по одному на строку, как их читает `pfctl -T replace -f`.
func tableInput(addrs []netip.Addr) string {
	var b strings.Builder
	for _, a := range addrs {
		b.WriteString(a.String())
		b.WriteByte('\n')
	}
	return b.String()
}

// Clear снимает правила и таблицы якоря и возвращает токен pf.
func (p *PF) Clear() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	errs := []error{
		run(pfctl, "-a", Anchor, "-F", "rules"),
		run(pfctl, "-a", Anchor, "-F", "Tables"),
	}
	if p.TokenFile != "" {
		if token, err := os.ReadFile(p.TokenFile); err == nil {
			if t := strings.TrimSpace(string(token)); t != "" {
				errs = append(errs, run(pfctl, "-X", t))
			}
			errs = append(errs, os.Remove(p.TokenFile))
		} else if !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// enable включает pf своим токеном, если pf выключен или токена у нас ещё нет.
// Новый токен берётся раньше, чем отпускается старый: иначе на мгновение pf мог
// бы выключиться.
func (p *PF) enable() error {
	on, err := enabled()
	if err != nil {
		return err
	}
	if on && p.TokenFile != "" {
		if _, err := os.Stat(p.TokenFile); err == nil {
			return nil
		}
	}
	if on && p.TokenFile == "" {
		return nil
	}
	out, err := exec.Command(pfctl, "-E").CombinedOutput()
	if err != nil {
		return fmt.Errorf("pfctl -E: %w: %s", err, bytes.TrimSpace(out))
	}
	if p.TokenFile == "" {
		return nil
	}
	token := parseToken(out)
	if token == "" {
		return fmt.Errorf("pfctl -E не выдал токен: %s", bytes.TrimSpace(out))
	}
	old, _ := os.ReadFile(p.TokenFile)
	if err := os.WriteFile(p.TokenFile, []byte(token+"\n"), 0o600); err != nil {
		return err
	}
	if t := strings.TrimSpace(string(old)); t != "" && t != token {
		run(pfctl, "-X", t) // прежний токен мог пропасть вместе с `pfctl -d` — это не ошибка
	}
	return nil
}

var tokenRe = regexp.MustCompile(`Token\s*:\s*(\d+)`)

func parseToken(out []byte) string {
	if m := tokenRe.FindSubmatch(out); m != nil {
		return string(m[1])
	}
	return ""
}

func enabled() (bool, error) {
	out, err := exec.Command(pfctl, "-s", "info").CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("pfctl -s info: %w: %s", err, bytes.TrimSpace(out))
	}
	return bytes.Contains(out, []byte("Status: Enabled")), nil
}

// mainConf — основной конфиг pf системы. В нём точка `anchor "com.apple/*"`,
// через которую действует якорь appguard.
const mainConf = "/etc/pf.conf"

var hookRule = []byte(`anchor "com.apple/*"`)

// mainRules — правила фильтрации основного набора, как их показывает pfctl.
func mainRules() ([]byte, error) {
	out, err := exec.Command(pfctl, "-sr").Output()
	if err != nil {
		return nil, fmt.Errorf("pfctl -sr: %w", err)
	}
	return out, nil
}

// hook проверяет, что основной набор правил вызывает якоря com.apple: без этого
// правила appguard не действуют. Основной набор мы не перезагружаем: в нём
// бывают якоря, которые системные службы вставляют на лету. Исключение —
// пустой набор фильтров (его сбросили, вставленного на лету там уже нет): его
// фильтры возвращаются из /etc/pf.conf, правила NAT не трогаются (-R).
func hook() error {
	out, err := mainRules()
	if err != nil || bytes.Contains(out, hookRule) {
		return err
	}
	if len(bytes.TrimSpace(out)) == 0 {
		if err := run(pfctl, "-Rf", mainConf); err != nil {
			return fmt.Errorf("основной набор правил pf сброшен, а вернуть его из %s не вышло: %w", mainConf, err)
		}
		if out, err = mainRules(); err != nil || bytes.Contains(out, hookRule) {
			return err
		}
	}
	return errors.New(`основной набор правил pf не вызывает якоря com.apple (anchor "com.apple/*"): его заменила другая программа или изменён /etc/pf.conf — правила appguard не действуют`)
}

// Verify сверяет файрвол с правилами r, ничего не меняя: pf включён, основной
// набор вызывает якоря com.apple, в якоре столько правил, сколько в r, а в
// таблицах — столько адресов. Сторож зовёт его раз в секунду, поэтому только
// чтение и только счёт.
func (p *PF) Verify(r Rules) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if on, err := enabled(); err != nil || !on {
		return cmp.Or(err, errors.New("pf выключен"))
	}
	out, err := mainRules()
	if err != nil {
		return err
	}
	if !bytes.Contains(out, hookRule) {
		return errors.New("основной набор правил pf сброшен: якоря com.apple не вызываются")
	}
	if out, err = exec.Command(pfctl, "-a", Anchor, "-sr").Output(); err != nil {
		return fmt.Errorf("pfctl -a %s -sr: %w", Anchor, err)
	}
	if got, want := countRules(out), countRules([]byte(anchorRules(r))); got != want {
		return fmt.Errorf("в якоре %d %s вместо %d", got, core.Plural(got, "правило", "правила", "правил"), want)
	}
	for _, t := range []struct {
		name  string
		addrs []netip.Addr
	}{{table4, r.V4}, {table6, r.V6}} {
		out, err := exec.Command(pfctl, "-a", Anchor, "-t", t.name, "-T", "show").Output()
		if err != nil {
			return fmt.Errorf("таблицы %s нет", t.name)
		}
		if got := len(bytes.Fields(out)); got != len(t.addrs) {
			return fmt.Errorf("в таблице %s %d адресов вместо %d", t.name, got, len(t.addrs))
		}
	}
	return nil
}

// countRules — сколько правил фильтрации в тексте правил pf.
func countRules(text []byte) int {
	n := 0
	for line := range bytes.Lines(text) {
		if line = bytes.TrimSpace(line); bytes.HasPrefix(line, []byte("pass ")) || bytes.HasPrefix(line, []byte("block ")) {
			n++
		}
	}
	return n
}

// load грузит набор rules в якорь.
func load(rules string) error {
	cmd := exec.Command(pfctl, "-a", Anchor, "-f", "-")
	cmd.Stdin = strings.NewReader(rules)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("загрузка правил в якорь %s: %w: %s", Anchor, err, bytes.TrimSpace(out))
	}
	return nil
}

// anchorRules — текст правил якоря для состояния r. Таблицы только
// объявляются: их содержимое ставит replaceTable. Пустая таблица ничего не
// закрывает, так что правила можно держать всегда.
func anchorRules(r Rules) string {
	var b strings.Builder
	fmt.Fprintf(&b, "table <%s> persist\n", table4)
	fmt.Fprintf(&b, "table <%s> persist\n", table6)
	// Порт непроверенного прокси закрыт для всех программ, кроме root. Владельца
	// сокета pf знает (`user`), а программу — нет. Петля lo0 фильтруется: в
	// /etc/pf.conf нет `set skip on lo0`. Соединения, открытые раньше, без
	// состояния pf, поэтому рвутся тоже — через прокси, выход которого стал
	// российским, не уходит ни одного нового пакета.
	for _, ap := range r.ClosedProxies {
		if a := ap.Addr().WithZone(""); a.IsValid() && ap.Port() != 0 {
			fmt.Fprintf(&b, "block drop out quick proto tcp from any to %s port %d user != 0\n", a.Unmap(), ap.Port())
		}
	}
	// Через проверенные туннели — пропускаем, с состоянием для ответов.
	//
	// TCP — с `flags any`. По умолчанию pf заводит состояние только по SYN, а у
	// соединения, открытого раньше правил, состояния нет (pf не следит за потоками,
	// которых не касалось ни одно правило, а на чистом маке он вообще выключен и
	// включается позже). Адрес узнаётся по уже работающему соединению и попадает
	// в таблицу посреди потока: его пакеты — повторы и ACK без SYN — иначе не
	// подошли бы под пропуск и упёрлись бы в запрет ниже, а приложение теряло бы
	// соединение на каждом новом адресе.
	//
	// Состояние привязано к интерфейсу (if-bound): когда VPN обрывается и пакеты
	// того же соединения уходят в Wi‑Fi, они не проскакивают по старому
	// состоянию, а проходят правила заново и упираются в запрет.
	for _, ifn := range r.OpenIfaces {
		if !okIface(ifn) {
			continue
		}
		for _, fam := range []struct{ inet, table string }{{"inet", table4}, {"inet6", table6}} {
			fmt.Fprintf(&b, "pass out quick on %s %s proto tcp from any to <%s> flags any keep state (if-bound)\n", ifn, fam.inet, fam.table)
			fmt.Fprintf(&b, "pass out quick on %s %s from any to <%s> keep state (if-bound)\n", ifn, fam.inet, fam.table)
		}
	}
	// Сервер VPN на адресе защищённого сервиса (VPN через CDN) разрешён на
	// физическом интерфейсе: иначе клиент VPN не подключится. Только там — через
	// непроверенный туннель адрес по-прежнему закрыт.
	if okIface(r.Physical) {
		for _, a := range r.Servers {
			if a = a.Unmap().WithZone(""); !a.IsValid() {
				continue
			}
			inet := "inet"
			if a.Is6() {
				inet = "inet6"
			}
			fmt.Fprintf(&b, "pass out quick on %s %s proto tcp from any to %s flags any keep state (if-bound)\n", r.Physical, inet, a)
			fmt.Fprintf(&b, "pass out quick on %s %s from any to %s keep state (if-bound)\n", r.Physical, inet, a)
		}
	}
	// Везде ещё — закрываем. Правила quick: до правил дальше по списку дело не доходит.
	fmt.Fprintf(&b, "block drop out quick inet from any to <%s>\n", table4)
	fmt.Fprintf(&b, "block drop out quick inet6 from any to <%s>\n", table6)
	return b.String()
}

// okIface — имя интерфейса из букв и цифр: в правила pf не попадёт ничего
// постороннего.
func okIface(name string) bool {
	if name == "" {
		return false
	}
	for _, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

func run(name string, args ...string) error {
	if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, bytes.TrimSpace(out))
	}
	return nil
}
