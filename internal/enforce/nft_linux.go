package enforce

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"

	"appguard/internal/procs"
)

// Table — таблица appguard в nftables. Своя таблица не трогает чужие правила и
// правила дистрибутива, а пакет проходит базовые цепочки всех таблиц: разрешение
// здесь не отменяет чужой запрет, запрет здесь окончательный.
const Table = "appguard"

// resolvConf — откуда видно, какими серверами DNS пользуются программы.
const resolvConf = "/etc/resolv.conf"

// NFT — исполнитель на nftables. Требует root.
//
// Защищённое приложение закрыто само: его процессы лежат в группе net_cls, у
// их сокетов метка класса, и всё помеченное выходит только через петлю и
// проверенные туннели (цепочка app). Адреса защищённых сервисов закрыты всем
// программам везде, кроме проверенных туннелей (цепочка guard): так сайт сервиса
// не откроется и в браузере. Как процессы попадают в группу, описывает jail.
//
// Правила и файл закрытых правил (ClosedFile) переживают падение службы: первые
// остаются в ядре, вторые старт службы грузит раньше неё самой. После
// перезагрузки таблицу ставит тот же файл, ещё до сети.
type NFT struct {
	// ClosedFile — те же правила, но со всеми закрытыми путями: их грузит
	// ExecStartPre службы.
	ClosedFile string
	// Logf — куда писать то, что защиту не снимает; nil — никуда.
	Logf func(format string, args ...any)

	mu    sync.Mutex
	jail  jail
	found found // что было в системе на момент последнего Apply
}

// found — что правилам нужно знать, кроме Rules: система знает это сама.
type found struct {
	dns []netip.Addr // серверы DNS в локальной сети
	// ports — порты сокетов ядра. Туннель в ядре (WireGuard) шифрует пакет на месте:
	// внешний пакет сохраняет сокет приложения, а с ним и метку группы, хотя уходит
	// с физического интерфейса. По этим портам пакеты туннеля узнаются раньше метки,
	// иначе защищённому приложению не было бы сети и через проверенный туннель.
	// Занять такой порт программа не может: он уже занят ядром.
	ports []uint16
}

func look() found { return found{dns: localDNS(resolvConf), ports: procs.KernelUDPPorts()} }

// Apply приводит таблицу к правилам r одной транзакцией nft: промежутка без
// правил нет.
func (n *NFT) Apply(r Rules) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.found = look()
	if err := nftLoad(ruleset(r, n.found)); err != nil {
		return err
	}
	if err := n.saveClosed(r); err != nil {
		return err
	}
	n.jail.logf = n.Logf
	return n.jail.set(r.Apps)
}

// saveClosed пишет правила для старта службы: все пути закрыты, адреса и серверы VPN
// — как сейчас.
func (n *NFT) saveClosed(r Rules) error {
	if n.ClosedFile == "" {
		return nil
	}
	r.OpenIfaces = nil
	text := []byte(ruleset(r, n.found))
	if cur, err := os.ReadFile(n.ClosedFile); err == nil && bytes.Equal(cur, text) {
		return nil
	}
	tmp := n.ClosedFile + ".new"
	if err := os.WriteFile(tmp, text, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, n.ClosedFile)
}

// Clear снимает всё: перехват запуска, таблицу, группу процессов, файл правил.
// Работает и в другом процессе, чем Apply: удаление через sudo идёт мимо службы.
func (n *NFT) Clear() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	errs := []error{n.jail.clear(), nftDelete()}
	if n.ClosedFile != "" {
		if err := os.Remove(n.ClosedFile); err != nil && !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Verify сверяет таблицу с правилами r, ничего не меняя: она на месте, в цепочках
// столько правил и в наборах столько адресов, сколько должно быть, группа процессов
// и перехват запуска живы. Сторож зовёт его раз в секунду.
func (n *NFT) Verify(r Rules) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	out, err := exec.Command("nft", "list", "table", "inet", Table).Output()
	if err != nil {
		return fmt.Errorf("таблицы %s нет", Table)
	}
	want, got := tally(ruleset(r, n.found)), tally(string(out))
	if !maps.Equal(want, got) {
		for _, k := range slices.Sorted(maps.Keys(want)) {
			if want[k] != got[k] {
				return fmt.Errorf("%s: %d вместо %d", k, got[k], want[k])
			}
		}
		return errors.New("в таблице лишние цепочки или наборы")
	}
	return n.jail.verify(r.Apps)
}

// Preflight проверяет на чистой системе, что ядро умеет всё нужное: установка
// узнаёт об этом раньше, чем что-то изменит.
func Preflight() error {
	if _, err := exec.LookPath("nft"); err != nil {
		return errors.New("нет программы nft: поставь пакет nftables")
	}
	cmd := exec.Command("nft", "--check", "-f", "-")
	cmd.Stdin = strings.NewReader(ruleset(Rules{}, found{}))
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("ядро не принимает правила nftables: %w: %s", err, bytes.TrimSpace(out))
	}
	// Уже смонтированную иерархию снимать нельзя: при обновлении в ней лежат
	// защищённые процессы.
	if root, _, err := findNetCls(); err == nil && root != "" {
		return nil
	}
	root, _, err := netClsRoot()
	if err != nil {
		return fmt.Errorf("в ядре нет контроллера net_cls, а без него защита по приложению невозможна (%w)", err)
	}
	return unmountRoot(root)
}

func nftLoad(text string) error {
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(text)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nft: %w: %s", err, bytes.TrimSpace(out))
	}
	return nil
}

// nftDelete снимает таблицу; её нет — не ошибка.
func nftDelete() error {
	return nftLoad(fmt.Sprintf("table inet %s\ndelete table inet %s\n", Table, Table))
}

// ruleset — текст правил для состояния r. Первые две строки заводят таблицу, если
// её нет, и удаляют; всё вместе — одна транзакция, так таблица заменяется целиком.
// Правила и элементы наборов tally считает по этому же тексту и по выводу nft:
// по правилу на строку, элементы через запятую.
//
// Цепочки сами по себе без состояния: каждый пакет проверяется заново, поэтому
// соединение, открытое через туннель, не проскочит в Wi‑Fi, когда VPN оборвётся.
func ruleset(r Rules, f found) string {
	var b strings.Builder
	fmt.Fprintf(&b, "table inet %s\ndelete table inet %s\ntable inet %s {\n", Table, Table, Table)
	fmt.Fprintf(&b, "\tset addrs4 {\n\t\ttype ipv4_addr\n%s\t}\n", elements(r.V4))
	fmt.Fprintf(&b, "\tset addrs6 {\n\t\ttype ipv6_addr\n%s\t}\n", elements(r.V6))
	open := ifaceSet(r.OpenIfaces)

	// Адреса защищённых сервисов — всем программам. Через проверенный туннель они
	// открыты; сервер VPN на таком адресе (VPN через CDN) открыт на физическом
	// интерфейсе, иначе клиент VPN не подключится; везде ещё — закрыты.
	b.WriteString("\tchain guard {\n")
	if open != "" {
		fmt.Fprintf(&b, "\t\toifname %s accept\n", open)
	}
	if okIface(r.Physical) {
		v4, v6 := split(r.Servers)
		if len(v4) > 0 {
			fmt.Fprintf(&b, "\t\toifname %q ip daddr { %s } accept\n", r.Physical, join(v4))
		}
		if len(v6) > 0 {
			fmt.Fprintf(&b, "\t\toifname %q ip6 daddr { %s } accept\n", r.Physical, join(v6))
		}
	}
	b.WriteString("\t\tip daddr @addrs4 drop\n\t\tip6 daddr @addrs6 drop\n\t}\n")

	// Защищённым приложениям — петля и проверенные туннели. DNS в локальной сети
	// открыт: без него приложение не узнало бы адрес и через VPN, а домашний адрес
	// видит только собственный роутер. Остальное — отказ, а не тишина: приложение
	// сразу узнаёт, что сети нет, и не висит на таймаутах.
	b.WriteString("\tchain app {\n\t\toifname \"lo\" accept\n")
	if open != "" {
		fmt.Fprintf(&b, "\t\toifname %s accept\n", open)
	}
	v4, v6 := split(f.dns)
	if len(v4) > 0 {
		fmt.Fprintf(&b, "\t\tip daddr { %s } meta l4proto { tcp, udp } th dport 53 accept\n", join(v4))
	}
	if len(v6) > 0 {
		fmt.Fprintf(&b, "\t\tip6 daddr { %s } meta l4proto { tcp, udp } th dport 53 accept\n", join(v6))
	}
	b.WriteString("\t\treject with icmpx admin-prohibited\n\t}\n")

	b.WriteString("\tchain output {\n\t\ttype filter hook output priority filter - 10; policy accept;\n")
	if len(f.ports) > 0 {
		fmt.Fprintf(&b, "\t\tudp sport { %s } accept\n", joinPorts(f.ports))
	}
	fmt.Fprintf(&b, "\t\tmeta cgroup %d jump app\n\t\tjump guard\n\t}\n", classID)
	// Чужой трафик через этот компьютер (виртуалки, контейнеры) до адресов сервисов
	// тоже не доходит, как и на macOS.
	b.WriteString("\tchain forward {\n\t\ttype filter hook forward priority filter - 10; policy accept;\n\t\tjump guard\n\t}\n}\n")
	return b.String()
}

// elements — строка elements для набора; пустой набор без неё.
func elements(addrs []netip.Addr) string {
	list := clean(addrs)
	if len(list) == 0 {
		return ""
	}
	return "\t\telements = { " + join(list) + " }\n"
}

func join(addrs []netip.Addr) string {
	strs := make([]string, len(addrs))
	for i, a := range addrs {
		strs[i] = a.String()
	}
	return strings.Join(strs, ", ")
}

func joinPorts(ports []uint16) string {
	strs := make([]string, len(ports))
	for i, p := range ports {
		strs[i] = strconv.Itoa(int(p))
	}
	return strings.Join(strs, ", ")
}

// clean — адреса без зоны и без обёртки IPv4 в IPv6, сортированные и без повторов:
// повтор в наборе nft считает ошибкой.
func clean(addrs []netip.Addr) []netip.Addr {
	var out []netip.Addr
	for _, a := range addrs {
		if a = a.Unmap().WithZone(""); a.IsValid() {
			out = append(out, a)
		}
	}
	slices.SortFunc(out, netip.Addr.Compare)
	return slices.Compact(out)
}

func split(addrs []netip.Addr) (v4, v6 []netip.Addr) {
	for _, a := range clean(addrs) {
		if a.Is4() {
			v4 = append(v4, a)
		} else {
			v6 = append(v6, a)
		}
	}
	return v4, v6
}

// ifaceSet — набор имён интерфейсов для правила; пусто — ни одного годного.
func ifaceSet(names []string) string {
	var ok []string
	for _, n := range names {
		if okIface(n) {
			ok = append(ok, fmt.Sprintf("%q", n))
		}
	}
	if len(ok) == 0 {
		return ""
	}
	slices.Sort(ok)
	return "{ " + strings.Join(slices.Compact(ok), ", ") + " }"
}

var ifaceName = regexp.MustCompile(`^[A-Za-z0-9._-]{1,15}$`)

// okIface — имя интерфейса: в правила nft не попадёт ничего постороннего, а
// интерфейс с другим именем останется закрытым.
func okIface(name string) bool { return ifaceName.MatchString(name) }

var elementsRe = regexp.MustCompile(`(?s)elements = \{(.*?)\}`)

// tally считает в тексте правил — своём или из вывода `nft list table` — правила
// в каждой цепочке и элементы в каждом наборе.
func tally(text string) map[string]int {
	out := map[string]int{}
	kind, name := "", ""
	depth := 0
	if _, rest, ok := strings.Cut(text, "\ndelete table"); ok {
		text = rest // две первые строки своего текста — не содержимое таблицы
	}
	start := strings.Index(text, "table inet")
	if start < 0 {
		return out
	}
	lines := strings.Split(elementsRe.ReplaceAllStringFunc(text[start:], func(m string) string {
		return "elements " + strings.ReplaceAll(strings.Trim(strings.TrimPrefix(m, "elements = "), "{} \n\t"), "\n", " ")
	}), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		switch {
		case line == "":
		case strings.HasPrefix(line, "table inet"):
		case strings.HasPrefix(line, "set ") || strings.HasPrefix(line, "chain "):
			f := strings.Fields(line)
			kind, name = f[0], f[1]
			out[kind+" "+name] = 0
			depth = 1
		case line == "}":
			if depth--; depth <= 0 {
				kind = ""
			}
		case kind == "chain" && !strings.HasPrefix(line, "type "):
			out["chain "+name]++
		case kind == "set" && strings.HasPrefix(line, "elements "):
			out["set "+name] += strings.Count(line, ",") + 1
		}
	}
	return out
}

// localDNS — серверы DNS из файла path, которые лежат в локальной сети. Заглушка
// systemd-resolved (127.0.0.53) на петле и так открыта, а публичный сервер пойдёт
// через туннель.
func localDNS(path string) []netip.Addr {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil
	}
	return parseLocalDNS(data)
}

func parseLocalDNS(data []byte) []netip.Addr {
	var out []netip.Addr
	for line := range strings.Lines(string(data)) {
		f := strings.Fields(line)
		if len(f) < 2 || f[0] != "nameserver" {
			continue
		}
		if a, err := netip.ParseAddr(f[1]); err == nil && (a.IsPrivate() || a.IsLinkLocalUnicast()) {
			out = append(out, a.Unmap().WithZone(""))
		}
	}
	return out
}
