package enforce

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"vpnlock/internal/apps"
	"vpnlock/internal/procs"
)

// classID — метка net_cls на сокетах защищённых процессов: «VLK» и единица. Её
// видят правила: meta cgroup.
const classID = 0x564c4b01

const (
	// netClsMount — куда служба монтирует иерархию net_cls, если её никто не
	// смонтировал раньше.
	netClsMount = "/run/vpnlock/net_cls"
	// jailDir — группа защищённых процессов внутри иерархии: по подгруппе на приложение.
	jailDir = "vpnlock"
	// sweepEvery — как часто просматривать процессы: так под защиту попадает то,
	// что запуск не поймал (скрипт через интерпретатор, запуск при лежащей службе).
	sweepEvery = 2 * time.Second
	// remarkEvery — как часто обновлять перехват: файл заменили обновлением, в
	// папке появилась новая вложенная папка.
	remarkEvery = 10 * time.Second
)

// Пределы обхода папки установки: глубже и больше папок у приложений не бывает.
const (
	maxDepth = 8
	maxDirs  = 1000
)

// jail собирает процессы защищённых приложений в группы net_cls.
//
// Почему net_cls, хотя это наследие cgroup v1: метка живёт в своей иерархии, куда
// systemd не заглядывает, поэтому переживает перемещение процесса в другой scope
// (GNOME и snap так делают с каждым запущенным приложением), и при переносе процесса
// ядро ставит её и на уже открытые сокеты — соединения, начатые до защиты, тоже
// закрываются. У `socket cgroupv2` нет ни того, ни другого.
//
// В группу процесс попадает раньше, чем выполнит первую инструкцию: fanotify
// останавливает запуск защищённого файла, пока служба не перенесёт процесс
// (FAN_OPEN_EXEC_PERM). Перехват стоит только на файлах и папках приложений, а не
// на всей системе: зависшая служба не остановит чужие программы, и ядро само
// пропускает всё ожидающее, когда служба завершается. Дети наследуют группу.
//
// Раз в sweepEvery просмотр процессов ловит то, что перехват не видит: `python3
// bot.py` (сам файл не запускается), программы, запущенные, пока служба лежала, и
// процессы, которые уже работали, когда приложение добавили. Их открытые соединения
// закрываются вместе с переносом.
type jail struct {
	logf func(format string, args ...any)

	mu      sync.Mutex
	root    string // корень иерархии net_cls
	ours    bool   // иерархию смонтировала служба
	targets atomic.Pointer[[]*target]
	fan     *os.File // fanotify; nil — перехвата нет: ядро без него или он ещё не поставлен
	noFan   bool     // ядро не умеет перехват: о нём больше не спрашивать
	dead    atomic.Bool
	marked  map[string]bool // что уже под перехватом
	stop    chan struct{}
	said    map[int]bool // о каких процессах уже сказано
}

// target — приложение и его группа.
type target struct {
	key  string // как в Rules.Apps
	ref  procs.AppRef
	dir  string   // группа приложения
	unit string   // служба systemd; пусто у программы
	exes []string // файлы службы: на них перехват с проверкой её cgroup
}

// set приводит группы и перехват к списку приложений. Защищённые сейчас процессы
// переносятся сразу: команда `add` возвращается, когда они уже закрыты.
func (j *jail) set(list []string) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if len(list) == 0 && j.root == "" {
		if root, _, err := findNetCls(); err != nil || root == "" {
			return nil // приложений не было и нет: монтировать незачем
		}
	}
	if err := j.open(); err != nil {
		return err
	}
	var next []*target
	want := map[string]bool{}
	for _, key := range list {
		t := j.target(key)
		if err := os.MkdirAll(t.dir, 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(t.dir, "net_cls.classid"), []byte(strconv.Itoa(classID)), 0o644); err != nil {
			return err
		}
		want[filepath.Base(t.dir)] = true
		next = append(next, t)
	}
	j.targets.Store(&next)
	j.remark()
	j.sweep()
	// Убранные приложения отпускаются последними: их процессы снова выходят в сеть
	// как обычно, а остальные группы при этом не трогаются.
	entries, err := os.ReadDir(filepath.Join(j.root, jailDir))
	if err != nil {
		return err
	}
	var errs []error
	for _, e := range entries {
		if e.IsDir() && !want[e.Name()] {
			errs = append(errs, j.release(filepath.Join(j.root, jailDir, e.Name())))
		}
	}
	if j.stop == nil {
		j.stop = make(chan struct{})
		go j.loop(j.stop)
	}
	return errors.Join(errs...)
}

// target описывает приложение key: файл, папку установки или службу.
func (j *jail) target(key string) *target {
	sum := sha256.Sum256([]byte(key))
	t := &target{key: key, ref: procs.AppRef{ID: key, Path: key, Command: true},
		dir: filepath.Join(j.root, jailDir, hex.EncodeToString(sum[:8]))}
	if unit, ok := strings.CutPrefix(key, apps.ServicePrefix); ok {
		t.unit = unit
		t.exes, _ = apps.ServiceExecs(unit)
	}
	return t
}

// open монтирует иерархию и заводит перехват.
func (j *jail) open() error {
	if j.root == "" {
		root, ours, err := netClsRoot()
		if err != nil {
			return fmt.Errorf("контроллер net_cls: %w", err)
		}
		j.root, j.ours = root, ours
	}
	if err := os.MkdirAll(filepath.Join(j.root, jailDir), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(j.root, jailDir, "net_cls.classid"), []byte(strconv.Itoa(classID)), 0o644); err != nil {
		return err
	}
	if j.fan != nil && !j.dead.Load() || j.noFan {
		return nil
	}
	j.closeFan()
	fd, err := unix.FanotifyInit(unix.FAN_CLASS_CONTENT|unix.FAN_CLOEXEC|unix.FAN_NONBLOCK, unix.O_RDONLY|unix.O_LARGEFILE|unix.O_CLOEXEC)
	if err != nil {
		// Ядро без CONFIG_FANOTIFY_ACCESS_PERMISSIONS: остаётся просмотр процессов.
		j.noFan = true
		j.log("перехвата запуска нет (%v): приложение попадает под защиту в течение %v после старта", err, sweepEvery)
		return nil
	}
	j.fan = os.NewFile(uintptr(fd), "fanotify")
	j.marked = map[string]bool{}
	j.dead.Store(false)
	go j.gate(j.fan)
	return nil
}

func (j *jail) closeFan() {
	if j.fan != nil {
		j.fan.Close()
		j.fan = nil
	}
}

func (j *jail) log(format string, args ...any) {
	if j.logf != nil {
		j.logf(format, args...)
	}
}

// loop просматривает процессы и обновляет перехват, пока не закрыт stop.
func (j *jail) loop(stop <-chan struct{}) {
	sweep := time.NewTicker(sweepEvery)
	defer sweep.Stop()
	remark := time.NewTicker(remarkEvery)
	defer remark.Stop()
	for {
		select {
		case <-stop:
			return
		case <-sweep.C:
			j.mu.Lock()
			j.sweep()
			j.mu.Unlock()
		case <-remark.C:
			j.mu.Lock()
			j.remark()
			j.mu.Unlock()
		}
	}
}

// sweep переносит в группы процессы защищённых приложений, которые не там.
// Вызывать под j.mu.
func (j *jail) sweep() {
	list := j.current()
	if len(list) == 0 {
		return
	}
	resolve := procs.Resolver()
	for _, p := range procs.Processes() {
		if strings.HasPrefix(p.NetCls, "/"+jailDir+"/") {
			continue
		}
		for _, t := range list {
			if !procs.Belongs(p, t.ref, resolve) {
				continue
			}
			if err := move(t.dir, p.PID); err == nil && !j.said[p.PID] {
				if j.said == nil {
					j.said = map[int]bool{}
				}
				j.said[p.PID] = true
				j.log("процесс %d (%s) закрыт просмотром, а не перехватом запуска", p.PID, p.Exe)
			}
			break
		}
	}
}

func (j *jail) current() []*target {
	if p := j.targets.Load(); p != nil {
		return *p
	}
	return nil
}

// remark ставит перехват на файлы и папки приложений. Повторная метка на тот же
// файл ничего не меняет, а на новый — ставит: так перехват догоняет обновления.
// Вызывать под j.mu.
func (j *jail) remark() {
	if j.fan == nil {
		return
	}
	want := map[string]bool{} // путь → папка
	for _, t := range j.current() {
		switch {
		case t.unit != "":
			for _, exe := range t.exes {
				want[exe] = false
			}
		default:
			for _, m := range marksFor(t.key) {
				want[m.path] = m.dir
			}
		}
	}
	for _, tool := range selfRun() {
		delete(want, tool)
	}
	fd := int(j.fan.Fd())
	for path, dir := range want {
		flags, mask := uint(unix.FAN_MARK_ADD), uint64(unix.FAN_OPEN_EXEC_PERM)
		if dir {
			flags |= unix.FAN_MARK_ONLYDIR
			mask |= unix.FAN_EVENT_ON_CHILD
		}
		if err := unix.FanotifyMark(fd, flags, mask, unix.AT_FDCWD, path); err != nil {
			if !errors.Is(err, unix.ENOENT) {
				j.log("перехват запуска %s: %v", path, err)
			}
			continue
		}
		j.marked[path] = dir
	}
	for path, dir := range j.marked {
		if _, ok := want[path]; ok {
			continue
		}
		flags, mask := uint(unix.FAN_MARK_REMOVE), uint64(unix.FAN_OPEN_EXEC_PERM)
		if dir {
			flags |= unix.FAN_MARK_ONLYDIR
			mask |= unix.FAN_EVENT_ON_CHILD
		}
		unix.FanotifyMark(fd, flags, mask, unix.AT_FDCWD, path) // файла уже нет — метка ушла вместе с ним
		delete(j.marked, path)
	}
}

// selfTools — программы, которые запускает сама служба.
var selfTools = []string{"nft", "ip", "resolvectl", "systemctl", "loginctl", "notify-send"}

// selfRun — настоящие пути программ службы. Перехват на них ставить нельзя: Go
// запускает программу через vfork и, пока exec не завершится, держит за собой
// планировщик. Запуск упёрся бы в метку, ответить на которую должен этот же процесс,
// и служба встала бы, а за ней — все запуски помеченного файла. Такую программу
// закрывает просмотр процессов.
func selfRun() []string {
	var out []string
	for _, name := range selfTools {
		if p, err := exec.LookPath(name); err == nil {
			if real, err := filepath.EvalSymlinks(p); err == nil {
				out = append(out, real)
			}
		}
	}
	return out
}

// mark — что поставить под перехват.
type mark struct {
	path string
	dir  bool
}

// marksFor — метки приложения: сам файл или папка установки со всеми вложенными
// папками. Метка на папку ловит и файлы, которые в ней появятся.
func marksFor(path string) []mark {
	fi, err := os.Stat(path)
	if err != nil {
		return nil
	}
	if !fi.IsDir() {
		return []mark{{path, false}}
	}
	out := []mark{}
	var walk func(dir string, depth int)
	walk = func(dir string, depth int) {
		if len(out) >= maxDirs {
			return
		}
		out = append(out, mark{dir, true})
		if depth >= maxDepth {
			return
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		for _, e := range entries {
			if e.IsDir() {
				walk(filepath.Join(dir, e.Name()), depth+1)
			}
		}
	}
	walk(path, 0)
	return out
}

// gate отвечает на запуски защищённых файлов: переносит процесс в группу и
// разрешает запуск. Запрета нет никогда: не вышло — запуск всё равно идёт, а
// сеть у процесса закроет просмотр.
func (j *jail) gate(fan *os.File) {
	buf := make([]byte, 4096)
	size := int(unsafe.Sizeof(unix.FanotifyEventMetadata{}))
	for {
		n, err := fan.Read(buf)
		if err != nil {
			if !errors.Is(err, os.ErrClosed) {
				j.log("перехват запуска остановился: %v", err)
				j.dead.Store(true)
			}
			return
		}
		for off := 0; off+size <= n; {
			m := (*unix.FanotifyEventMetadata)(unsafe.Pointer(&buf[off]))
			if m.Vers != unix.FANOTIFY_METADATA_VERSION || int(m.Event_len) < size {
				j.log("перехват запуска: неизвестный формат события")
				j.dead.Store(true)
				return
			}
			j.pass(fan, m)
			off += int(m.Event_len)
		}
	}
}

// pass решает судьбу одного запуска и закрывает дескриптор события.
func (j *jail) pass(fan *os.File, m *unix.FanotifyEventMetadata) {
	if m.Fd < 0 {
		return
	}
	defer unix.Close(int(m.Fd))
	if path, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(int(m.Fd))); err == nil {
		if t := j.owner(int(m.Pid), path); t != nil {
			if err := move(t.dir, int(m.Pid)); err != nil && !errors.Is(err, unix.ESRCH) {
				j.log("не удалось закрыть процесс %d (%s): %v", m.Pid, path, err)
			}
		}
	}
	r := unix.FanotifyResponse{Fd: m.Fd, Response: unix.FAN_ALLOW}
	if _, err := fan.Write(unsafe.Slice((*byte)(unsafe.Pointer(&r)), unsafe.Sizeof(r))); err != nil && !errors.Is(err, os.ErrClosed) {
		j.log("перехват запуска: ответ ядру: %v", err)
	}
}

// owner — приложение, к которому относится запуск файла path процессом pid. Файл
// службы (интерпретатор и другие общие программы) считается, только если процесс
// работает в её cgroup: систему целиком он не касается.
func (j *jail) owner(pid int, path string) *target {
	list := j.current()
	for _, t := range list {
		if t.unit == "" && (path == t.key || strings.HasPrefix(path, t.key+"/")) {
			return t
		}
	}
	var unified string
	for _, t := range list {
		if t.unit == "" || !slices.Contains(t.exes, path) {
			continue
		}
		if unified == "" {
			if data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cgroup"); err == nil {
				unified, _ = procs.ParseCgroups(data)
			}
		}
		if procs.InUnit(unified, t.unit) {
			return t
		}
	}
	return nil
}

// move переносит процесс pid в группу dir. Ядро переставляет метку и на его
// открытые сокеты.
func move(dir string, pid int) error {
	return os.WriteFile(filepath.Join(dir, "cgroup.procs"), []byte(strconv.Itoa(pid)), 0o644)
}

// release выпускает процессы группы dir в корень иерархии и удаляет группу.
func (j *jail) release(dir string) error {
	var err error
	for range 5 { // пока переносили, процесс мог породить ребёнка
		data, rerr := os.ReadFile(filepath.Join(dir, "cgroup.procs"))
		if errors.Is(rerr, fs.ErrNotExist) {
			return nil
		}
		for f := range strings.FieldsSeq(string(data)) {
			if pid, perr := strconv.Atoi(f); perr == nil {
				if merr := move(j.rootOf(dir), pid); merr != nil && !errors.Is(merr, unix.ESRCH) {
					j.log("процесс %d остался закрытым: %v", pid, merr)
				}
			}
		}
		if err = unix.Rmdir(dir); err == nil {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("группа %s: %w", dir, err)
}

// rootOf — корень иерархии для группы dir: <корень>/vpnlock/<приложение>.
func (j *jail) rootOf(dir string) string { return filepath.Dir(filepath.Dir(dir)) }

// clear снимает перехват и выпускает всех. Работает и там, где set не вызывался:
// `sudo vpnlock uninstall` — другой процесс, чем служба.
func (j *jail) clear() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.closeFan()
	j.targets.Store(nil)
	if j.stop != nil {
		close(j.stop)
		j.stop = nil
	}
	root, ours := j.root, j.ours
	if root == "" {
		found, mine, err := findNetCls()
		if err != nil || found == "" {
			return err
		}
		root, ours = found, mine
	}
	j.root = ""
	group := filepath.Join(root, jailDir)
	entries, err := os.ReadDir(group)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	var errs []error
	for _, e := range entries {
		if e.IsDir() {
			errs = append(errs, j.release(filepath.Join(group, e.Name())))
		}
	}
	if err := unix.Rmdir(group); err != nil && !errors.Is(err, unix.ENOENT) {
		errs = append(errs, err)
	}
	if ours {
		errs = append(errs, unmountRoot(root))
	}
	return errors.Join(errs...)
}

// verify — группы на месте, метка в них верная, перехват жив.
func (j *jail) verify(list []string) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if len(list) == 0 {
		return nil
	}
	if j.root == "" {
		return errors.New("группа защищённых приложений не создана")
	}
	if j.dead.Load() {
		return errors.New("перехват запуска остановился")
	}
	if n := len(j.current()); n != len(list) {
		return fmt.Errorf("приложений под защитой %d вместо %d", n, len(list))
	}
	for _, t := range j.current() {
		data, err := os.ReadFile(filepath.Join(t.dir, "net_cls.classid"))
		if err != nil {
			return fmt.Errorf("группы приложения %s нет", t.key)
		}
		if strings.TrimSpace(string(data)) != strconv.Itoa(classID) {
			return fmt.Errorf("у группы приложения %s другая метка", t.key)
		}
	}
	return nil
}

// netClsRoot — корень иерархии net_cls; смонтированной нет — монтирует свою. ours —
// смонтировала служба, ей и снимать.
func netClsRoot() (root string, ours bool, err error) {
	root, ours, err = findNetCls()
	if err != nil || root != "" {
		return root, ours, err
	}
	if err := os.MkdirAll(netClsMount, 0o755); err != nil {
		return "", false, err
	}
	if err := unix.Mount("vpnlock", netClsMount, "cgroup", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, "net_cls"); err != nil {
		return "", false, fmt.Errorf("mount: %w", err)
	}
	return netClsMount, true, nil
}

// findNetCls — смонтированная иерархия net_cls из /proc/self/mountinfo: её могли
// смонтировать раньше служба или другая программа (контейнеры, клиент VPN).
func findNetCls() (root string, ours bool, err error) {
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return "", false, err
	}
	root = parseNetCls(data)
	return root, root == netClsMount, nil
}

// parseNetCls находит в mountinfo точку монтирования файловой системы cgroup с
// контроллером net_cls.
func parseNetCls(mountinfo []byte) string {
	for line := range bytes.Lines(mountinfo) {
		left, right, ok := strings.Cut(strings.TrimSpace(string(line)), " - ")
		if !ok {
			continue
		}
		l, r := strings.Fields(left), strings.Fields(right)
		if len(l) < 5 || len(r) < 3 || r[0] != "cgroup" {
			continue
		}
		if slices.Contains(strings.Split(r[2], ","), "net_cls") {
			return l[4]
		}
	}
	return ""
}

func unmountRoot(root string) error {
	if err := unix.Unmount(root, 0); err != nil {
		return fmt.Errorf("umount %s: %w", root, err)
	}
	os.Remove(root)
	os.Remove(filepath.Dir(root))
	return nil
}
