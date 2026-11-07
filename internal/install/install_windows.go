package install

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"vpnlock/internal/paths"
)

// Installer ставит и снимает установку по раскладке Layout.
type Installer struct {
	Layout paths.Layout
	// Clear снимает правила файрвола. Удаление зовёт его, когда служба уже
	// остановлена (иначе её сторож вернул бы правила), а её файлы ещё на
	// месте: в них записано, что снимать.
	Clear func() error
	// Note — что сказать человеку после установки (про каталог); пусто — нечего.
	Note string
}

// Права на папки данных в SDDL. Владелец — администраторы (BA). P — права не
// наследуются от ProgramData: там любой пользователь может создавать файлы.
// Настройки и состояние — только у службы (SY) и администраторов: среди них
// адреса серверов VPN. Журнал службы читают и пользователи (BU): на него
// ссылается статус, когда служба не отвечает.
const (
	dataSDDL = "O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
	logSDDL  = "O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)"
)

// stopWait — сколько ждать, пока прежняя служба остановится.
const stopWait = 20 * time.Second

// Install ставит исполняемый файл src службой Windows и запускает её. Поверх
// прежней установки работает как обновление: служба перезапускается, настройки
// остаются.
func (in *Installer) Install(src string) error {
	L := in.Layout
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("диспетчер служб Windows: %w", err)
	}
	defer m.Disconnect()
	// Работающая служба держит свой vpnlock.exe: заменить его можно только
	// после остановки.
	if err := stopService(m); err != nil {
		return fmt.Errorf("не удалось остановить прежнюю службу: %w", err)
	}
	// Папка данных получает свои права раньше, чем в ней появится что-то ещё.
	if err := os.MkdirAll(L.DataDir, 0o755); err != nil {
		return err
	}
	if err := secure(L.DataDir, dataSDDL); err != nil {
		return fmt.Errorf("права на %s: %w", L.DataDir, err)
	}
	for _, d := range []string{L.StateDir, L.LogDir, filepath.Dir(L.Binary)} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}
	if err := secure(L.LogDir, logSDDL); err != nil {
		return fmt.Errorf("права на %s: %w", L.LogDir, err)
	}
	if err := put(src, L.Binary); err != nil {
		return fmt.Errorf("не удалось скопировать vpnlock: %w", err)
	}
	note, err := in.installCatalog(src)
	if err != nil {
		return err
	}
	in.Note = note
	if err := in.rememberClone(src); err != nil {
		return err
	}
	if err := addToPath(filepath.Dir(L.Binary)); err != nil {
		return fmt.Errorf("не удалось добавить vpnlock в PATH: %w", err)
	}
	if err := startService(m, L.Binary); err != nil {
		return err
	}
	in.Note = joinNotes(in.Note, in.installTasks(src))
	return nil
}

// put кладёт src на место dst. Работающий файл (команду vpnlock log в
// другом окне, агента уведомлений) Windows заменить не даёт, но даёт
// переименовать: прежний уезжает во временную папку Windows.
func put(src, dst string) error {
	if err := copyFile(src, dst, 0o755); err == nil {
		return nil
	}
	if err := moveAside(dst); err != nil {
		return err
	}
	return copyFile(src, dst, 0o755)
}

// installTasks ставит задачи планировщика: агента уведомлений, значок службы и
// ежедневное обновление каталога. Все запускают vpnlockw.exe — тот же vpnlock без
// окна консоли, его собирает подготовка рядом с vpnlock.exe. Не встали — служба
// работает и так; человек узнаёт почему.
func (in *Installer) installTasks(src string) string {
	quietSrc := filepath.Join(filepath.Dir(src), filepath.Base(in.Layout.QuietExe))
	if _, err := os.Stat(quietSrc); err != nil {
		return "Уведомления, значок и ежедневное обновление каталога не поставлены: рядом с vpnlock.exe нет vpnlockw.exe — запусти подготовку ещё раз."
	}
	if err := put(quietSrc, in.Layout.QuietExe); err != nil {
		return fmt.Sprintf("Уведомления, значок и ежедневное обновление каталога не поставлены: %v", err)
	}
	return joinNotes(joinNotes(in.installNotifyTask(), in.installTrayTask()), in.installCatalogTask(src))
}

// installNotifyTask: при входе любого пользователя в его сеансе запускается
// агент уведомлений.
func (in *Installer) installNotifyTask() string {
	if err := createTask(paths.NotifyTask, userTaskXML(in.Layout.QuietExe, "notify-agent", "vpnlock: уведомления о закрытии защищённых сервисов")); err != nil {
		return fmt.Sprintf("Уведомления не поставлены: %v", err)
	}
	if schtasks("/Run", "/TN", paths.NotifyTask) != nil {
		return "Уведомления о закрытии сервисов заработают после следующего входа в Windows."
	}
	return "Уведомления о закрытии сервисов включены: их показывает задача vpnlock-notify при входе в Windows."
}

// trayPin — Windows 11 прячет новые значки, а закрепить значок программно штатного
// способа нет: недокументированный IsPromoted в реестре не трогаем.
const trayPin = "Windows прячет новые значки за стрелку ^ на панели задач: перетащи значок vpnlock оттуда к часам, один раз."

// installTrayTask: при входе любого пользователя в его сеансе запускается значок
// службы. При обновлении /Run запускает второй экземпляр, он видит мьютекс и выходит.
func (in *Installer) installTrayTask() string {
	if err := createTask(paths.TrayTask, userTaskXML(in.Layout.QuietExe, "tray", "vpnlock: значок службы рядом с часами")); err != nil {
		return fmt.Sprintf("Значок не поставлен: %v. Защита работает и без него.", err)
	}
	if schtasks("/Run", "/TN", paths.TrayTask) != nil {
		return "Значок появится рядом с часами после следующего входа в Windows. " + trayPin
	}
	return "Значок vpnlock появился рядом с часами: есть значок — служба отвечает. " + trayPin
}

// installCatalogTask: раз в сутки и при входе того, кто ставит vpnlock, git
// pull в его клоне — с его ключами и паролями, — и служба берёт каталог из
// клона. Задача работает без повышения: в клон пишут и обычные программы, и
// хук git, подложенный туда, с наивысшими правами получил бы права
// администратора без окна UAC. Итог служба принимает от владельца клона.
func (in *Installer) installCatalogTask(src string) string {
	clone := filepath.Dir(filepath.Dir(src))
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return fmt.Sprintf("Ежедневное обновление каталога не поставлено: %v. Защита работает на текущем каталоге.", err)
	}
	if err := createTask(paths.CatalogTask, catalogTaskXML(in.Layout.QuietExe, clone, u.User.Sid.String())); err != nil {
		return fmt.Sprintf("Ежедневное обновление каталога не поставлено: %v. Защита работает на текущем каталоге.", err)
	}
	return "Ежедневное обновление каталога поставлено: раз в сутки git pull в клоне " + clone + "."
}

func xmlEscape(s string) string {
	var b strings.Builder
	xml.EscapeText(&b, []byte(s))
	return b.String()
}

// catalogTaskXML — задача «раз в сутки (пропущенный раз — как только можно) и
// при входе пользователя sid, от его имени с наивысшими правами, без окна».
func catalogTaskXML(exe, clone, sid string) string {
	return `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>vpnlock: каталог приложений из клона, раз в сутки</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>` + xmlEscape(sid) + `</UserId>
    </LogonTrigger>
    <CalendarTrigger>
      <StartBoundary>2026-01-01T12:00:00</StartBoundary>
      <Enabled>true</Enabled>
      <ScheduleByDay>
        <DaysInterval>1</DaysInterval>
      </ScheduleByDay>
    </CalendarTrigger>
  </Triggers>
  <Principals>
    <Principal id="Student">
      <UserId>` + xmlEscape(sid) + `</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <StartWhenAvailable>true</StartWhenAvailable>
    <ExecutionTimeLimit>PT10M</ExecutionTimeLimit>
    <Hidden>true</Hidden>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Student">
    <Exec>
      <Command>` + xmlEscape(exe) + `</Command>
      <Arguments>` + xmlEscape(`catalog sync "`+clone+`"`) + `</Arguments>
    </Exec>
  </Actions>
</Task>
`
}

// userTaskXML — задача «при входе любого пользователя (группа «Пользователи»), без
// прав администратора, без окна, сколько угодно долго»: exe с аргументом arg.
func userTaskXML(exe, arg, description string) string {
	esc := xmlEscape
	return `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>` + esc(description) + `</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Users">
      <GroupId>S-1-5-32-545</GroupId>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>Parallel</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <RestartOnFailure>
      <Interval>PT1M</Interval>
      <Count>3</Count>
    </RestartOnFailure>
    <Hidden>true</Hidden>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Users">
    <Exec>
      <Command>` + esc(exe) + `</Command>
      <Arguments>` + esc(arg) + `</Arguments>
    </Exec>
  </Actions>
</Task>
`
}

// createTask заводит задачу из XML. schtasks читает XML задачи в UTF-16.
func createTask(name, xmlText string) error {
	f, err := os.CreateTemp("", "vpnlock-task-*.xml")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	u := utf16.Encode([]rune(xmlText))
	b := make([]byte, 2+2*len(u))
	b[0], b[1] = 0xff, 0xfe // BOM UTF-16LE
	for i, c := range u {
		b[2+2*i], b[3+2*i] = byte(c), byte(c>>8)
	}
	_, err = f.Write(b)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return schtasks("/Create", "/TN", name, "/XML", f.Name(), "/F")
}

// schtasks — планировщик заданий Windows.
func schtasks(args ...string) error {
	sys, err := windows.GetSystemDirectory()
	if err != nil {
		return err
	}
	out, err := exec.Command(filepath.Join(sys, "schtasks.exe"), args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("schtasks %s: %v: %s", args[0], err, bytes.TrimSpace(out))
	}
	return nil
}

// startService заводит службу (или обновляет прежнюю) и запускает её. Служба
// стартует вместе с системой от имени LocalSystem, а если завершилась с
// ошибкой или упала, Windows запускает её снова.
func startService(m *mgr.Mgr, binary string) error {
	const description = "Защищённые приложения выходят в сеть только через проверенный VPN."
	s, err := m.OpenService(paths.ServiceName)
	switch {
	case errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST):
		s, err = m.CreateService(paths.ServiceName, binary, mgr.Config{
			DisplayName: "vpnlock",
			Description: description,
			StartType:   mgr.StartAutomatic,
		}, "daemon")
		if err != nil {
			return fmt.Errorf("не удалось завести службу: %w", err)
		}
	case err != nil:
		return err
	default:
		c, err := s.Config()
		if err != nil {
			s.Close()
			return err
		}
		c.BinaryPathName = syscall.EscapeArg(binary) + " daemon"
		c.DisplayName, c.Description, c.StartType = "vpnlock", description, mgr.StartAutomatic
		if err := s.UpdateConfig(c); err != nil {
			s.Close()
			return fmt.Errorf("не удалось обновить службу: %w", err)
		}
	}
	defer s.Close()
	restart := []mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: time.Second},
		{Type: mgr.ServiceRestart, Delay: time.Second},
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
	}
	if err := s.SetRecoveryActions(restart, uint32((24 * time.Hour).Seconds())); err != nil {
		return fmt.Errorf("перезапуск службы: %w", err)
	}
	// Служба, вышедшая с ошибкой, тоже перезапускается, а не только упавшая.
	if err := s.SetRecoveryActionsOnNonCrashFailures(true); err != nil {
		return fmt.Errorf("перезапуск службы: %w", err)
	}
	if err := s.Start(); err != nil {
		return fmt.Errorf("служба не запустилась: %w", err)
	}
	return nil
}

// stopService останавливает службу, если она есть и работает, и ждёт, пока её
// процесс завершится: до этого Windows не даст заменить или удалить vpnlock.exe.
func stopService(m *mgr.Mgr) error {
	s, err := m.OpenService(paths.ServiceName)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return nil
	}
	if err != nil {
		return err
	}
	defer s.Close()
	return stop(s)
}

func stop(s *mgr.Service) error {
	st, err := s.Query()
	if err != nil {
		return err
	}
	if st.State == svc.Stopped {
		return nil
	}
	var proc windows.Handle
	if st.ProcessId != 0 {
		proc, _ = windows.OpenProcess(windows.SYNCHRONIZE, false, st.ProcessId)
	}
	if proc != 0 {
		defer windows.CloseHandle(proc)
	}
	if st.State != svc.StopPending {
		if err := stopPlanned(s); err != nil && !errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) {
			return err
		}
	}
	deadline := time.Now().Add(stopWait)
	for {
		st, err := s.Query()
		if err != nil {
			return err
		}
		if st.State == svc.Stopped {
			break
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("служба не остановилась за %d секунд", int(stopWait.Seconds()))
		}
		time.Sleep(200 * time.Millisecond)
	}
	if proc != 0 {
		windows.WaitForSingleObject(proc, uint32(stopWait.Milliseconds()))
	}
	return nil
}

// Uninstall снимает службу и всё, что поставила установка. Службу сначала
// помечаем к удалению, потом останавливаем: даже если дальше что-то не выйдет,
// после перезагрузки она не стартует.
func (in *Installer) Uninstall() error {
	L := in.Layout
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("диспетчер служб Windows: %w", err)
	}
	defer m.Disconnect()
	var errs []error
	if err := deleteService(m); err != nil {
		errs = append(errs, err)
	}
	if in.Clear != nil {
		if err := in.Clear(); err != nil {
			errs = append(errs, err)
		}
	}
	// Задач может и не быть (не ставились) — это не ошибка.
	for _, task := range []string{paths.NotifyTask, paths.TrayTask, paths.CatalogTask} {
		if schtasks("/Query", "/TN", task) == nil {
			if err := schtasks("/Delete", "/TN", task, "/F"); err != nil {
				errs = append(errs, err)
			}
		}
	}
	if err := removeFromPath(filepath.Dir(L.Binary)); err != nil {
		errs = append(errs, fmt.Errorf("PATH: %w", err))
	}
	// Удаляют обычно установленной командой, то есть этим же vpnlock.exe, а
	// агенты уведомлений и значки ещё работают из vpnlockw.exe: работающие файлы
	// Windows удалить не даёт. Значок сам выйдет, когда увидит, что vpnlock удалён.
	for _, f := range []string{L.Binary, L.QuietExe} {
		if err := removeBusy(f); err != nil {
			errs = append(errs, err)
		}
	}
	for _, p := range []string{L.AppDir, L.DataDir} {
		if err := os.RemoveAll(p); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func deleteService(m *mgr.Mgr) error {
	s, err := m.OpenService(paths.ServiceName)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return nil
	}
	if err != nil {
		return err
	}
	defer s.Close()
	if err := s.Delete(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_MARKED_FOR_DELETE) {
		return fmt.Errorf("не удалось удалить службу: %w", err)
	}
	if err := stop(s); err != nil {
		return fmt.Errorf("не удалось остановить службу: %w", err)
	}
	return nil
}

// removeBusy удаляет файл, а работающий — переименовывает: удалить его
// Windows не даёт, а переименовать даёт.
func removeBusy(path string) error {
	err := os.Remove(path)
	if err == nil || errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return moveAside(path)
}

// moveAside уносит файл во временную папку Windows и ставит его на удаление
// при следующей загрузке; его место освобождается сразу.
func moveAside(path string) error {
	win, err := windows.GetWindowsDirectory()
	if err != nil {
		return err
	}
	aside := filepath.Join(win, "Temp", fmt.Sprintf("vpnlock-%d-%d-%s", os.Getpid(), time.Now().UnixNano(), filepath.Base(path)))
	if err := os.Rename(path, aside); err != nil {
		return fmt.Errorf("не удалось убрать работающий %s: %w", path, err)
	}
	p, err := windows.UTF16PtrFromString(aside)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(p, nil, windows.MOVEFILE_DELAY_UNTIL_REBOOT)
}

// Remove — служба не снимает себя сама: свой vpnlock.exe и открытые файлы
// журнала ей не удалить. На Windows vpnlock удаляют из PowerShell от имени
// администратора, и команда снимает всё на месте (Uninstall).
func (in *Installer) Remove() error {
	return errors.New("на Windows vpnlock удаляют из PowerShell от имени администратора: vpnlock uninstall")
}

// Stop просит диспетчер служб остановить службу, не дожидаясь этого.
func (in *Installer) Stop() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(paths.ServiceName)
	if err != nil {
		return err
	}
	defer s.Close()
	return stopPlanned(s)
}

// stopPlanned останавливает службу, предупредив, что остановку начал vpnlock
// (обновление, удаление): без предупреждения она выйдет с ошибкой, и диспетчер
// служб запустит её снова.
func stopPlanned(s *mgr.Service) error {
	if _, err := s.Control(svc.Cmd(paths.PlannedStop)); err != nil {
		return err
	}
	_, err := s.Control(svc.Stop)
	return err
}

// secure задаёт папке владельца и права из sddl; вложенные папки и файлы их
// наследуют.
func secure(path, sddl string) error {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	const info = windows.OWNER_SECURITY_INFORMATION | windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, info, owner, nil, dacl, nil)
}

// own — на Windows владельца и права файлам задаёт папка: файлы наследуют её ACL.
func own(string) error { return nil }

// envKey — системные переменные окружения в реестре.
const envKey = `SYSTEM\CurrentControlSet\Control\Session Manager\Environment`

// addToPath дописывает dir в конец системного PATH, если его там ещё нет.
// Команда vpnlock появится в новых окнах PowerShell.
func addToPath(dir string) error {
	return editPath(func(path string) string {
		for part := range strings.SplitSeq(path, ";") {
			if samePath(part, dir) {
				return path
			}
		}
		if path != "" && !strings.HasSuffix(path, ";") {
			path += ";"
		}
		return path + dir
	})
}

// removeFromPath убирает из системного PATH ровно dir; остальное не трогает.
func removeFromPath(dir string) error {
	return editPath(func(path string) string {
		var keep []string
		for part := range strings.SplitSeq(path, ";") {
			if !samePath(part, dir) {
				keep = append(keep, part)
			}
		}
		return strings.Join(keep, ";")
	})
}

func samePath(a, b string) bool {
	return strings.EqualFold(strings.TrimRight(strings.TrimSpace(a), `\`), strings.TrimRight(b, `\`))
}

// editPath меняет системный PATH, сохраняя тип значения (обычно REG_EXPAND_SZ:
// в нём бывают %SystemRoot% и подобные), и сообщает об этом открытым программам.
func editPath(edit func(string) string) error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, envKey, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	old, typ, err := k.GetStringValue("Path")
	if err != nil && !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, registry.ErrNotExist) {
		return err
	}
	path := edit(old)
	if path == old {
		return nil
	}
	if typ == registry.SZ {
		err = k.SetStringValue("Path", path)
	} else {
		err = k.SetExpandStringValue("Path", path)
	}
	if err != nil {
		return err
	}
	announceEnv()
	return nil
}

var sendMessageTimeout = windows.NewLazySystemDLL("user32.dll").NewProc("SendMessageTimeoutW")

// announceEnv рассылает WM_SETTINGCHANGE «Environment»: Проводник перечитает
// переменные окружения, и окна, открытые после установки, увидят новый PATH.
func announceEnv() {
	const (
		hwndBroadcast   = 0xffff
		wmSettingChange = 0x001a
		smtoAbortIfHung = 0x0002
	)
	env, err := windows.UTF16PtrFromString("Environment")
	if err != nil {
		return
	}
	var result uintptr
	sendMessageTimeout.Call(hwndBroadcast, wmSettingChange, 0, uintptr(unsafe.Pointer(env)),
		smtoAbortIfHung, 5000, uintptr(unsafe.Pointer(&result)))
}
