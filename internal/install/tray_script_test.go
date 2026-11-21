//go:build !windows

package install

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

const (
	ubuntuUUID = "ubuntu-appindicators@ubuntu.com"
	fedoraUUID = "appindicatorsupport@rgcjonas.gmail.com"
	extPackage = "gnome-shell-extension-appindicator"
)

// trayStand — система для setup/linux/tray.sh: каталог подменённых программ и запись
// того, что скрипт вызвал. PATH содержит только их и пару системных утилит, поэтому
// менеджер пакетов на машине с тестом на результат не влияет.
type trayStand struct {
	t    *testing.T
	bin  string
	data string // XDG_DATA_DIRS: откуда виден каталог расширений
	log  string
	env  map[string]string
}

func newTrayStand(t *testing.T) *trayStand {
	t.Helper()
	dir := t.TempDir()
	s := &trayStand{
		t: t, bin: filepath.Join(dir, "bin"), data: filepath.Join(dir, "share"), log: filepath.Join(dir, "calls"),
		env: map[string]string{"DISPLAY": ":0", "XDG_CURRENT_DESKTOP": "ubuntu:GNOME"},
	}
	if err := os.MkdirAll(s.bin, 0o755); err != nil {
		t.Fatal(err)
	}
	// grep нужен скрипту, остальное — подменённым программам.
	for _, tool := range []string{"grep", "mkdir", "cat", "chmod", "dirname"} {
		path, err := exec.LookPath(tool)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(path, filepath.Join(s.bin, tool)); err != nil {
			t.Fatal(err)
		}
	}
	// setsid запускает значок, pkill снимает прежний: записываем, а не запускаем.
	s.program("setsid", `echo "setsid $*" >>"$LOG"`)
	s.program("pkill", `echo "pkill $*" >>"$LOG"`)
	s.program("id", `echo 1000`)
	s.program("sleep", `exit 0`)
	s.host(false)
	return s
}

// program подменяет программу.
func (s *trayStand) program(name, body string) {
	s.t.Helper()
	text := "#!/bin/bash\n" + body + "\n"
	if err := os.WriteFile(filepath.Join(s.bin, name), []byte(text), 0o755); err != nil {
		s.t.Fatal(err)
	}
}

// host — есть ли на шине область значков.
func (s *trayStand) host(has bool) {
	s.program("gdbus", fmt.Sprintf(`echo "(%v,)"`, has))
}

// extensionAt кладёт расширение на диск, как его положил бы пакет.
func (s *trayStand) extensionAt(uuid string) {
	s.t.Helper()
	if err := os.MkdirAll(filepath.Join(s.data, "gnome-shell", "extensions", uuid), 0o755); err != nil {
		s.t.Fatal(err)
	}
}

// packageManager подменяет менеджер пакетов и sudo: успешная установка кладёт
// расширение uuid на диск.
func (s *trayStand) packageManager(name, uuid string) {
	s.program("sudo", `shift 2; exec "$@"`)
	s.program(name, fmt.Sprintf(`echo "%s $*" >>"$LOG"; mkdir -p "%s/gnome-shell/extensions/%s"`, name, s.data, uuid))
}

// run запускает скрипт и возвращает его вывод и что он вызвал.
func (s *trayStand) run() (out, calls string) {
	s.t.Helper()
	cmd := exec.Command("/bin/bash", "../../setup/linux/tray.sh", "/opt/appguard/bin/appguard")
	cmd.Env = []string{"PATH=" + s.bin, "HOME=" + s.t.TempDir(), "LOG=" + s.log, "XDG_DATA_DIRS=" + s.data}
	for k, v := range s.env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	b, err := cmd.CombinedOutput()
	if err != nil {
		s.t.Fatalf("шаг прервал установку: %v\n%s", err, b)
	}
	// Значок запускается в фоне: дождаться его записи.
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		if data, _ := os.ReadFile(s.log); strings.Contains(string(data), "setsid") {
			break
		}
		if s.env["DISPLAY"] == "" && s.env["WAYLAND_DISPLAY"] == "" {
			break
		}
	}
	data, _ := os.ReadFile(s.log)
	return string(b), string(data)
}

func wantIn(t *testing.T, text string, parts ...string) {
	t.Helper()
	for _, p := range parts {
		if !strings.Contains(text, p) {
			t.Errorf("нет %q в:\n%s", p, text)
		}
	}
}

func wantNot(t *testing.T, text string, parts ...string) {
	t.Helper()
	for _, p := range parts {
		if strings.Contains(text, p) {
			t.Errorf("лишнее %q в:\n%s", p, text)
		}
	}
}

// Ubuntu: область значков уже есть, шаг ничего не ставит и только запускает значок.
func TestTrayStepSkipsWhenHostExists(t *testing.T) {
	s := newTrayStand(t)
	s.host(true)
	s.packageManager("apt-get", ubuntuUUID)
	out, calls := s.run()
	wantIn(t, out, "рядом с часами")
	wantNot(t, calls, "apt-get")
	wantIn(t, calls, "setsid /opt/appguard/bin/appguard tray")
	// Прежний значок (до обновления) снят раньше, чем запущен новый, и только он.
	if i := strings.Index(calls, "pkill -u 1000 -xf /opt/appguard/bin/appguard tray"); i < 0 || i > strings.Index(calls, "setsid") {
		t.Errorf("прежний значок не снят перед запуском нового:\n%s", calls)
	}
}

// Чистый GNOME: нужный пакет своим менеджером, UUID — тот, что лёг на диск.
func TestTrayStepInstallsExtension(t *testing.T) {
	for _, tt := range []struct{ manager, uuid, want string }{
		{"apt-get", ubuntuUUID, "apt-get install -y " + extPackage},
		{"dnf", fedoraUUID, "dnf install -y " + extPackage},
		{"pacman", fedoraUUID, "pacman -S --noconfirm " + extPackage},
		{"zypper", fedoraUUID, "zypper --non-interactive install " + extPackage},
	} {
		t.Run(tt.manager, func(t *testing.T) {
			s := newTrayStand(t)
			s.packageManager(tt.manager, tt.uuid)
			s.program("gnome-extensions", `echo "gnome-extensions $*" >>"$LOG"`)
			out, calls := s.run()
			wantIn(t, calls, tt.want, "gnome-extensions enable "+tt.uuid, "setsid /opt/appguard/bin/appguard tray")
			wantIn(t, out, "после следующего входа")
		})
	}
}

// Debian кладёт расширение под тем же UUID, что Ubuntu: система здесь ни при чём.
func TestTrayStepTakesUUIDFromDisk(t *testing.T) {
	s := newTrayStand(t)
	s.env["XDG_CURRENT_DESKTOP"] = "GNOME"
	s.packageManager("apt-get", ubuntuUUID)
	s.program("gnome-extensions", `echo "gnome-extensions $*" >>"$LOG"`)
	_, calls := s.run()
	wantIn(t, calls, "gnome-extensions enable "+ubuntuUUID)
	wantNot(t, calls, fedoraUUID)
}

// Расширение стоит, но выключено: пакет не ставится, и если Shell сразу его подхватил,
// ждать входа незачем.
func TestTrayStepEnablesInstalledExtension(t *testing.T) {
	s := newTrayStand(t)
	s.extensionAt(fedoraUUID)
	s.packageManager("dnf", fedoraUUID)
	s.program("gnome-extensions", `echo "gnome-extensions $*" >>"$LOG"
cat >"$(dirname "$0")/gdbus" <<'EOF'
#!/bin/bash
echo "(true,)"
EOF
chmod +x "$(dirname "$0")/gdbus"`)
	out, calls := s.run()
	wantNot(t, calls, "dnf")
	wantIn(t, calls, "gnome-extensions enable "+fedoraUUID)
	wantNot(t, out, "после следующего входа")
}

// gnome-extensions нет или он отказал: расширение дописывается в настройки, к чужим.
func TestTrayStepFallsBackToSettings(t *testing.T) {
	for _, tt := range []struct{ before, after string }{
		{"@as []", "['" + fedoraUUID + "']"},
		{"[]", "['" + fedoraUUID + "']"},
		{"['a@b.c']", "['a@b.c', '" + fedoraUUID + "']"},
	} {
		s := newTrayStand(t)
		s.packageManager("dnf", fedoraUUID)
		s.program("gnome-extensions", `echo "Расширения не существует" >&2; exit 2`)
		s.program("gsettings", fmt.Sprintf(`if [ "$1" = get ]; then echo "%s"; else echo "gsettings $*" >>"$LOG"; fi`, tt.before))
		out, calls := s.run()
		wantIn(t, calls, "gsettings set org.gnome.shell enabled-extensions "+tt.after)
		wantIn(t, out, "после следующего входа")
	}
}

func TestTrayStepKeepsExtensionAlreadyInSettings(t *testing.T) {
	s := newTrayStand(t)
	s.packageManager("dnf", fedoraUUID)
	s.program("gnome-extensions", `exit 2`)
	s.program("gsettings", fmt.Sprintf(`if [ "$1" = get ]; then echo "['%s']"; else echo "gsettings $*" >>"$LOG"; fi`, fedoraUUID))
	_, calls := s.run()
	wantNot(t, calls, "gsettings set")
}

// Что бы ни случилось, установка идёт дальше: код 0 проверяет run. Причина названа,
// сказано, что защита работает.
func TestTrayStepNeverStopsInstall(t *testing.T) {
	t.Run("пакет не поставился", func(t *testing.T) {
		s := newTrayStand(t)
		s.program("sudo", `shift 2; exec "$@"`)
		s.program("apt-get", `echo "E: нет сети"; exit 100`)
		out, _ := s.run()
		wantIn(t, out, "E: нет сети", "защита работает", extPackage)
	})
	t.Run("нет менеджера пакетов", func(t *testing.T) {
		s := newTrayStand(t)
		out, _ := s.run()
		wantIn(t, out, "менеджер пакетов", "защита работает")
	})
	t.Run("пакет есть, расширения нет", func(t *testing.T) {
		s := newTrayStand(t)
		s.program("sudo", `shift 2; exec "$@"`)
		s.program("apt-get", `exit 0`)
		out, _ := s.run()
		wantIn(t, out, "нет на диске", "защита работает")
	})
	t.Run("не включается", func(t *testing.T) {
		s := newTrayStand(t)
		s.extensionAt(fedoraUUID)
		out, _ := s.run()
		wantIn(t, out, "Не удалось включить", "защита работает")
	})
	t.Run("sudo отказал", func(t *testing.T) {
		s := newTrayStand(t)
		s.program("sudo", `echo "Sorry, try again."; exit 1`)
		s.program("apt-get", `exit 0`)
		out, _ := s.run()
		wantIn(t, out, "Sorry", "защита работает")
	})
}

// Сервер и вход по SSH: ни пакетов, ни значка, ни ошибок.
func TestTrayStepOnServerDoesNothing(t *testing.T) {
	s := newTrayStand(t)
	s.env = map[string]string{"XDG_CURRENT_DESKTOP": ""}
	s.packageManager("apt-get", ubuntuUUID)
	out, calls := s.run()
	if calls != "" {
		t.Fatalf("на сервере вызваны программы:\n%s", calls)
	}
	wantIn(t, out, "Графического сеанса здесь нет", "защита работает")
	wantNot(t, out, "✗")
}

func TestTrayStepOnOtherDesktops(t *testing.T) {
	t.Run("KDE с областью значков", func(t *testing.T) {
		s := newTrayStand(t)
		s.env["XDG_CURRENT_DESKTOP"] = "KDE"
		s.host(true)
		s.packageManager("apt-get", ubuntuUUID)
		out, calls := s.run()
		wantIn(t, out, "рядом с часами")
		wantNot(t, calls, "apt-get")
		wantIn(t, calls, "setsid")
	})
	t.Run("tiling без панели", func(t *testing.T) {
		s := newTrayStand(t)
		s.env = map[string]string{"WAYLAND_DISPLAY": "wayland-1", "XDG_CURRENT_DESKTOP": "sway"}
		s.packageManager("apt-get", ubuntuUUID)
		out, calls := s.run()
		wantIn(t, out, "нет области значков", "защита работает")
		wantNot(t, calls, "apt-get")
	})
}

// Шаг встроен в установку так, что не может её прервать, и счётчик шагов сходится.
func TestInstallScriptRunsTrayStepAsOptional(t *testing.T) {
	data, err := os.ReadFile("../../setup/linux/install.sh")
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !regexp.MustCompile(`tray\.sh"[^\n]*\|\| true`).MatchString(text) {
		t.Error("шаг со значком может прервать установку")
	}
	prepare, err := os.ReadFile("../../setup/linux/prepare.sh")
	if err != nil {
		t.Fatal(err)
	}
	total := regexp.MustCompile(`--install\) TOTAL=(\d+)`).FindStringSubmatch(string(prepare))
	if total == nil {
		t.Fatal("в prepare.sh нет числа шагов установки")
	}
	wantIn(t, text, "[%d/"+total[1]+"]", "section "+total[1]+" ")
	if strings.Contains(text, "section "+fmt.Sprint(atoi(t, total[1])+1)) {
		t.Error("шагов больше, чем объявлено")
	}
}

func atoi(t *testing.T, s string) int {
	t.Helper()
	var n int
	if _, err := fmt.Sscan(s, &n); err != nil {
		t.Fatal(err)
	}
	return n
}
