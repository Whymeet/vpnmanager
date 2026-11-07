// Package browsers — «безопасный DNS» в браузерах. Браузер с собственным
// DNS-over-HTTPS узнаёт адреса сервисов мимо резолвера службы: новых адресов
// нет в таблицах, и сайт сервиса открывается без VPN. Проверка только читает
// настройки браузеров из профиля пользователя и подсказывает, что выключить.
package browsers

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
)

// SecureDNS — что известно о «безопасном DNS» браузера.
type SecureDNS struct {
	Browser  string
	On       bool   // браузер ходит к своему DNS-over-HTTPS
	Provider string // к какому, если сказано
	Hint     string // как выключить
}

// chromium — браузеры на Chromium: режим лежит в Local State, ключ
// dns_over_https. «secure» — свой поставщик; «automatic» (и по умолчанию,
// когда ключа нет) — «с текущим поставщиком», то есть системный DNS. mac — папка
// в ~/Library/Application Support, win — в %LOCALAPPDATA% (там Local State
// лежит в «User Data»), linux — в ~/.config.
var chromium = []struct{ name, mac, win, linux, hint string }{
	{"Chrome", "Google/Chrome", "Google/Chrome/User Data", "google-chrome", "Настройки → Конфиденциальность и безопасность → Безопасность → «Использовать безопасный DNS» — выключи или выбери «С текущим поставщиком услуг» (chrome://settings/security)"},
	{"Edge", "Microsoft Edge", "Microsoft/Edge/User Data", "microsoft-edge", "Настройки → Конфиденциальность, поиск и службы → Безопасность → «Использовать безопасный DNS» — выключи или выбери текущего поставщика (edge://settings/privacy)"},
	{"Brave", "BraveSoftware/Brave-Browser", "BraveSoftware/Brave-Browser/User Data", "BraveSoftware/Brave-Browser", "Настройки → Конфиденциальность и безопасность → Безопасность → «Использовать безопасный DNS» — выключи или выбери текущего поставщика (brave://settings/security)"},
}

const firefoxHint = "Настройки → Приватность и защита → DNS через HTTPS → «Выкл.» (about:preferences#privacy)"

// Check — «безопасный DNS» установленных браузеров пользователя с домашним
// каталогом home. Браузера нет — его нет и в ответе.
func Check(home string) []SecureDNS { return check(home, runtime.GOOS) }

// check — Check для раскладки профиля системы goos: так обе раскладки
// проверяются тестами на любой системе.
func check(home, goos string) []SecureDNS {
	settings := filepath.Join(home, "Library", "Application Support")
	firefox := filepath.Join(settings, "Firefox")
	switch goos {
	case "windows":
		settings = filepath.Join(home, "AppData", "Local")
		firefox = filepath.Join(home, "AppData", "Roaming", "Mozilla", "Firefox")
	case "linux":
		settings = filepath.Join(home, ".config")
		firefox = filepath.Join(home, ".mozilla", "firefox")
	}
	var out []SecureDNS
	for _, b := range chromium {
		dir := b.mac
		switch goos {
		case "windows":
			dir = b.win
		case "linux":
			dir = b.linux
		}
		data, err := os.ReadFile(filepath.Join(settings, filepath.FromSlash(dir), "Local State"))
		if err != nil {
			continue
		}
		s := SecureDNS{Browser: b.name, Hint: b.hint}
		var st struct {
			DoH struct {
				Mode      string `json:"mode"`
				Templates string `json:"templates"`
			} `json:"dns_over_https"`
		}
		if json.Unmarshal(data, &st) == nil && st.DoH.Mode == "secure" {
			s.On, s.Provider = true, st.DoH.Templates
		}
		out = append(out, s)
	}
	pattern := filepath.Join(firefox, "Profiles", "*", "prefs.js")
	if goos == "linux" { // на Linux папки Profiles нет: профили лежат прямо в ~/.mozilla/firefox
		pattern = filepath.Join(firefox, "*", "prefs.js")
	}
	profiles, _ := filepath.Glob(pattern)
	if len(profiles) > 0 {
		s := SecureDNS{Browser: "Firefox", Hint: firefoxHint}
		for _, p := range profiles {
			if on, uri := firefoxDoH(p); on {
				s.On, s.Provider = true, uri
			}
		}
		out = append(out, s)
	}
	return out
}

var prefRe = regexp.MustCompile(`^user_pref\("([^"]+)",\s*(.*)\);`)

// firefoxDoH читает prefs.js профиля Firefox. network.trr.mode 2 и 3 — свой
// DNS-over-HTTPS (первым или только он), 5 — выключен явно. Без своего режима
// действует тот, что включило постепенное развёртывание (doh-rollout.mode).
func firefoxDoH(path string) (bool, string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, ""
	}
	prefs := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		if m := prefRe.FindStringSubmatch(sc.Text()); m != nil {
			prefs[m[1]] = m[2]
		}
	}
	mode, set := prefs["network.trr.mode"]
	if !set || mode == "0" {
		mode = prefs["doh-rollout.mode"]
	}
	if mode != "2" && mode != "3" {
		return false, ""
	}
	uri, _ := strconv.Unquote(prefs["network.trr.uri"])
	return true, uri
}
