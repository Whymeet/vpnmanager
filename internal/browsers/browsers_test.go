package browsers

import (
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, path, data string) {
	t.Helper()
	os.MkdirAll(filepath.Dir(path), 0o755)
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
}

func find(list []SecureDNS, browser string) (SecureDNS, bool) {
	for _, s := range list {
		if s.Browser == browser {
			return s, true
		}
	}
	return SecureDNS{}, false
}

func TestChromiumSecureModeIsOwnDNS(t *testing.T) {
	home := t.TempDir()
	support := filepath.Join(home, "Library", "Application Support")
	write(t, filepath.Join(support, "Google/Chrome/Local State"),
		`{"dns_over_https":{"mode":"secure","templates":"https://chrome.cloudflare-dns.com/dns-query"}}`)
	write(t, filepath.Join(support, "Microsoft Edge/Local State"), `{"dns_over_https":{"mode":"automatic","templates":""}}`)
	write(t, filepath.Join(support, "BraveSoftware/Brave-Browser/Local State"), `{"browser":{}}`)

	got := check(home, "darwin")
	if c, _ := find(got, "Chrome"); !c.On || c.Provider != "https://chrome.cloudflare-dns.com/dns-query" || c.Hint == "" {
		t.Fatalf("Chrome: %+v", c)
	}
	// «С текущим поставщиком» и умолчание — системный DNS: не свой.
	for _, b := range []string{"Edge", "Brave"} {
		if s, ok := find(got, b); !ok || s.On {
			t.Fatalf("%s: %+v %v", b, s, ok)
		}
	}
}

func TestFirefoxModes(t *testing.T) {
	for name, tc := range map[string]struct {
		prefs string
		on    bool
	}{
		"только свой DoH":        {`user_pref("network.trr.mode", 3);` + "\n" + `user_pref("network.trr.uri", "https://mozilla.cloudflare-dns.com/dns-query");`, true},
		"сначала свой DoH":       {`user_pref("network.trr.mode", 2);`, true},
		"выключен явно":          {`user_pref("network.trr.mode", 5);` + "\n" + `user_pref("doh-rollout.mode", 2);`, false},
		"включило развёртывание": {`user_pref("doh-rollout.mode", 2);`, true},
		"по умолчанию":           {`user_pref("browser.startup.page", 3);`, false},
	} {
		t.Run(name, func(t *testing.T) {
			home := t.TempDir()
			write(t, filepath.Join(home, "Library/Application Support/Firefox/Profiles/abc.default-release/prefs.js"), tc.prefs+"\n")
			s, ok := find(check(home, "darwin"), "Firefox")
			if !ok || s.On != tc.on {
				t.Fatalf("%+v %v", s, ok)
			}
		})
	}
}

func TestNoBrowsersNoFindings(t *testing.T) {
	if got := Check(t.TempDir()); len(got) != 0 {
		t.Fatalf("%+v", got)
	}
}

// На Windows настройки лежат в AppData: Chromium — в Local\…\User Data,
// Firefox — в Roaming\Mozilla.
func TestWindowsProfileLayout(t *testing.T) {
	home := t.TempDir()
	local := filepath.Join(home, "AppData", "Local")
	write(t, filepath.Join(local, "Google/Chrome/User Data/Local State"), `{"dns_over_https":{"mode":"secure","templates":"https://dns.google/dns-query"}}`)
	write(t, filepath.Join(local, "Microsoft/Edge/User Data/Local State"), `{"dns_over_https":{"mode":"automatic"}}`)
	write(t, filepath.Join(home, "AppData", "Roaming", "Mozilla", "Firefox", "Profiles", "abc.default-release", "prefs.js"), `user_pref("network.trr.mode", 3);`)

	got := check(home, "windows")
	if c, _ := find(got, "Chrome"); !c.On || c.Provider != "https://dns.google/dns-query" {
		t.Fatalf("Chrome: %+v", c)
	}
	if e, ok := find(got, "Edge"); !ok || e.On {
		t.Fatalf("Edge: %+v", e)
	}
	if f, ok := find(got, "Firefox"); !ok || !f.On {
		t.Fatalf("Firefox: %+v", f)
	}
	if _, ok := find(got, "Brave"); ok {
		t.Fatal("Brave не установлен, а найден")
	}
	if len(check(home, "darwin")) != 0 {
		t.Fatal("раскладка macOS нашла браузеры Windows")
	}
}

// На Linux настройки Chromium лежат в ~/.config, а профили Firefox — прямо в
// ~/.mozilla/firefox, без папки Profiles.
func TestLinuxLayout(t *testing.T) {
	home := t.TempDir()
	write := func(rel, text string) {
		t.Helper()
		p := filepath.Join(home, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(".config/google-chrome/Local State", `{"dns_over_https":{"mode":"secure","templates":"https://dns.example/q"}}`)
	write(".mozilla/firefox/abc.default/prefs.js", `user_pref("network.trr.mode", 3);`+"\n")
	got := check(home, "linux")
	if len(got) != 2 || got[0].Browser != "Chrome" || !got[0].On || got[1].Browser != "Firefox" || !got[1].On {
		t.Errorf("%+v", got)
	}
}
