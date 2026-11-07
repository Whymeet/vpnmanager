package apps

import "testing"

func TestInstallTarget(t *testing.T) {
	f := Folders{
		System:   `C:\Windows`,
		Programs: []string{`C:\Program Files`, `C:\Program Files (x86)`, `C:\ProgramData`},
		Profiles: `C:\Users`,
	}
	for _, tc := range []struct{ exe, want string }{
		// Папка установки целиком: помощники, обновлятор, новые версии.
		{`C:\Users\Иван\AppData\Local\Programs\Notion\Notion.exe`, `C:\Users\Иван\AppData\Local\Programs\Notion`},
		{`C:\Program Files\Google\Chrome\Application\chrome.exe`, `C:\Program Files\Google\Chrome\Application`},
		{`C:\Users\Иван\AppData\Local\Discord\Update.exe`, `C:\Users\Иван\AppData\Local\Discord`},
		{`C:\Users\Иван\AppData\Local\Discord\app-1.0.9035\Discord.exe`, `C:\Users\Иван\AppData\Local\Discord`},
		{`D:\Apps\Figma\Figma.exe`, `D:\Apps\Figma`},
		// Общие папки — только сам файл.
		{`C:\Windows\System32\curl.exe`, `C:\Windows\System32\curl.exe`},
		{`C:\windows\notepad.exe`, `C:\windows\notepad.exe`},
		{`C:\Program Files\tool.exe`, `C:\Program Files\tool.exe`},
		{`C:\Users\Иван\Downloads\portable.exe`, `C:\Users\Иван\Downloads\portable.exe`},
		{`C:\Users\Иван\Desktop\app.exe`, `C:\Users\Иван\Desktop\app.exe`},
		{`C:\Users\Иван\AppData\Local\Programs\setup.exe`, `C:\Users\Иван\AppData\Local\Programs\setup.exe`},
		{`C:\Users\Иван\app.exe`, `C:\Users\Иван\app.exe`},
		{`C:\Users\app.exe`, `C:\Users\app.exe`},
		{`C:\app.exe`, `C:\app.exe`},
	} {
		if got := InstallTarget(tc.exe, f); got != tc.want {
			t.Errorf("%s → %s, ждали %s", tc.exe, got, tc.want)
		}
	}
}

func TestParseStartAppsKeepsStorePackages(t *testing.T) {
	out := []byte("\ufeff" + `[{"Name":"Spotify","AppID":"SpotifyAB.SpotifyMusic_zpdnekdrzrea0!Spotify"},` +
		`{"Name":"Блокнот","AppID":"Microsoft.WindowsNotepad_8wekyb3d8bbwe!App"},` +
		`{"Name":"Notion","AppID":"C:\\Users\\u\\AppData\\Local\\Programs\\Notion\\Notion.exe"},` +
		`{"Name":"Странный","AppID":"not a family!App"}]`)
	got := parseStartApps(out)
	if len(got) != 2 || got[0].Name != "Spotify" || got[0].Path != "package:SpotifyAB.SpotifyMusic_zpdnekdrzrea0" ||
		got[0].ID != "package:spotifyab.spotifymusic_zpdnekdrzrea0" || !got[0].Instant || got[1].Name != "Блокнот" {
		t.Fatalf("%+v", got)
	}
	one := parseStartApps([]byte(`{"Name":"Spotify","AppID":"SpotifyAB.SpotifyMusic_zpdnekdrzrea0!Spotify"}`))
	if len(one) != 1 || one[0].Name != "Spotify" {
		t.Fatalf("одно приложение: %+v", one)
	}
	if parseStartApps([]byte("")) != nil {
		t.Fatal("пустой вывод — не приложения")
	}
}
