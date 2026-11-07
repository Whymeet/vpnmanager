package apps

import (
	"encoding/json"
	"regexp"
	"strings"
)

// Приложения Store на Windows. Разбор — без Windows, тесты идут на любой системе.

// familyName — семейство пакета Store: имя и издатель (13 знаков base32).
var familyName = regexp.MustCompile(`^[A-Za-z0-9.\-]{1,50}_[a-z0-9]{13}$`)

// startApp — строка Get-StartApps.
type startApp struct {
	Name  string
	AppID string
}

// parseStartApps разбирает ConvertTo-Json: одно приложение — объект, несколько — массив.
func parseStartApps(out []byte) []App {
	out = []byte(strings.TrimPrefix(strings.TrimSpace(string(out)), "\ufeff"))
	var list []startApp
	if json.Unmarshal(out, &list) != nil {
		var one startApp
		if json.Unmarshal(out, &one) != nil {
			return nil
		}
		list = []startApp{one}
	}
	var apps []App
	for _, s := range list {
		fam, _, ok := strings.Cut(s.AppID, "!")
		if !ok || !familyName.MatchString(fam) || s.Name == "" {
			continue
		}
		apps = append(apps, App{ID: PackagePrefix + strings.ToLower(fam), Name: s.Name, Path: PackagePrefix + fam, Instant: true})
	}
	return apps
}
