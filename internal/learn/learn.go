// Package learn — отбор адресов при обучении: какие из удалённых адресов
// процессов приложения станут адресами защищённого сервиса. Чистая логика.
package learn

import (
	"net/netip"
	"slices"
	"strings"
)

// Acceptable — можно ли запомнить удалённый адрес addr:port как адрес сервиса.
// Не запоминаются:
//   - свои и локальные адреса — петля, link-local, частные сети: через VPN в
//     них не ходят, а закрывать их незачем и опасно (локальный прокси клиента
//     VPN, принтер, соседний компьютер);
//   - служебные диапазоны, в которых нет настоящих серверов, — общий NAT
//     провайдера (100.64/10), фиктивные адреса клиентов VPN (198.18/15), группы,
//     зарезервированные блоки;
//   - DNS: порты 53 и 853. Имена разрешает система, а не сервис;
//   - адреса, без которых не работает сама служба (Reserved).
func Acceptable(addr netip.Addr, port uint16) bool {
	a := addr.Unmap()
	switch {
	case !a.IsValid(), a.IsUnspecified(), a.IsLoopback(), a.IsPrivate(),
		a.IsLinkLocalUnicast(), a.IsLinkLocalMulticast(), a.IsInterfaceLocalMulticast(), a.IsMulticast():
		return false
	}
	if port == 53 || port == 853 {
		return false
	}
	for _, p := range notServers {
		if p.Contains(a) {
			return false
		}
	}
	return !Reserved(a)
}

// notServers — диапазоны без настоящих серверов сервисов.
var notServers = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),     // «этот» хост
	netip.MustParsePrefix("100.64.0.0/10"), // общий NAT провайдера; здесь же Tailscale
	netip.MustParsePrefix("192.0.0.0/24"),  // служебный IETF
	netip.MustParsePrefix("198.18.0.0/15"), // тесты; клиенты VPN выдают отсюда фиктивные адреса имён
	netip.MustParsePrefix("240.0.0.0/4"),   // зарезервировано, в том числе 255.255.255.255
	netip.MustParsePrefix("64:ff9b::/96"),  // NAT64: настоящий адрес прячется внутри
	netip.MustParsePrefix("2001:db8::/32"), // документация
	netip.MustParsePrefix("2002::/16"),     // 6to4
	netip.MustParsePrefix("fec0::/10"),     // устаревшие частные сети IPv6
}

// reserved — адреса, к которым ходит сама служба. Закрыть их на физическом
// интерфейсе значило бы сломать проверку выхода или резолвер: проверка идёт
// через туннель, который ещё не проверен, и упёрлась бы в запрет. Список надо
// держать в согласии с exitcheck и resolver — это проверяет тест.
var reserved = []netip.Addr{
	netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("1.0.0.1"), // Cloudflare: trace и DoH
	netip.MustParseAddr("2606:4700:4700::1111"), netip.MustParseAddr("2606:4700:4700::1001"),
	netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("8.8.4.4"), // Google: DoH
	netip.MustParseAddr("2001:4860:4860::8888"), netip.MustParseAddr("2001:4860:4860::8844"),
	netip.MustParseAddr("77.88.8.8"), netip.MustParseAddr("77.88.8.1"), // Яндекс: российский DNS
}

// Reserved — адрес нужен самой службе.
func Reserved(addr netip.Addr) bool { return slices.Contains(reserved, addr.Unmap()) }

// reservedDomains — имена, к которым ходит сама служба (запасные источники
// проверки выхода, зонд «Россия напрямую»), и DoH, — вместе с поддоменами.
// Защищённое имя закрылось бы мимо туннеля: проверка через ещё не проверенный
// туннель и зонд через физический интерфейс упёрлись бы в запрет. Список надо
// держать в согласии с exitcheck — это проверяет тест.
var reservedDomains = []string{
	"ipinfo.io", "country.is", "ipwho.is", // запасные источники проверки выхода
	"yandex.ru", "yandex.net", // зонд «Россия напрямую»
	"cloudflare-dns.com", "one.one.one.one", "dns.google", // DoH
}

// notDomains — окончания имён, которые не ведут в интернет: локальная сеть,
// обратные зоны.
var notDomains = []string{"local", "arpa", "internal", "lan", "home", "localhost"}

// Domain — можно ли запомнить имя name (строчными, без точки в конце) как
// домен сервиса: не служебное и не локальное.
func Domain(name string) bool {
	if _, err := netip.ParseAddr(name); err == nil || !strings.Contains(name, ".") {
		return false
	}
	under := func(list []string) bool {
		return slices.ContainsFunc(list, func(d string) bool { return name == d || strings.HasSuffix(name, "."+d) })
	}
	return !under(reservedDomains) && !under(notDomains)
}
