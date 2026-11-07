// Package enforce — исполнитель правил: закрывает адреса защищённых сервисов на
// всех интерфейсах, кроме проверенных туннелей. Что именно закрыть и что
// открыть, решает ядро (core); как это выразить средствами ОС — здесь.
package enforce

import (
	"net/netip"
	"slices"
)

// Rules — желаемое состояние файрвола. Пустой OpenIfaces значит «закрыто
// везде»: до адресов сервисов не добраться ни одним путём.
type Rules struct {
	OpenIfaces []string     // туннели, через которые защищённый трафик проходит
	V4         []netip.Addr // адреса защищённых сервисов, IPv4
	V6         []netip.Addr // адреса защищённых сервисов, IPv6
	// ClosedProxies — порты системного прокси с непроверенным выходом. Они
	// закрыты для всех программ, кроме root: файрвол не различает программы, а
	// служба (root) проверяет выход через этот же порт.
	ClosedProxies []netip.AddrPort
	// Servers — серверы VPN, адрес которых совпал с адресом защищённого
	// сервиса (VPN через CDN): на физическом интерфейсе Physical они разрешены
	// всегда, иначе клиент VPN не подключится.
	Servers  []netip.Addr
	Physical string
	// Apps, OpenAddrs и OpenProxies — для Windows и Linux. Apps — что защищено:
	// исполняемый файл, папка установки, пакет Store (package:<семейство>) или
	// служба systemd (systemd:<имя>.service). На Windows приложениям сеть открыта
	// только с локальных адресов открытых туннелей (OpenAddrs) и до открытых
	// прокси (OpenProxies); закрытые прокси (ClosedProxies) закрыты только им. На
	// Linux приложениям сеть открыта через интерфейсы OpenIfaces. pf на macOS
	// программ не различает, и там эти поля не нужны.
	Apps        []string
	OpenAddrs   []netip.Addr
	OpenProxies []netip.AddrPort
}

// Enforcer применяет правила к системе.
type Enforcer interface {
	// Apply приводит файрвол к состоянию r. Вызов идемпотентен.
	Apply(r Rules) error
	// Clear снимает всё, что поставил исполнитель: после него сеть как до установки.
	Clear() error
	// Verify сверяет файрвол с правилами r, применёнными раньше, ничего не
	// меняя: nil — всё на месте, иначе — что сброшено.
	Verify(r Rules) error
}

// Equal — правила совпадают (порядок адресов и интерфейсов не важен).
func (r Rules) Equal(o Rules) bool {
	return sameSet(r.OpenIfaces, o.OpenIfaces) && sameAddrs(r.V4, o.V4) && sameAddrs(r.V6, o.V6) &&
		sameSorted(r.ClosedProxies, o.ClosedProxies, netip.AddrPort.Compare) &&
		sameAddrs(r.Servers, o.Servers) && r.Physical == o.Physical &&
		sameSet(r.Apps, o.Apps) && sameAddrs(r.OpenAddrs, o.OpenAddrs) &&
		sameSorted(r.OpenProxies, o.OpenProxies, netip.AddrPort.Compare)
}

func sameSet(a, b []string) bool {
	a, b = slices.Clone(a), slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(a, b)
}

func sameAddrs(a, b []netip.Addr) bool { return sameSorted(a, b, netip.Addr.Compare) }

func sameSorted[T comparable](a, b []T, cmp func(T, T) int) bool {
	a, b = slices.Clone(a), slices.Clone(b)
	slices.SortFunc(a, cmp)
	slices.SortFunc(b, cmp)
	return slices.Equal(a, b)
}
