package catalog

import (
	"bytes"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"unicode"

	"vpnlock/internal/resolver"
)

// ParseList — домены и адреса из файла для vpnlock import. Файл — выгрузка
// (каталог JSON: домены и адреса всех его приложений) или простой список: по
// домену, адресу или ссылке, через пробел, запятую или с новой строки; «#» —
// комментарий до конца строки. Из ссылки берётся имя (https://claude.ai/new →
// claude.ai), «*.» в начале имени отбрасывается: домен и так защищается вместе
// с поддоменами. Диапазоны адресов не поддерживаются.
func ParseList(data []byte) (domains, addrs, warnings []string, err error) {
	if t := bytes.TrimSpace(data); len(t) > 0 && t[0] == '{' {
		c, w, err := Parse(data)
		if err != nil {
			return nil, nil, nil, err
		}
		for _, a := range c.Apps {
			domains = append(domains, a.Domains...)
			addrs = append(addrs, a.Addrs...)
		}
		return unique(domains), unique(addrs), w, nil
	}
	for _, line := range strings.Split(string(data), "\n") {
		line, _, _ = strings.Cut(line, "#")
		for _, f := range strings.FieldsFunc(line, func(r rune) bool { return unicode.IsSpace(r) || r == ',' || r == ';' }) {
			if _, err := netip.ParsePrefix(f); err == nil {
				warnings = append(warnings, fmt.Sprintf("%s — диапазоны не поддерживаются, нужен адрес", f))
				continue
			}
			if _, host, ok := strings.Cut(f, "://"); ok {
				f = host
			}
			f, _, _ = strings.Cut(f, "/")
			if a, err := netip.ParseAddr(strings.Trim(f, "[]")); err == nil {
				addrs = append(addrs, a.Unmap().String())
				continue
			}
			name := strings.TrimPrefix(resolver.Normalize(f), "*.")
			if !resolver.ValidDomain(name) {
				warnings = append(warnings, fmt.Sprintf("%q — не домен и не адрес", f))
				continue
			}
			domains = append(domains, name)
		}
	}
	return unique(domains), unique(addrs), warnings, nil
}

func unique(list []string) []string {
	slices.Sort(list)
	return slices.Compact(list)
}
