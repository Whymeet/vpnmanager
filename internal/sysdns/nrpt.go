package sysdns

import (
	"slices"
	"strings"
)

// Правила NRPT (Windows) без Windows: как домены раскладываются по правилам и
// какие уже заняты чужими. Тесты идут на любой системе.

// nrptPerRule — сколько доменов умещает одно правило NRPT: больше 50 оно, по
// опыту Tailscale, не держит.
const nrptPerRule = 50

// nrptChunks раскладывает домены по правилам: по nrptPerRule, с ведущей точкой
// — так правило действует на домен и все его поддомены. Порядок постоянный:
// одни и те же домены дают одни и те же правила.
func nrptChunks(domains []string) [][]string {
	names := make([]string, 0, len(domains))
	for _, d := range domains {
		names = append(names, "."+strings.TrimPrefix(strings.ToLower(d), "."))
	}
	slices.Sort(names)
	names = slices.Compact(names)
	var out [][]string
	for len(names) > 0 {
		n := min(nrptPerRule, len(names))
		out = append(out, names[:n])
		names = names[n:]
	}
	return out
}

// coveredBy — у домена уже есть чужое правило NRPT: на сам домен или на
// домен выше.
func coveredBy(foreign []string, domain string) bool {
	domain = strings.TrimPrefix(strings.ToLower(domain), ".")
	for _, f := range foreign {
		f = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(f)), ".")
		if f != "" && (domain == f || strings.HasSuffix(domain, "."+f)) {
			return true
		}
	}
	return false
}
