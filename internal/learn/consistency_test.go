package learn_test

import (
	"testing"

	"appguard/internal/exitcheck"
	"appguard/internal/learn"
	"appguard/internal/resolver"
)

// Всё, к чему служба ходит сама по адресу, обязано быть в служебном списке:
// иначе приложение, пользующееся тем же адресом (DoH в браузере), загнало бы
// его в таблицу, и проверка выхода или резолвер упёрлись бы в запрет.
func TestServiceAddressesAreNeverLearned(t *testing.T) {
	fixed := append(exitcheck.FixedAddrs(), resolver.FixedAddrs()...)
	if len(fixed) < 4 {
		t.Fatalf("не нашлось служебных адресов: %v", fixed)
	}
	for _, a := range fixed {
		if !learn.Reserved(a) {
			t.Errorf("%s нужен службе, но его можно выучить — добавь в reserved", a)
		}
		if learn.Acceptable(a, 443) {
			t.Errorf("%s принят к обучению", a)
		}
	}
}

// То же для имён: к ним проверка выхода и зонд «Россия напрямую» ходят сами.
func TestServiceNamesAreNeverLearned(t *testing.T) {
	names := exitcheck.FixedNames()
	if len(names) < 4 {
		t.Fatalf("не нашлось служебных имён: %v", names)
	}
	for _, n := range names {
		if learn.Domain(n) {
			t.Errorf("%s нужен службе, но его можно выучить — добавь в reservedDomains", n)
		}
	}
	for _, n := range []string{"api.notion.com", "o1.ingest.sentry.io"} {
		if !learn.Domain(n) {
			t.Errorf("%s не принят к обучению", n)
		}
	}
	for _, n := range []string{"printer.local", "4.3.2.1.in-addr.arpa", "203.0.113.5", "localhost"} {
		if learn.Domain(n) {
			t.Errorf("%s принят к обучению", n)
		}
	}
}
