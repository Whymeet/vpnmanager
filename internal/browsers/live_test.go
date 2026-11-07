//go:build live

// Живая проверка: tools/go test -tags live -v ./internal/browsers

package browsers

import (
	"os"
	"testing"
)

// Браузеры этого мака и их «безопасный DNS».
func TestLiveBrowsersHere(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range Check(home) {
		t.Logf("%s: свой DoH %v %s", b.Browser, b.On, b.Provider)
	}
}
