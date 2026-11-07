package tray

import (
	"errors"
	"testing"
)

// Второй экземпляр выходит и первого не трогает: при обновлении его запускает
// schtasks /Run, а мьютекс держит первый.
func TestSecondInstanceIsRefused(t *testing.T) {
	first, err := System()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := System(); !errors.Is(err, ErrBusy) {
		t.Fatalf("второй экземпляр: %v", err)
	}
	if first == nil {
		t.Fatal("первый экземпляр без показа")
	}
}
