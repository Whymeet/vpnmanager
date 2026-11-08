package enforce

import (
	"errors"
	"testing"
)

// На ARM64 функции fwpuclnt возвращают DWORD с расширенным знаком: «уже есть»
// приходит как 0xffffffff80320009. Без отбрасывания старшей половины служба
// через 30 с после старта закрывала сессии WFP и не могла их восстановить.
func TestResultIgnoresUpperHalfOfRegister(t *testing.T) {
	var signExtended uint64 = 0xffffffff80320009
	if err := result(uintptr(signExtended)); !errors.Is(err, fwpAlreadyExists) {
		t.Fatalf("result(%#x) = %v, нужен fwpAlreadyExists", signExtended, err)
	}
	var upperOnly uint64 = 0xffffffff00000000
	if err := result(uintptr(upperOnly)); err != nil {
		t.Fatalf("result(%#x) = %v, нужен успех", upperOnly, err)
	}
	if err := result(0x80320009); !errors.Is(err, fwpAlreadyExists) {
		t.Fatalf("result(0x80320009) = %v", err)
	}
}
