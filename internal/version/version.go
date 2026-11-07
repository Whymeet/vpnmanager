// Package version — версия инструмента. Она одна на клиент и службу: оба режима
// собираются в один исполняемый файл.
package version

import (
	_ "embed"
	"strconv"
	"strings"
)

//go:embed VERSION
var raw string

// Version — содержимое файла VERSION рядом с пакетом. Статус показывает версию
// службы, а напоминание о новой версии сверяет её с этим файлом в клоне.
var Version = strings.TrimSpace(raw)

// Newer — версия a новее b: числа через точку сравниваются по порядку. Не
// число — не новее: напоминать о непонятной версии незачем.
func Newer(a, b string) bool {
	pa, pb := strings.Split(strings.TrimSpace(a), "."), strings.Split(strings.TrimSpace(b), ".")
	for i := range max(len(pa), len(pb)) {
		x, y := 0, 0
		var err error
		if i < len(pa) {
			if x, err = strconv.Atoi(pa[i]); err != nil {
				return false
			}
		}
		if i < len(pb) {
			if y, err = strconv.Atoi(pb[i]); err != nil {
				return false
			}
		}
		if x != y {
			return x > y
		}
	}
	return false
}
