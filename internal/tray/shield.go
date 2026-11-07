package tray

import (
	"bytes"
	_ "embed"
	"image"
	"image/color"
	"image/png"
)

// shieldPNG — значок для Windows и Linux: цветной щит, который читается и на
// тёмной, и на светлой панели. На macOS значок системный, шаблонный.
//
//go:embed shield.png
var shieldPNG []byte

// shield — значок со стороной size. Цвет не умножен на альфу: так его ждут и
// CreateIconIndirect, и IconPixmap. Прозрачные пиксели в среднем не участвуют:
// иначе край щита потемнел бы.
func shield(size int) *image.NRGBA {
	src, err := png.Decode(bytes.NewReader(shieldPNG))
	if err != nil {
		panic(err) // файл вшит в программу, его проверяет тест
	}
	const samples = 4
	b := src.Bounds()
	out := image.NewNRGBA(image.Rect(0, 0, size, size))
	for y := range size {
		for x := range size {
			var a, r, g, bl uint32
			for sy := range samples {
				for sx := range samples {
					px := b.Min.X + (x*samples+sx)*b.Dx()/(size*samples)
					py := b.Min.Y + (y*samples+sy)*b.Dy()/(size*samples)
					c := color.NRGBAModel.Convert(src.At(px, py)).(color.NRGBA)
					a += uint32(c.A)
					r += uint32(c.R) * uint32(c.A)
					g += uint32(c.G) * uint32(c.A)
					bl += uint32(c.B) * uint32(c.A)
				}
			}
			if a > 0 {
				out.SetNRGBA(x, y, color.NRGBA{uint8(r / a), uint8(g / a), uint8(bl / a), uint8(a / (samples * samples))})
			}
		}
	}
	return out
}
