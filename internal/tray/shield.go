package tray

import (
	"bytes"
	_ "embed"
	"image"
	"image/color"
	"image/png"
	"math"
)

// shieldPNG — значок для Windows и Linux: цветной щит, который читается и на
// тёмной, и на светлой панели. На macOS значок системный, шаблонный.
//
//go:embed shield.png
var shieldPNG []byte

// shield — значок со стороной size. open — щит из shield.png: защищённые
// приложения в сети. Иначе — тот же щит серым, перечёркнутый красной чертой:
// отличается и цветом, и формой, поэтому виден и тому, кто не различает красный
// и зелёный.
//
// Цвет не умножен на альфу: так его ждут и CreateIconIndirect, и IconPixmap.
// Прозрачные пиксели в среднем не участвуют: иначе край щита потемнел бы.
func shield(size int, open bool) *image.NRGBA {
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
					// Точка выборки — доля стороны: черта считается по ней, а не по
					// пикселям исходника, и её край сглаживается так же, как край щита.
					fx := (float64(x*samples+sx) + 0.5) / float64(size*samples)
					fy := (float64(y*samples+sy) + 0.5) / float64(size*samples)
					c := color.NRGBAModel.Convert(src.At(b.Min.X+int(fx*float64(b.Dx())), b.Min.Y+int(fy*float64(b.Dy())))).(color.NRGBA)
					if !open {
						c = crossed(c, fx, fy)
					}
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

// slash — красная черта перечёркнутого щита.
var slash = color.NRGBA{0xe0, 0x2f, 0x24, 0xff}

// crossed — точка (x, y) перечёркнутого щита (доли стороны): щит серым, поверх —
// черта из левого верхнего угла в правый нижний, вдоль неё прозрачный зазор,
// чтобы черта не сливалась со щитом.
func crossed(c color.NRGBA, x, y float64) color.NRGBA {
	const (
		end  = 0.12 // концы черты отстоят от углов значка
		half = 0.07 // половина толщины черты
		gap  = 0.06 // зазор между чертой и щитом
	)
	// Расстояние до отрезка (end, end)—(1-end, 1-end): концы черты круглые.
	t := min(max((x+y)/2, end), 1-end)
	d := math.Hypot(x-t, y-t)
	switch {
	case d < half:
		return slash
	case d < half+gap:
		return color.NRGBA{}
	}
	l := uint8((299*uint32(c.R) + 587*uint32(c.G) + 114*uint32(c.B)) / 1000)
	return color.NRGBA{l, l, l, c.A}
}
