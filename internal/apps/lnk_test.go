package apps

import (
	"bytes"
	"encoding/binary"
	"testing"
	"unicode/utf16"
)

// link собирает ярлык: LinkInfo с путём (ANSI и, если unicodePath не пуст,
// юникодным), аргументы и блок с путём через переменные окружения.
func link(ansiPath, unicodePath, args, envPath string) []byte {
	var b bytes.Buffer
	w32 := func(v uint32) { binary.Write(&b, binary.LittleEndian, v) }
	w16 := func(v uint16) { binary.Write(&b, binary.LittleEndian, v) }
	u16 := func(s string) []byte {
		var out bytes.Buffer
		for _, c := range utf16.Encode([]rune(s)) {
			binary.Write(&out, binary.LittleEndian, c)
		}
		return out.Bytes()
	}
	flags := uint32(lnkHasLinkInfo | lnkIsUnicode | lnkHasIDList)
	if args != "" {
		flags |= lnkHasArguments
	}
	// Заголовок.
	w32(lnkHeaderSize)
	b.Write(lnkCLSID)
	w32(flags)
	b.Write(make([]byte, lnkHeaderSize-b.Len()))
	// Список идентификаторов — его разбор не нужен, только пропустить.
	w16(4)
	b.Write([]byte{2, 0, 0, 0})
	// LinkInfo: заголовок 0x24, VolumeID из 16 байт, затем строки.
	header := uint32(0x1c)
	if unicodePath != "" {
		header = 0x24
	}
	volume := header
	ansi := volume + 16
	ansiSuffix := ansi + uint32(len(ansiPath)) + 1
	uni := ansiSuffix + 1
	uniSuffix := uni + uint32(len(u16(unicodePath))) + 2
	size := uniSuffix + 2
	if unicodePath == "" {
		size = uni
	}
	w32(size)
	w32(header)
	w32(lnkLocalPath)
	w32(volume)
	w32(ansi)
	w32(0)
	w32(ansiSuffix)
	if unicodePath != "" {
		w32(uni)
		w32(uniSuffix)
	}
	b.Write(make([]byte, 16))
	b.WriteString(ansiPath + "\x00")
	b.WriteByte(0)
	if unicodePath != "" {
		b.Write(u16(unicodePath))
		w16(0)
		w16(0)
	}
	if args != "" {
		w16(uint16(len(utf16.Encode([]rune(args)))))
		b.Write(u16(args))
	}
	if envPath != "" {
		w32(lnkEnvBlockSize)
		w32(lnkEnvBlock)
		b.Write(make([]byte, 260))
		p := u16(envPath)
		b.Write(p)
		b.Write(make([]byte, 520-len(p)))
	}
	w32(0) // последний блок
	return b.Bytes()
}

func TestParseLinkPrefersUnicodePath(t *testing.T) {
	l, err := ParseLink(link(`C:\Users\????\AppData\Local\Discord\Update.exe`, `C:\Users\Иван\AppData\Local\Discord\Update.exe`,
		"--processStart Discord.exe", `%LOCALAPPDATA%\Discord\Update.exe`))
	if err != nil {
		t.Fatal(err)
	}
	if l.Target != `C:\Users\Иван\AppData\Local\Discord\Update.exe` {
		t.Errorf("цель %q", l.Target)
	}
	if l.Arguments != "--processStart Discord.exe" {
		t.Errorf("аргументы %q", l.Arguments)
	}
	if l.EnvTarget != `%LOCALAPPDATA%\Discord\Update.exe` {
		t.Errorf("цель через переменные %q", l.EnvTarget)
	}
}

func TestParseLinkTakesASCIIPathOnly(t *testing.T) {
	l, err := ParseLink(link(`C:\Program Files\Notion\Notion.exe`, "", "", ""))
	if err != nil || l.Target != `C:\Program Files\Notion\Notion.exe` {
		t.Fatalf("латинский ANSI-путь: %q, %v", l.Target, err)
	}
	l, err = ParseLink(link("C:\\Users\\\xc8\xe2\xe0\xed\\app.exe", "", "", ""))
	if err != nil || l.Target != "" {
		t.Fatalf("ANSI-путь в неизвестной кодировке принят: %q, %v", l.Target, err)
	}
}

func TestParseLinkRefusesBrokenFiles(t *testing.T) {
	good := link(`C:\Program Files\Notion\Notion.exe`, `C:\Program Files\Notion\Notion.exe`, "--x", `%APPDATA%\x.exe`)
	for n := range good {
		ParseLink(good[:n]) // обрезанный ярлык — ошибка или неполный ответ, но не паника
	}
	if _, err := ParseLink([]byte("not a link at all, just some text that is long enough to pass the length check ....")); err == nil {
		t.Fatal("текст принят за ярлык")
	}
}
