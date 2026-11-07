package apps

import (
	"bytes"
	"encoding/binary"
	"errors"
	"unicode/utf16"
)

// Ярлык Windows (.lnk, формат MS-SHLLINK) — обычный файл, поэтому разбирается
// без Windows, и тесты идут на любой системе.

// Link — что ярлык знает о своей цели.
type Link struct {
	Target    string // полный путь к цели из LinkInfo; пусто — ярлык его не хранит
	EnvTarget string // путь с переменными окружения (%LOCALAPPDATA%\…), если есть
	Arguments string
}

var errNotLink = errors.New("не ярлык Windows")

var lnkCLSID = []byte{0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}

// Флаги заголовка ярлыка (LinkFlags).
const (
	lnkHasIDList     = 0x1
	lnkHasLinkInfo   = 0x2
	lnkHasName       = 0x4
	lnkHasRelPath    = 0x8
	lnkHasWorkingDir = 0x10
	lnkHasArguments  = 0x20
	lnkHasIcon       = 0x40
	lnkIsUnicode     = 0x80

	lnkHeaderSize   = 0x4c
	lnkEnvBlock     = 0xa0000001 // EnvironmentVariableDataBlock
	lnkEnvBlockSize = 0x314
	lnkLocalPath    = 0x1 // LinkInfo: есть VolumeID и LocalBasePath
)

// ParseLink разбирает ярлык. Битый ярлык — ошибка, а не паника.
func ParseLink(data []byte) (Link, error) {
	if len(data) < lnkHeaderSize || le32(data, 0) != lnkHeaderSize || !bytes.Equal(data[4:20], lnkCLSID) {
		return Link{}, errNotLink
	}
	flags := le32(data, 20)
	off := lnkHeaderSize
	if flags&lnkHasIDList != 0 {
		if off+2 > len(data) {
			return Link{}, errNotLink
		}
		off += 2 + int(le16(data, off))
	}
	var l Link
	if flags&lnkHasLinkInfo != 0 {
		if off+4 > len(data) {
			return Link{}, errNotLink
		}
		size := int(le32(data, off))
		if size < 0x1c || off+size > len(data) {
			return Link{}, errNotLink
		}
		l.Target = linkInfoPath(data[off : off+size])
		off += size
	}
	unicode := flags&lnkIsUnicode != 0
	for _, f := range []uint32{lnkHasName, lnkHasRelPath, lnkHasWorkingDir, lnkHasArguments, lnkHasIcon} {
		if flags&f == 0 {
			continue
		}
		if off+2 > len(data) {
			return Link{}, errNotLink
		}
		n := int(le16(data, off))
		off += 2
		size := n
		if unicode {
			size *= 2
		}
		if off+size > len(data) {
			return Link{}, errNotLink
		}
		if f == lnkHasArguments {
			if unicode {
				l.Arguments = utf16z(data[off : off+size])
			} else {
				l.Arguments = ascii(data[off : off+size])
			}
		}
		off += size
	}
	for off+8 <= len(data) {
		size := int(le32(data, off))
		if size < 8 || off+size > len(data) {
			break // последний блок — размер меньше 4
		}
		if le32(data, off+4) == lnkEnvBlock && size >= lnkEnvBlockSize {
			l.EnvTarget = utf16z(data[off+8+260 : off+8+260+520])
		}
		off += size
	}
	return l, nil
}

// linkInfoPath — путь из LinkInfo: юникодный, если ярлык его хранит, иначе
// ANSI, но только из латиницы: кодировку ANSI той системы здесь не узнать.
func linkInfoPath(info []byte) string {
	header := int(le32(info, 4))
	if le32(info, 8)&lnkLocalPath == 0 {
		return ""
	}
	if header >= 0x24 && len(info) >= 0x24 {
		base, suffix := int(le32(info, 28)), int(le32(info, 32))
		if base > 0 && base < len(info) {
			p := utf16z(info[base:])
			if suffix > 0 && suffix < len(info) {
				p += utf16z(info[suffix:])
			}
			return p
		}
	}
	base, suffix := int(le32(info, 16)), int(le32(info, 24))
	if base <= 0 || base >= len(info) {
		return ""
	}
	p := cstr(info[base:])
	if suffix > 0 && suffix < len(info) {
		p += cstr(info[suffix:])
	}
	if ascii([]byte(p)) != p {
		return ""
	}
	return p
}

func le16(b []byte, off int) uint16 { return binary.LittleEndian.Uint16(b[off:]) }
func le32(b []byte, off int) uint32 { return binary.LittleEndian.Uint32(b[off:]) }

// utf16z — строка UTF-16LE до нулевого символа.
func utf16z(b []byte) string {
	var u []uint16
	for i := 0; i+1 < len(b); i += 2 {
		c := binary.LittleEndian.Uint16(b[i:])
		if c == 0 {
			break
		}
		u = append(u, c)
	}
	return string(utf16.Decode(u))
}

// cstr — байты до нулевого.
func cstr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

// ascii — латиница как есть, остальное — пусто: такой строке нельзя верить.
func ascii(b []byte) string {
	for _, c := range b {
		if c >= 0x80 {
			return ""
		}
	}
	return string(b)
}
