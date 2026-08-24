package ar

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/vertex-language/elf/internal/binio"
)

// header is a decoded member header. Name is the raw 16-byte field with
// trailing spaces removed; it has not yet been resolved through the string
// table.
type header struct {
	rawName string
	mtime   int64
	uid     int
	gid     int
	mode    uint32
	size    int64
}

// parseHeader decodes the fixed 60-byte member header at off.
//
// Only ar_size and the terminator are load-bearing enough to fail on. A
// non-numeric uid or a garbled mode makes the member's metadata wrong but its
// contents still readable, and archives produced by older tools do contain
// blank fields, so those degrade to zero rather than failing the archive.
func parseHeader(b []byte, off int64) (header, error) {
	if len(b) < HeaderSize {
		return header{}, fmt.Errorf("ar: header at %#x is %d bytes, want %d: %w",
			off, len(b), HeaderSize, ErrBadHeader)
	}
	if string(b[58:60]) != headerTerm {
		return header{}, fmt.Errorf("ar: member header at %#x lacks the terminator: %w",
			off, ErrBadHeader)
	}

	var h header
	h.rawName = strings.TrimRight(string(b[0:16]), " ")

	size, err := parseDecimal(b[48:58], off, "size")
	if err != nil {
		return header{}, err
	}
	if size < 0 {
		return header{}, fmt.Errorf("ar: member at %#x declares a negative size: %w",
			off, ErrBadHeader)
	}
	h.size = size

	h.mtime, _ = parseDecimal(b[16:28], off, "mtime")
	uid, _ := parseDecimal(b[28:34], off, "uid")
	gid, _ := parseDecimal(b[34:40], off, "gid")
	h.uid, h.gid = int(uid), int(gid)

	if s := strings.TrimSpace(string(b[40:48])); s != "" {
		if v, err := strconv.ParseUint(s, 8, 32); err == nil {
			h.mode = uint32(v)
		}
	}
	return h, nil
}

func parseDecimal(b []byte, off int64, field string) (int64, error) {
	s := strings.TrimSpace(string(b))
	if s == "" {
		return 0, nil
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("ar: member at %#x has a non-numeric %s field %q: %w",
			off, field, s, ErrBadHeader)
	}
	return v, nil
}

// isBSDLongName reports whether a raw name field uses the BSD "#1/N"
// convention, where the real name follows the header and is counted in
// ar_size.
func isBSDLongName(raw string) bool {
	return strings.HasPrefix(raw, "#1/")
}

// writeHeader emits a member header. name must already be in its final
// encoded form: "foo.o/" for a short name, "/768" for a string table
// reference, or one of the special names.
func writeHeader(b *binio.Buf, name string, mtime int64, uid, gid int, mode uint32, size int64) error {
	if len(name) > 16 {
		return fmt.Errorf("ar: internal: encoded member name %q exceeds the 16-byte field", name)
	}
	if size < 0 || size > maxSizeField {
		return fmt.Errorf("ar: member size %d does not fit the 10-byte ar_size field", size)
	}
	field(b, name, 16)
	field(b, strconv.FormatInt(mtime, 10), 12)
	field(b, strconv.Itoa(uid), 6)
	field(b, strconv.Itoa(gid), 6)
	field(b, strconv.FormatUint(uint64(mode), 8), 8)
	field(b, strconv.FormatInt(size, 10), 10)
	b.WriteString(headerTerm)
	return nil
}

// field writes s left-justified in n bytes, space-padded. Unused header bytes
// are 0x20 by specification.
func field(b *binio.Buf, s string, n int) {
	if len(s) > n {
		s = s[:n]
	}
	b.WriteString(s)
	for i := len(s); i < n; i++ {
		b.WriteByte(' ')
	}
}

// padOdd appends the 0x0A filler byte if the buffer sits at an odd offset.
// Member headers must begin at even offsets.
func padOdd(b *binio.Buf) {
	if b.Len()%2 != 0 {
		b.WriteByte('\n')
	}
}