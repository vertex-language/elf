package ar

import (
	"encoding/binary"
	"fmt"

	"github.com/vertex-language/elf/internal/binio"
)

// The SysV symbol index is a count, then that many member-header offsets, then
// that many NUL-terminated symbol names in the same order. Every integer is
// big-endian regardless of the architecture the archive holds — the index is a
// property of the archive format, not of its contents.
//
// The "/SYM64/" variant widens the count and the offsets from four bytes to
// eight, for archives whose members no longer fit under 4 GiB.

// indexWord is the width of the count and offset fields.
func indexWord(wide bool) int64 {
	if wide {
		return 8
	}
	return 4
}

// encodeIndex builds a symbol index member's contents.
func encodeIndex(entries []IndexEntry, wide bool) []byte {
	b := binio.NewBufSize(binary.BigEndian, int(indexSize(entries, wide)))
	b.UWord(wide, uint64(len(entries)))
	for _, e := range entries {
		b.UWord(wide, uint64(e.HeaderOffset))
	}
	for _, e := range entries {
		b.WriteString(e.Name)
		b.WriteByte(0)
	}
	return b.Bytes()
}

// indexSize reports how many bytes encodeIndex will produce, so that member
// offsets can be computed before the index itself is built.
func indexSize(entries []IndexEntry, wide bool) int64 {
	word := indexWord(wide)
	n := word + word*int64(len(entries))
	for _, e := range entries {
		n += int64(len(e.Name)) + 1
	}
	return n
}

// decodeIndex parses a symbol index member's contents.
func decodeIndex(data []byte, wide bool) ([]IndexEntry, error) {
	word := indexWord(wide)
	c := binio.NewCursor(data, binary.BigEndian)

	count := c.UWord(wide)
	if c.Err() != nil {
		return nil, fmt.Errorf("ar: symbol index is too short to hold its count: %w", ErrBadIndex)
	}

	// Reject a declared count before allocating against it. The bound is what
	// the offset array alone requires; the names that follow only add to it.
	if max := (int64(len(data)) - word) / word; int64(count) > max {
		return nil, fmt.Errorf("ar: symbol index declares %d symbols but has room for at most %d: %w",
			count, max, ErrBadIndex)
	}

	out := make([]IndexEntry, count)
	for i := range out {
		out[i].HeaderOffset = int64(c.UWord(wide))
	}
	for i := range out {
		out[i].Name = c.CString()
	}
	if err := c.Err(); err != nil {
		return nil, fmt.Errorf("ar: decoding symbol index: %w", err)
	}
	return out, nil
}