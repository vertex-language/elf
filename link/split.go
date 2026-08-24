package link

import (
	"encoding/binary"
	"fmt"

	"github.com/vertex-language/elf"
	"github.com/vertex-language/elf/image"
)

// split breaks chunks that are collections of independent pieces into
// fragments, so that later phases work at the granularity the content
// actually has.
//
// It runs before garbage collection and before merging, and the ordering is
// load-bearing in both directions. Splitting after GC would sweep whole
// sections when only some records inside them are dead; splitting after merge
// would place whole chunks, so a deduplicated string would still occupy its
// original space and a dead FDE would keep its bytes however thoroughly the
// sweep proved it unreachable.
func (l *Linker) split(img *image.Image) error {
	for _, in := range img.Inputs {
		for _, ch := range in.Chunks {
			if ch.Discarded {
				continue
			}
			switch {
			case ch.Name == ".eh_frame" && ch.Type == elf.SHT_PROGBITS:
				if err := splitEhFrame(ch, img.Target.Class); err != nil {
					return fmt.Errorf("link: %s: %w", ch, err)
				}
			case ch.Flags.Mergeable():
				if err := splitMergeable(ch); err != nil {
					return fmt.Errorf("link: %s: %w", ch, err)
				}
			}
		}
	}
	return nil
}

// splitMergeable cuts an SHF_MERGE section into its records.
//
// With SHF_STRINGS the records are NUL-terminated strings of sh_entsize-wide
// characters; without it they are fixed-size entries of sh_entsize bytes. A
// section claiming to be mergeable with no entry size is malformed, but it is
// also common enough in hand-written assembly that the section is left whole
// rather than rejected.
func splitMergeable(ch *image.Chunk) error {
	if ch.Entsize == 0 {
		ch.Flags &^= image.SecFlags(elf.SHF_MERGE | elf.SHF_STRINGS)
		return nil
	}
	data, err := ch.Data()
	if err != nil {
		return err
	}
	if len(data) == 0 {
		return nil
	}

	if ch.Flags.Strings() {
		return splitStrings(ch, data)
	}
	return splitFixed(ch, data)
}

func splitStrings(ch *image.Chunk, data []byte) error {
	width := int(ch.Entsize)
	if width <= 0 || len(data)%width != 0 {
		return fmt.Errorf("mergeable string section of %d bytes is not a multiple of its %d-byte character",
			len(data), ch.Entsize)
	}

	start := 0
	for i := 0; i+width <= len(data); i += width {
		if !allZero(data[i : i+width]) {
			continue
		}
		end := i + width
		ch.Fragments = append(ch.Fragments, &image.Fragment{
			Parent: ch,
			Off:    uint64(start),
			Data:   data[start:end],
			Align:  ch.Align,
		})
		start = end
	}
	if start != len(data) {
		return fmt.Errorf("mergeable string section's last entry is unterminated")
	}
	return nil
}

func splitFixed(ch *image.Chunk, data []byte) error {
	n := int(ch.Entsize)
	if len(data)%n != 0 {
		return fmt.Errorf("mergeable section of %d bytes is not a multiple of its %d-byte entry",
			len(data), n)
	}
	// Alignment cannot exceed the entry size, or the pieces could not be
	// packed back-to-back after deduplication.
	align := ch.Align
	if align > ch.Entsize {
		align = ch.Entsize
	}
	for off := 0; off < len(data); off += n {
		ch.Fragments = append(ch.Fragments, &image.Fragment{
			Parent: ch,
			Off:    uint64(off),
			Data:   data[off : off+n],
			Align:  align,
		})
	}
	return nil
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// CFI record framing.
const (
	// cfiExtended in the length field escapes to a 64-bit length.
	cfiExtended = 0xffffffff

	// cieID is the value of the id field in a CIE. In an FDE the same field
	// is a nonzero backward distance to its CIE.
	cieID = 0
)

// splitEhFrame cuts .eh_frame into its CIE and FDE records.
//
// Each record is a 4-byte length that does not count itself, optionally
// escaping to an 8-byte length when it reads 0xffffffff, followed by an id
// field. An id of zero marks a CIE; anything else marks an FDE, and the value
// is how far backward from the id field the owning CIE's length field sits. A
// length of zero is a terminator and ends the section.
//
// Fragment.Off is each record's offset in the input section, because that is
// what a relocation into .eh_frame names.
func splitEhFrame(ch *image.Chunk, cl elf.Class) error {
	data, err := ch.Data()
	if err != nil {
		return err
	}
	if len(data) == 0 {
		return nil
	}
	ord := byteOrder(cl, ch)

	off := 0
	for off < len(data) {
		if off+4 > len(data) {
			return fmt.Errorf("truncated CFI record header at %#x", off)
		}
		lenField := ord.Uint32(data[off:])
		hdr := 4
		var size uint64

		switch lenField {
		case 0:
			// Terminator. Anything after it is padding.
			return nil
		case cfiExtended:
			if off+12 > len(data) {
				return fmt.Errorf("truncated 64-bit CFI length at %#x", off)
			}
			size = ord.Uint64(data[off+4:])
			hdr = 12
		default:
			size = uint64(lenField)
		}

		end := uint64(off) + uint64(hdr) + size
		if end > uint64(len(data)) || end <= uint64(off) {
			return fmt.Errorf("CFI record at %#x claims %d bytes, past the section's %d",
				off, size, len(data))
		}

		ch.Fragments = append(ch.Fragments, &image.Fragment{
			Parent: ch,
			Off:    uint64(off),
			Data:   data[off:end],
			Align:  ch.Align,
		})
		off = int(end)
	}
	return nil
}

// isCIE reports whether a CFI record is a common information entry.
func isCIE(rec []byte, ord binary.ByteOrder) bool {
	if len(rec) < 8 {
		return false
	}
	if ord.Uint32(rec) == cfiExtended {
		return len(rec) >= 16 && ord.Uint64(rec[12:]) == cieID
	}
	return ord.Uint32(rec[4:]) == cieID
}

// byteOrder returns the byte order to read a chunk's contents with.
func byteOrder(cl elf.Class, ch *image.Chunk) binary.ByteOrder {
	if ch.Input != nil && ch.Input.Target.Endian == elf.EndianBig {
		return binary.BigEndian
	}
	return binary.LittleEndian
}