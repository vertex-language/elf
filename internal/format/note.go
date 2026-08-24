package format

import (
	"github.com/vertex-language/elf"
	"github.com/vertex-language/elf/internal/binio"
)

// Nhdr is a note record header. Identical in both classes, so Decode and
// Encode ignore the class argument; it is present to keep the shape uniform
// and to let Nhdr be used with DecodeN.
type Nhdr struct {
	Namesz uint32
	Descsz uint32
	Type   uint32
}

func (n *Nhdr) Decode(c *binio.Cursor, _ elf.Class) {
	n.Namesz = c.U32()
	n.Descsz = c.U32()
	n.Type = c.U32()
}

func (n *Nhdr) Encode(b *binio.Buf, _ elf.Class) {
	b.U32(n.Namesz)
	b.U32(n.Descsz)
	b.U32(n.Type)
}

// NoteAlign is the padding applied after a note's name and after its
// descriptor.
//
// The gABI specifies four-byte alignment for both classes, but 64-bit Linux
// notes are widely emitted with eight-byte alignment and the section's
// sh_addralign says which was used. Parsers must take the alignment from the
// section rather than assume; this helper only performs the rounding.
func NoteAlign(off, align int) int {
	if align <= 1 {
		return off
	}
	if r := off % align; r != 0 {
		off += align - r
	}
	return off
}