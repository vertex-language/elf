package format

import (
	"github.com/vertex-language/elf"
	"github.com/vertex-language/elf/internal/binio"
)

// Chdr is the compression header that prefixes the contents of a section
// flagged SHF_COMPRESSED.
//
// The 64-bit form carries four bytes of padding after ch_type to align ch_size
// — the only reserved field in any ELF structure this module writes. It is
// written as zero and ignored on read.
type Chdr struct {
	Type      elf.CompressionType
	Size      uint64
	Addralign uint64
}

func (h *Chdr) Decode(c *binio.Cursor, cl elf.Class) {
	if !checkClass(c, cl) {
		return
	}
	if cl.Wide() {
		h.Type = elf.CompressionType(c.U32())
		c.Skip(4) // ch_reserved
		h.Size = c.U64()
		h.Addralign = c.U64()
		return
	}
	h.Type = elf.CompressionType(c.U32())
	h.Size = uint64(c.U32())
	h.Addralign = uint64(c.U32())
}

func (h *Chdr) Encode(b *binio.Buf, cl elf.Class) {
	if cl.Wide() {
		b.U32(uint32(h.Type))
		b.U32(0) // ch_reserved
		b.U64(h.Size)
		b.U64(h.Addralign)
		return
	}
	b.U32(uint32(h.Type))
	b.U32(uint32(h.Size))
	b.U32(uint32(h.Addralign))
}