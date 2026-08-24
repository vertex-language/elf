package format

import (
	"github.com/vertex-language/elf"
	"github.com/vertex-language/elf/internal/binio"
)

// Shdr is a section header.
//
// Flags is uint64 in both classes; the 32-bit form is zero-extended on decode
// and truncated on encode. The alternative — a 32-bit field that silently
// widens — puts the class check at every use site instead of here.
type Shdr struct {
	Name      uint32
	Type      elf.SHType
	Flags     uint64
	Addr      uint64
	Off       uint64
	Size      uint64
	Link      uint32
	Info      uint32
	Addralign uint64
	Entsize   uint64
}

func (s *Shdr) Decode(c *binio.Cursor, cl elf.Class) {
	if !checkClass(c, cl) {
		return
	}
	wide := cl.Wide()

	s.Name = c.U32()
	s.Type = elf.SHType(c.U32())
	s.Flags = c.UWord(wide)
	s.Addr = c.UWord(wide)
	s.Off = c.UWord(wide)
	s.Size = c.UWord(wide)
	s.Link = c.U32()
	s.Info = c.U32()
	s.Addralign = c.UWord(wide)
	s.Entsize = c.UWord(wide)
}

func (s *Shdr) Encode(b *binio.Buf, cl elf.Class) {
	wide := cl.Wide()

	b.U32(s.Name)
	b.U32(uint32(s.Type))
	b.UWord(wide, s.Flags)
	b.UWord(wide, s.Addr)
	b.UWord(wide, s.Off)
	b.UWord(wide, s.Size)
	b.U32(s.Link)
	b.U32(s.Info)
	b.UWord(wide, s.Addralign)
	b.UWord(wide, s.Entsize)
}