package format

import (
	"github.com/vertex-language/elf"
	"github.com/vertex-language/elf/internal/binio"
)

// Phdr is a program header.
//
// The two classes do not merely differ in width: p_flags sits immediately
// after p_type in the 64-bit form and immediately before p_align in the
// 32-bit form. A width-only conversion produces a header whose permissions
// and alignment are swapped.
type Phdr struct {
	Type   elf.ProgType
	Flags  uint32
	Off    uint64
	Vaddr  uint64
	Paddr  uint64
	Filesz uint64
	Memsz  uint64
	Align  uint64
}

func (p *Phdr) Decode(c *binio.Cursor, cl elf.Class) {
	if !checkClass(c, cl) {
		return
	}
	if cl.Wide() {
		p.Type = elf.ProgType(c.U32())
		p.Flags = c.U32()
		p.Off = c.U64()
		p.Vaddr = c.U64()
		p.Paddr = c.U64()
		p.Filesz = c.U64()
		p.Memsz = c.U64()
		p.Align = c.U64()
		return
	}
	p.Type = elf.ProgType(c.U32())
	p.Off = uint64(c.U32())
	p.Vaddr = uint64(c.U32())
	p.Paddr = uint64(c.U32())
	p.Filesz = uint64(c.U32())
	p.Memsz = uint64(c.U32())
	p.Flags = c.U32()
	p.Align = uint64(c.U32())
}

func (p *Phdr) Encode(b *binio.Buf, cl elf.Class) {
	if cl.Wide() {
		b.U32(uint32(p.Type))
		b.U32(p.Flags)
		b.U64(p.Off)
		b.U64(p.Vaddr)
		b.U64(p.Paddr)
		b.U64(p.Filesz)
		b.U64(p.Memsz)
		b.U64(p.Align)
		return
	}
	b.U32(uint32(p.Type))
	b.U32(uint32(p.Off))
	b.U32(uint32(p.Vaddr))
	b.U32(uint32(p.Paddr))
	b.U32(uint32(p.Filesz))
	b.U32(uint32(p.Memsz))
	b.U32(p.Flags)
	b.U32(uint32(p.Align))
}