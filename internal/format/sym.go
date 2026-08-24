package format

import (
	"github.com/vertex-language/elf"
	"github.com/vertex-language/elf/internal/binio"
)

// Sym is a symbol table entry.
//
// The 32- and 64-bit forms hold the same members in different orders: 32-bit
// is name/value/size/info/other/shndx at 16 bytes, 64-bit is
// name/info/other/shndx/value/size at 24. Only the field order differs, so a
// converter that adjusts widths without reordering produces entries whose
// value and size land in info and other.
//
// Info and Other are raw bytes, as in the file. Bind, Type, and Visibility
// decode them; keeping the stored form raw means psABI-specific bits above the
// visibility field — PPC64's local entry offset, the MIPS STO_* flags —
// survive a read-modify-write untouched.
type Sym struct {
	Name  uint32
	Info  uint8
	Other uint8
	Shndx uint16
	Value uint64
	Size  uint64
}

func (s *Sym) Decode(c *binio.Cursor, cl elf.Class) {
	if !checkClass(c, cl) {
		return
	}
	if cl.Wide() {
		s.Name = c.U32()
		s.Info = c.U8()
		s.Other = c.U8()
		s.Shndx = c.U16()
		s.Value = c.U64()
		s.Size = c.U64()
		return
	}
	s.Name = c.U32()
	s.Value = uint64(c.U32())
	s.Size = uint64(c.U32())
	s.Info = c.U8()
	s.Other = c.U8()
	s.Shndx = c.U16()
}

func (s *Sym) Encode(b *binio.Buf, cl elf.Class) {
	if cl.Wide() {
		b.U32(s.Name)
		b.U8(s.Info)
		b.U8(s.Other)
		b.U16(s.Shndx)
		b.U64(s.Value)
		b.U64(s.Size)
		return
	}
	b.U32(s.Name)
	b.U32(uint32(s.Value))
	b.U32(uint32(s.Size))
	b.U8(s.Info)
	b.U8(s.Other)
	b.U16(s.Shndx)
}

// Bind returns the binding packed into st_info.
func (s *Sym) Bind() elf.SymBind { return elf.SymBind(s.Info >> 4) }

// Type returns the symbol type packed into st_info.
func (s *Sym) Type() elf.SymType { return elf.SymType(s.Info & 0xf) }

// SetInfo packs a binding and type into st_info.
func (s *Sym) SetInfo(bind elf.SymBind, typ elf.SymType) { s.Info = elf.SymInfo(bind, typ) }

// Visibility returns the visibility held in the low bits of st_other.
func (s *Sym) Visibility() elf.SymVisibility { return elf.Visibility(s.Other) }

// SetVisibility replaces the visibility in st_other, preserving the
// psABI-specific bits above it.
func (s *Sym) SetVisibility(v elf.SymVisibility) { s.Other = elf.WithVisibility(s.Other, v) }