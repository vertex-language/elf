package format

import (
	"github.com/vertex-language/elf"
	"github.com/vertex-language/elf/internal/binio"
)

// Rel is a relocation entry without an explicit addend.
//
// Info packs a symbol index and a relocation type, but with different shifts
// and field widths per class: 24/8 in the 32-bit form, 32/32 in the 64-bit
// form. Sym and Type unpack it; Info is never interpreted without a class.
type Rel struct {
	Off  uint64
	Info uint64
}

func (r *Rel) Decode(c *binio.Cursor, cl elf.Class) {
	if !checkClass(c, cl) {
		return
	}
	if cl.Wide() {
		r.Off = c.U64()
		r.Info = c.U64()
		return
	}
	r.Off = uint64(c.U32())
	r.Info = uint64(c.U32())
}

func (r *Rel) Encode(b *binio.Buf, cl elf.Class) {
	if cl.Wide() {
		b.U64(r.Off)
		b.U64(r.Info)
		return
	}
	b.U32(uint32(r.Off))
	b.U32(uint32(r.Info))
}

// Sym returns the symbol table index this relocation names.
func (r *Rel) Sym(cl elf.Class) uint32 {
	if cl.Wide() {
		return elf.RelSym64(r.Info)
	}
	return elf.RelSym32(uint32(r.Info))
}

// Type returns the relocation type.
func (r *Rel) Type(cl elf.Class) uint32 {
	if cl.Wide() {
		return elf.RelType64(r.Info)
	}
	return elf.RelType32(uint32(r.Info))
}

// SetInfo packs a symbol index and relocation type for the given class.
func (r *Rel) SetInfo(cl elf.Class, sym, typ uint32) {
	if cl.Wide() {
		r.Info = elf.RelInfo64(sym, typ)
		return
	}
	r.Info = uint64(elf.RelInfo32(sym, typ))
}

// Rela is a relocation entry with an explicit addend.
type Rela struct {
	Off    uint64
	Info   uint64
	Addend int64
}

func (r *Rela) Decode(c *binio.Cursor, cl elf.Class) {
	if !checkClass(c, cl) {
		return
	}
	if cl.Wide() {
		r.Off = c.U64()
		r.Info = c.U64()
		r.Addend = c.I64()
		return
	}
	r.Off = uint64(c.U32())
	r.Info = uint64(c.U32())
	r.Addend = int64(c.I32())
}

func (r *Rela) Encode(b *binio.Buf, cl elf.Class) {
	if cl.Wide() {
		b.U64(r.Off)
		b.U64(r.Info)
		b.I64(r.Addend)
		return
	}
	b.U32(uint32(r.Off))
	b.U32(uint32(r.Info))
	b.I32(int32(r.Addend))
}

// Sym returns the symbol table index this relocation names.
func (r *Rela) Sym(cl elf.Class) uint32 {
	if cl.Wide() {
		return elf.RelSym64(r.Info)
	}
	return elf.RelSym32(uint32(r.Info))
}

// Type returns the relocation type.
func (r *Rela) Type(cl elf.Class) uint32 {
	if cl.Wide() {
		return elf.RelType64(r.Info)
	}
	return elf.RelType32(uint32(r.Info))
}

// SetInfo packs a symbol index and relocation type for the given class.
func (r *Rela) SetInfo(cl elf.Class, sym, typ uint32) {
	if cl.Wide() {
		r.Info = elf.RelInfo64(sym, typ)
		return
	}
	r.Info = uint64(elf.RelInfo32(sym, typ))
}

// DecodeRelr reads one SHT_RELR entry: a bare word that is either an address
// or a bitmap of following addresses, with no struct around it.
func DecodeRelr(c *binio.Cursor, cl elf.Class) uint64 {
	if !checkClass(c, cl) {
		return 0
	}
	return c.UWord(cl.Wide())
}

// EncodeRelr writes one SHT_RELR entry.
func EncodeRelr(b *binio.Buf, cl elf.Class, v uint64) { b.UWord(cl.Wide(), v) }