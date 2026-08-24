package format

import (
	"github.com/vertex-language/elf"
	"github.com/vertex-language/elf/internal/binio"
)

// The symbol versioning structures are identical in both classes: every field
// is 16 or 32 bits regardless of width. Decode and Encode still take a class
// so that the whole package presents one shape.

// Verdef is a version definition, the head of a chain of Verdaux names.
type Verdef struct {
	Version uint16
	Flags   uint16
	Ndx     uint16
	Cnt     uint16
	Hash    uint32
	Aux     uint32 // byte offset from this Verdef to its first Verdaux
	Next    uint32 // byte offset to the next Verdef, or 0
}

func (v *Verdef) Decode(c *binio.Cursor, _ elf.Class) {
	v.Version = c.U16()
	v.Flags = c.U16()
	v.Ndx = c.U16()
	v.Cnt = c.U16()
	v.Hash = c.U32()
	v.Aux = c.U32()
	v.Next = c.U32()
}

func (v *Verdef) Encode(b *binio.Buf, _ elf.Class) {
	b.U16(v.Version)
	b.U16(v.Flags)
	b.U16(v.Ndx)
	b.U16(v.Cnt)
	b.U32(v.Hash)
	b.U32(v.Aux)
	b.U32(v.Next)
}

// Verdaux is one name within a version definition.
type Verdaux struct {
	Name uint32 // .dynstr offset
	Next uint32 // byte offset to the next Verdaux, or 0
}

func (v *Verdaux) Decode(c *binio.Cursor, _ elf.Class) {
	v.Name = c.U32()
	v.Next = c.U32()
}

func (v *Verdaux) Encode(b *binio.Buf, _ elf.Class) {
	b.U32(v.Name)
	b.U32(v.Next)
}

// Verneed is a version requirement on one needed object.
type Verneed struct {
	Version uint16
	Cnt     uint16
	File    uint32 // .dynstr offset of the needed object's name
	Aux     uint32 // byte offset to the first Vernaux
	Next    uint32 // byte offset to the next Verneed, or 0
}

func (v *Verneed) Decode(c *binio.Cursor, _ elf.Class) {
	v.Version = c.U16()
	v.Cnt = c.U16()
	v.File = c.U32()
	v.Aux = c.U32()
	v.Next = c.U32()
}

func (v *Verneed) Encode(b *binio.Buf, _ elf.Class) {
	b.U16(v.Version)
	b.U16(v.Cnt)
	b.U32(v.File)
	b.U32(v.Aux)
	b.U32(v.Next)
}

// Vernaux is one required version from a needed object.
type Vernaux struct {
	Hash  uint32
	Flags uint16
	Other uint16 // the version index referenced from .gnu.version
	Name  uint32 // .dynstr offset
	Next  uint32 // byte offset to the next Vernaux, or 0
}

func (v *Vernaux) Decode(c *binio.Cursor, _ elf.Class) {
	v.Hash = c.U32()
	v.Flags = c.U16()
	v.Other = c.U16()
	v.Name = c.U32()
	v.Next = c.U32()
}

func (v *Vernaux) Encode(b *binio.Buf, _ elf.Class) {
	b.U32(v.Hash)
	b.U16(v.Flags)
	b.U16(v.Other)
	b.U32(v.Name)
	b.U32(v.Next)
}

// Version record constants.
const (
	VER_DEF_CURRENT  = 1
	VER_NEED_CURRENT = 1

	VER_FLG_BASE = 0x1
	VER_FLG_WEAK = 0x2
	VER_FLG_INFO = 0x4

	// Reserved .gnu.version indexes.
	VER_NDX_LOCAL   = 0
	VER_NDX_GLOBAL  = 1
	VER_NDX_HIDDEN  = 0x8000 // flag bit, not an index
	VER_NDX_ELIMINATE = 0xff01
)