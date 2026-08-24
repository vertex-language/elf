package format

import (
	"github.com/vertex-language/elf"
	"github.com/vertex-language/elf/internal/binio"
)

// Dyn is one entry of the .dynamic array.
//
// d_tag is signed in the spec — Elf32_Sword and Elf64_Sxword — while the union
// that follows is read as unsigned. Decoding the tag unsigned makes the
// negative processor-specific tags compare wrong.
type Dyn struct {
	Tag elf.DynTag
	Val uint64
}

func (d *Dyn) Decode(c *binio.Cursor, cl elf.Class) {
	if !checkClass(c, cl) {
		return
	}
	wide := cl.Wide()
	d.Tag = elf.DynTag(c.IWord(wide))
	d.Val = c.UWord(wide)
}

func (d *Dyn) Encode(b *binio.Buf, cl elf.Class) {
	wide := cl.Wide()
	b.IWord(wide, int64(d.Tag))
	b.UWord(wide, d.Val)
}