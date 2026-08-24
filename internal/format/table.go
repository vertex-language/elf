package format

import (
	"github.com/vertex-language/elf"
	"github.com/vertex-language/elf/internal/binio"
)

// DecodeN decodes n consecutive structures from c.
//
// The count is checked against the data before anything is allocated, so a
// header claiming four billion symbols fails with a binio.CountError naming
// the declared count rather than allocating against it. Use it for every
// table whose length comes from the file.
//
// Constrained on the pointer type so that Decode, which has a pointer
// receiver, is visible:
//
//	syms, err := format.DecodeN[format.Sym](c, cl, n)
func DecodeN[T any, P interface {
	*T
	Decode(*binio.Cursor, elf.Class)
}](c *binio.Cursor, cl elf.Class, n int, stride int) ([]T, error) {
	if !checkClass(c, cl) {
		return nil, c.Err()
	}
	tab, err := c.Table(uint64(n), stride)
	if err != nil {
		return nil, err
	}
	out := make([]T, n)
	for i := range out {
		P(&out[i]).Decode(tab, cl)
	}
	if err := tab.Err(); err != nil {
		c.Fail(err)
		return nil, err
	}
	return out, nil
}

// DecodeSyms, DecodeShdrs, and friends fix the stride so callers cannot pass a
// mismatched one. Prefer these to DecodeN.

func DecodeShdrs(c *binio.Cursor, cl elf.Class, n int) ([]Shdr, error) {
	return DecodeN[Shdr](c, cl, n, ShdrSize(cl))
}

func DecodePhdrs(c *binio.Cursor, cl elf.Class, n int) ([]Phdr, error) {
	return DecodeN[Phdr](c, cl, n, PhdrSize(cl))
}

func DecodeSyms(c *binio.Cursor, cl elf.Class, n int) ([]Sym, error) {
	return DecodeN[Sym](c, cl, n, SymSize(cl))
}

func DecodeRels(c *binio.Cursor, cl elf.Class, n int) ([]Rel, error) {
	return DecodeN[Rel](c, cl, n, RelSize(cl))
}

func DecodeRelas(c *binio.Cursor, cl elf.Class, n int) ([]Rela, error) {
	return DecodeN[Rela](c, cl, n, RelaSize(cl))
}

func DecodeDyns(c *binio.Cursor, cl elf.Class, n int) ([]Dyn, error) {
	return DecodeN[Dyn](c, cl, n, DynSize(cl))
}