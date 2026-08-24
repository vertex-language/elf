package obj

import (
	"fmt"

	"github.com/vertex-language/elf"
	"github.com/vertex-language/elf/internal/format"
)

// Reloc is one decoded relocation.
//
// Addend is meaningful only when Explicit is true, which is to say only for
// SHT_RELA. For SHT_REL the addend is stored implicitly in the section
// contents at Offset, and recovering it requires knowing the instruction
// encoding the relocation type applies to: on ARM an R_ARM_CALL addend lives
// in a 24-bit immediate field, not in a machine word. That is psABI knowledge,
// so the object reader does not guess. The backend recovers it from the
// section bytes through backend.RelAddend.
type Reloc struct {
	Offset uint64

	// Sym is the referenced symbol, or nil if the index is out of range.
	// SymIndex is always the raw index, so a dangling reference is still
	// reportable.
	Sym      *Symbol
	SymIndex uint32

	Type   uint32
	Addend int64

	// Explicit reports whether Addend came from the file (RELA) rather than
	// needing recovery from section contents (REL).
	Explicit bool
}

// RelocSections returns the relocation sections that apply to s, in section
// table order. Usually there is one; there is no rule against several.
func (s *Section) RelocSections() []*Section {
	return s.file.relocsFor[s.Index]
}

// Relocs returns every relocation applying to s.
//
// A section with no relocations returns nil and no error.
func (s *Section) Relocs() ([]Reloc, error) {
	rels := s.file.relocsFor[s.Index]
	if len(rels) == 0 {
		return nil, nil
	}
	if len(rels) == 1 {
		return s.file.decodeRelocs(rels[0])
	}
	var out []Reloc
	for _, rs := range rels {
		part, err := s.file.decodeRelocs(rs)
		if err != nil {
			return nil, err
		}
		out = append(out, part...)
	}
	return out, nil
}

// decodeRelocs decodes one SHT_REL or SHT_RELA section.
func (f *File) decodeRelocs(relSec *Section) ([]Reloc, error) {
	rela := relSec.Type == elf.SHT_RELA
	if !rela && relSec.Type != elf.SHT_REL {
		return nil, fmt.Errorf("obj: section %q is %v, not a relocation section",
			relSec.Name, relSec.Type)
	}

	symtab := f.SectionAt(relSec.Link)
	if symtab == nil {
		return nil, fmt.Errorf("obj: relocation section %q sh_link %d names no symbol table",
			relSec.Name, relSec.Link)
	}
	syms, err := f.SymbolsOf(symtab)
	if err != nil {
		return nil, err
	}

	stride := format.RelSize(f.Class)
	if rela {
		stride = format.RelaSize(f.Class)
	}
	n, err := relSec.entryCount(stride, "relocation")
	if err != nil {
		return nil, err
	}

	c, err := relSec.cursor()
	if err != nil {
		return nil, err
	}

	out := make([]Reloc, n)
	if rela {
		raw, err := format.DecodeRelas(c, f.Class, n)
		if err != nil {
			return nil, fmt.Errorf("obj: decoding %q: %w", relSec.Name, err)
		}
		for i := range raw {
			r := &raw[i]
			idx := r.Sym(f.Class)
			out[i] = Reloc{
				Offset:   r.Off,
				Sym:      symAt(syms, idx),
				SymIndex: idx,
				Type:     r.Type(f.Class),
				Addend:   r.Addend,
				Explicit: true,
			}
		}
		return out, nil
	}

	raw, err := format.DecodeRels(c, f.Class, n)
	if err != nil {
		return nil, fmt.Errorf("obj: decoding %q: %w", relSec.Name, err)
	}
	for i := range raw {
		r := &raw[i]
		idx := r.Sym(f.Class)
		out[i] = Reloc{
			Offset:   r.Off,
			Sym:      symAt(syms, idx),
			SymIndex: idx,
			Type:     r.Type(f.Class),
			Explicit: false,
		}
	}
	return out, nil
}

// symAt returns the symbol at idx, or nil. An out-of-range index is left for
// the caller to report with context; failing the whole decode here would lose
// the offset and section that make the error actionable.
func symAt(syms []*Symbol, idx uint32) *Symbol {
	if uint64(idx) >= uint64(len(syms)) {
		return nil
	}
	return syms[idx]
}