package obj

import (
	"fmt"

	"github.com/vertex-language/elf"
	"github.com/vertex-language/elf/internal/format"
)

// Symbol is one entry of a parsed symbol table.
//
// Shndx is the symbol's section index after any SHT_SYMTAB_SHNDX escape has
// been resolved, so it may exceed what st_shndx can hold. Section is the
// section it names, or nil when Shndx is reserved (undefined, absolute,
// common) or out of range — use Undefined, Absolute, and Common rather than
// comparing Section against nil, which conflates "undefined" with "names a
// section this file does not have".
type Symbol struct {
	Name  string
	Value uint64
	Size  uint64
	Bind  elf.SymBind
	Type  elf.SymType

	// Other is the raw st_other byte. Visibility decodes the part of it the
	// gABI defines; the upper bits are psABI-specific and are preserved here
	// rather than discarded.
	Other uint8

	Shndx   uint32
	Section *Section

	// Index is the symbol's position in its table, which is what relocations
	// refer to.
	Index uint32
}

// Visibility returns the symbol's visibility from st_other.
func (s *Symbol) Visibility() elf.SymVisibility { return elf.Visibility(s.Other) }

// Undefined reports whether the symbol is a reference with no definition here.
func (s *Symbol) Undefined() bool { return s.Shndx == elf.SHN_UNDEF_IDX }

// Absolute reports whether the symbol's value is not subject to relocation.
func (s *Symbol) Absolute() bool { return s.Shndx == elf.SHN_ABS_IDX }

// Common reports whether the symbol labels an unallocated common block. For
// such symbols Value holds an alignment, not an offset.
func (s *Symbol) Common() bool { return s.Shndx == elf.SHN_COMMON_IDX }

// Defined reports whether this object provides a definition for the symbol.
func (s *Symbol) Defined() bool { return !s.Undefined() }

func (s *Symbol) String() string {
	if s.Name == "" {
		return fmt.Sprintf("<sym %d>", s.Index)
	}
	return s.Name
}

// Symbols returns the object's SHT_SYMTAB entries, entry zero included so that
// a symbol's position in the slice is its symbol table index.
//
// The result is cached: repeated calls return the same slice and the same
// *Symbol values. Relocations point at these, and the linker resolves by
// pointer, so identity has to be stable.
//
// A file with no symbol table returns nil and no error.
func (f *File) Symbols() ([]*Symbol, error) {
	if f.symtab == nil {
		return nil, nil
	}
	return f.SymbolsOf(f.symtab)
}

// DynamicSymbols returns the object's SHT_DYNSYM entries. Relocatable objects
// rarely have one.
func (f *File) DynamicSymbols() ([]*Symbol, error) {
	if f.dynsym == nil {
		return nil, nil
	}
	return f.SymbolsOf(f.dynsym)
}

// SymbolsOf returns the entries of an arbitrary symbol table section.
//
// Each table is decoded at most once and cached by section, so symbols reached
// through two different relocation sections that share a symbol table are the
// same objects.
func (f *File) SymbolsOf(sec *Section) ([]*Symbol, error) {
	if sec == nil {
		return nil, ErrNoSymbolTable
	}
	if sec.file != f {
		return nil, fmt.Errorf("obj: SymbolsOf on a section from a different file")
	}
	if syms, ok := f.syms[sec]; ok {
		return syms, nil
	}
	if sec.Type != elf.SHT_SYMTAB && sec.Type != elf.SHT_DYNSYM {
		return nil, fmt.Errorf("obj: section %q is %v, not a symbol table", sec.Name, sec.Type)
	}

	syms, err := f.parseSymbols(sec)
	if err != nil {
		return nil, err
	}
	f.syms[sec] = syms
	return syms, nil
}

// parseSymbols decodes a symbol table. It touches no File state beyond the
// section table, so it is safe to call from SymbolsOf under any ordering.
func (f *File) parseSymbols(sec *Section) ([]*Symbol, error) {
	strtab := f.SectionAt(sec.Link)
	if strtab == nil {
		return nil, fmt.Errorf("obj: symbol table %q sh_link %d names no string table",
			sec.Name, sec.Link)
	}
	strs, err := strtab.Data()
	if err != nil {
		return nil, fmt.Errorf("obj: reading %q's string table: %w", sec.Name, err)
	}

	stride := format.SymSize(f.Class)
	n, err := sec.entryCount(stride, "symbol")
	if err != nil {
		return nil, err
	}

	c, err := sec.cursor()
	if err != nil {
		return nil, err
	}
	raw, err := format.DecodeSyms(c, f.Class, n)
	if err != nil {
		return nil, fmt.Errorf("obj: decoding %q: %w", sec.Name, err)
	}

	xindex, err := f.extendedIndexes(sec, n)
	if err != nil {
		return nil, err
	}

	out := make([]*Symbol, n)
	for i := range raw {
		r := &raw[i]
		shndx := uint32(r.Shndx)
		if r.Shndx == elf.SHN_XINDEX_IDX {
			if xindex == nil {
				return nil, fmt.Errorf(
					"obj: symbol %d in %q uses SHN_XINDEX but the file has no SHT_SYMTAB_SHNDX for that table",
					i, sec.Name)
			}
			shndx = xindex[i]
		}
		sym := &Symbol{
			Name:  stringAt(strs, r.Name),
			Value: r.Value,
			Size:  r.Size,
			Bind:  r.Bind(),
			Type:  r.Type(),
			Other: r.Other,
			Shndx: shndx,
			Index: uint32(i),
		}
		sym.Section = f.SectionAt(shndx)
		out[i] = sym
	}
	return out, nil
}

// extendedIndexes reads the SHT_SYMTAB_SHNDX table associated with sec, or
// returns nil if there is none.
//
// The association is by sh_link, not by position: an object with two symbol
// tables can have two escape tables, and taking whichever comes first silently
// applies one table's indexes to the other's symbols.
func (f *File) extendedIndexes(sec *Section, n int) ([]uint32, error) {
	var xsec *Section
	for _, s := range f.Sections {
		if s.Type == elf.SHT_SYMTAB_SHNDX && s.Link == sec.Index {
			xsec = s
			break
		}
	}
	if xsec == nil {
		return nil, nil
	}

	data, err := xsec.Data()
	if err != nil {
		return nil, fmt.Errorf("obj: reading %q: %w", xsec.Name, err)
	}
	if len(data) < n*4 {
		return nil, fmt.Errorf("obj: %q holds %d entries for a symbol table of %d",
			xsec.Name, len(data)/4, n)
	}
	out := make([]uint32, n)
	for i := range out {
		out[i] = f.bo.Uint32(data[i*4:])
	}
	return out, nil
}