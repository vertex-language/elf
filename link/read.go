package link

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/vertex-language/elf"
	"github.com/vertex-language/elf/image"
	"github.com/vertex-language/elf/internal/binio"
	"github.com/vertex-language/elf/internal/format"
)

// Reading a dependency shared object.
//
// obj cannot do this: it rejects anything that is not ET_REL, and rightly so —
// a linked object has no section contributions, no relocations to apply, and
// no chunks. What the linker wants from a .so is exactly three things: its
// SONAME, its exported symbols, and its own dependencies.
//
// The parse goes through PT_DYNAMIC rather than the section header table.
// Section headers are optional in a linked object and stripped libraries in
// the wild do not have them, while PT_DYNAMIC is what the dynamic loader
// itself reads and is therefore always present and always correct.

// sharedFile is a parsed dependency.
type sharedFile struct {
	target  elf.Target
	soname  string
	needed  []string
	symbols []sharedSym
}

// sharedSym is one exported definition.
type sharedSym struct {
	name    string
	value   uint64
	size    uint64
	bind    elf.SymBind
	typ     elf.SymType
	other   uint8
	defined bool
}

// loadShared parses a shared object and merges its definitions.
func (r *resolver) loadShared(name string, data []byte) error {
	sf, err := readShared(name, data)
	if err != nil {
		return err
	}

	in := &image.Input{
		Name:   name,
		Target: sf.target,
		Shared: true,
		SOName: sf.soname,
	}
	if in.SOName == "" {
		// Without a DT_SONAME the loader has nothing to record but the path
		// it was given, which is what DT_NEEDED then has to name.
		in.SOName = name
	}
	if err := r.checkTarget(in); err != nil {
		return err
	}
	r.img.AddInput(in)

	for _, s := range sf.symbols {
		if s.name == "" || !s.defined {
			continue
		}
		g, _ := r.img.Syms.Insert(s.name)
		g.SetVisibility(elf.MostConstraining(g.Visibility(), elf.Visibility(s.other)))

		cand := rankShared
		if s.bind == elf.STB_WEAK {
			cand = rankSharedWeak
		}
		// A definition from an object file outranks one from a shared
		// object, and an archive member that has not been extracted ranks
		// below both. Only take the definition if nothing stronger has it.
		if r.rank[g] >= cand {
			continue
		}

		g.Class = image.SymShared
		g.Bind = s.bind
		g.Type = s.typ
		g.Other = s.other
		g.Value = s.value
		g.Size = s.size
		g.Input = in
		g.Chunk = nil
		r.rank[g] = cand
	}

	// A reference this library satisfies may still be offered by an archive
	// that comes later; the shared definition wins unless the member is
	// extracted for some other reason.
	r.needed = append(r.needed, in)
	return nil
}

// readShared parses the dynamic information out of a linked object.
func readShared(name string, data []byte) (*sharedFile, error) {
	eh, err := format.ParseEhdr(data)
	if err != nil {
		return nil, fmt.Errorf("link: %s: %w", name, err)
	}
	if eh.Type != elf.ET_DYN {
		return nil, fmt.Errorf("link: %s: e_type is %v, not ET_DYN", name, eh.Type)
	}

	cl := eh.Ident.Class
	ord := eh.Ident.ByteOrder()

	phdrs, err := readPhdrs(name, data, &eh, cl, ord)
	if err != nil {
		return nil, err
	}

	m := newVaddrMap(phdrs)
	dyn, err := readDynamic(name, data, phdrs, m, cl, ord)
	if err != nil {
		return nil, err
	}

	sf := &sharedFile{
		target: elf.Target{
			Arch:   elf.ArchOf(eh.Machine, cl),
			Class:  cl,
			Endian: eh.Ident.Data.Endian(),
			Flags:  eh.Flags,
		},
	}
	return sf, fillShared(name, data, dyn, m, cl, ord, sf)
}

func readPhdrs(name string, data []byte, eh *format.Ehdr,
	cl elf.Class, ord binary.ByteOrder) ([]format.Phdr, error) {

	if eh.Phoff == 0 || eh.Phnum == 0 {
		return nil, fmt.Errorf("link: %s: no program headers, so no dynamic information", name)
	}
	if eh.Phoff > uint64(len(data)) {
		return nil, fmt.Errorf("link: %s: e_phoff %#x is past the end of the file", name, eh.Phoff)
	}
	c := binio.NewCursorAt(data[eh.Phoff:], int64(eh.Phoff), ord)
	phdrs, err := format.DecodePhdrs(c, cl, int(eh.Phnum))
	if err != nil {
		return nil, fmt.Errorf("link: %s: %w", name, err)
	}
	return phdrs, nil
}

// vaddrMap converts run-time addresses to file offsets.
//
// Everything a .dynamic entry points at is a virtual address, because the
// loader reads it after mapping. Reading the same structure out of the file
// means undoing the mapping, which is what the PT_LOAD segments describe.
type vaddrMap struct{ loads []format.Phdr }

func newVaddrMap(phdrs []format.Phdr) *vaddrMap {
	var loads []format.Phdr
	for _, p := range phdrs {
		if p.Type == elf.PT_LOAD && p.Filesz > 0 {
			loads = append(loads, p)
		}
	}
	return &vaddrMap{loads: loads}
}

// offset returns the file offset holding the byte at virtual address v.
func (m *vaddrMap) offset(v uint64) (uint64, bool) {
	for _, p := range m.loads {
		if v >= p.Vaddr && v-p.Vaddr < p.Filesz {
			return p.Off + (v - p.Vaddr), true
		}
	}
	return 0, false
}

// slice returns the file bytes backing a range of virtual addresses.
func (m *vaddrMap) slice(data []byte, v, n uint64) ([]byte, bool) {
	off, ok := m.offset(v)
	if !ok || off > uint64(len(data)) || n > uint64(len(data))-off {
		return nil, false
	}
	return data[off : off+n], true
}

// rest returns the file bytes from a virtual address to the end of its
// segment, for tables whose length is not recorded.
func (m *vaddrMap) rest(data []byte, v uint64) ([]byte, bool) {
	for _, p := range m.loads {
		if v < p.Vaddr || v-p.Vaddr >= p.Filesz {
			continue
		}
		off := p.Off + (v - p.Vaddr)
		end := p.Off + p.Filesz
		if off > uint64(len(data)) || end > uint64(len(data)) || end < off {
			return nil, false
		}
		return data[off:end], true
	}
	return nil, false
}

// readDynamic decodes the .dynamic array.
func readDynamic(name string, data []byte, phdrs []format.Phdr, m *vaddrMap,
	cl elf.Class, ord binary.ByteOrder) ([]format.Dyn, error) {

	var seg *format.Phdr
	for i := range phdrs {
		if phdrs[i].Type == elf.PT_DYNAMIC {
			seg = &phdrs[i]
			break
		}
	}
	if seg == nil {
		return nil, fmt.Errorf("link: %s: no PT_DYNAMIC segment", name)
	}

	raw, ok := m.slice(data, seg.Vaddr, seg.Filesz)
	if !ok {
		// Some producers leave PT_DYNAMIC's p_vaddr outside every PT_LOAD.
		// Its p_offset is still good, so fall back to it rather than
		// refusing a library the loader would accept.
		if seg.Off > uint64(len(data)) || seg.Filesz > uint64(len(data))-seg.Off {
			return nil, fmt.Errorf("link: %s: PT_DYNAMIC lies outside the file", name)
		}
		raw = data[seg.Off : seg.Off+seg.Filesz]
	}

	stride := format.DynSize(cl)
	c := binio.NewCursor(raw, ord)
	dyn, err := format.DecodeDyns(c, cl, len(raw)/stride)
	if err != nil {
		return nil, fmt.Errorf("link: %s: decoding .dynamic: %w", name, err)
	}

	// DT_NULL terminates the array; entries after it are padding.
	for i, d := range dyn {
		if d.Tag == elf.DT_NULL {
			return dyn[:i], nil
		}
	}
	return dyn, nil
}

// fillShared reads the symbol table and the string table the .dynamic array
// points at.
func fillShared(name string, data []byte, dyn []format.Dyn, m *vaddrMap,
	cl elf.Class, ord binary.ByteOrder, sf *sharedFile) error {

	var strAddr, strSize, symAddr, hashAddr uint64
	var symEnt uint64
	var sonameOff uint64
	var neededOffs []uint64
	haveSoname := false

	for _, d := range dyn {
		switch d.Tag {
		case elf.DT_STRTAB:
			strAddr = d.Val
		case elf.DT_STRSZ:
			strSize = d.Val
		case elf.DT_SYMTAB:
			symAddr = d.Val
		case elf.DT_SYMENT:
			symEnt = d.Val
		case elf.DT_HASH:
			hashAddr = d.Val
		case elf.DT_SONAME:
			sonameOff, haveSoname = d.Val, true
		case elf.DT_NEEDED:
			neededOffs = append(neededOffs, d.Val)
		}
	}

	if strAddr == 0 || strSize == 0 {
		return fmt.Errorf("link: %s: .dynamic has no string table", name)
	}
	strs, ok := m.slice(data, strAddr, strSize)
	if !ok {
		return fmt.Errorf("link: %s: DT_STRTAB at %#x is not in any loaded segment", name, strAddr)
	}

	if haveSoname {
		sf.soname = dynString(strs, sonameOff)
	}
	for _, off := range neededOffs {
		if s := dynString(strs, off); s != "" {
			sf.needed = append(sf.needed, s)
		}
	}

	if symAddr == 0 {
		// A library exporting nothing is unusual but not malformed.
		return nil
	}
	if want := uint64(format.SymSize(cl)); symEnt != 0 && symEnt != want {
		return fmt.Errorf("link: %s: DT_SYMENT is %d, not the %d this class uses",
			name, symEnt, want)
	}

	n, err := dynSymCount(name, data, m, symAddr, hashAddr, cl, ord)
	if err != nil {
		return err
	}
	if n == 0 {
		return nil
	}

	raw, ok := m.slice(data, symAddr, n*uint64(format.SymSize(cl)))
	if !ok {
		return fmt.Errorf("link: %s: DT_SYMTAB of %d entries runs past its segment", name, n)
	}
	c := binio.NewCursor(raw, ord)
	syms, err := format.DecodeSyms(c, cl, int(n))
	if err != nil {
		return fmt.Errorf("link: %s: decoding .dynsym: %w", name, err)
	}

	sf.symbols = make([]sharedSym, 0, len(syms))
	for i := range syms {
		s := &syms[i]
		if i == 0 {
			continue
		}
		sf.symbols = append(sf.symbols, sharedSym{
			name:    dynString(strs, uint64(s.Name)),
			value:   s.Value,
			size:    s.Size,
			bind:    s.Bind(),
			typ:     s.Type(),
			other:   s.Other,
			defined: s.Shndx != elf.SHN_UNDEF_IDX,
		})
	}
	return nil
}

// dynSymCount works out how many entries .dynsym holds.
//
// Nothing in .dynamic records the count directly, which is the one genuinely
// awkward thing about reading a linked object. DT_HASH does record it: its
// second word is nchain, and the chain array has one entry per symbol. When
// there is no DT_HASH — a library with only DT_GNU_HASH, which is now the
// common case — the table is taken to run to the end of its segment, which is
// what it does in practice since .dynstr follows it.
func dynSymCount(name string, data []byte, m *vaddrMap,
	symAddr, hashAddr uint64, cl elf.Class, ord binary.ByteOrder) (uint64, error) {

	if hashAddr != 0 {
		if b, ok := m.slice(data, hashAddr, 8); ok {
			nchain := uint64(ord.Uint32(b[4:]))
			if nchain > 0 {
				return nchain, nil
			}
		}
	}

	rest, ok := m.rest(data, symAddr)
	if !ok {
		return 0, fmt.Errorf("link: %s: DT_SYMTAB at %#x is not in any loaded segment",
			name, symAddr)
	}
	return uint64(len(rest) / format.SymSize(cl)), nil
}

// dynString reads a NUL-terminated string from .dynstr.
func dynString(blob []byte, off uint64) string {
	if off >= uint64(len(blob)) {
		return ""
	}
	rest := blob[off:]
	if i := bytes.IndexByte(rest, 0); i >= 0 {
		return string(rest[:i])
	}
	return string(rest)
}