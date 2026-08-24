package obj

import (
	"encoding/binary"
	"fmt"
	"sort"

	"github.com/vertex-language/elf"
	"github.com/vertex-language/elf/internal/binio"
	"github.com/vertex-language/elf/internal/format"
	"github.com/vertex-language/elf/internal/strtab"
)

func byteOrder(t elf.Target) binary.ByteOrder {
	if t.Endian == elf.EndianBig {
		return binary.BigEndian
	}
	return binary.LittleEndian
}

// Close resolves the object and writes it.
//
// It may be called once. A second call is an error rather than a second
// object: the first call appends generated sections — .note.GNU-stack, the
// relocation sections, .symtab, .strtab, .shstrtab — and running it again
// would duplicate every one of them.
func (wr *Writer) Close() error {
	if wr.done {
		return fmt.Errorf("obj: Close called twice")
	}
	wr.done = true
	if wr.err != nil {
		return wr.err
	}

	cl := wr.class()
	bo := byteOrder(wr.opts.Target)

	if wr.opts.GNUStack != elf.StackOmit {
		flags := uint64(0)
		if wr.opts.GNUStack == elf.StackExec {
			flags = elf.SHF_EXECINSTR
		}
		wr.Section(SectionHeader{
			Name: ".note.GNU-stack", Type: elf.SHT_PROGBITS, Flags: flags, Addralign: 1,
		})
	}

	form, err := wr.resolveRelocFormat()
	if err != nil {
		return err
	}

	firstNonLocal, usedGNU := wr.orderSymbols()

	// REL targets carry their addends in the section contents, so this has to
	// happen before the contents are laid out.
	if form == elf.RelocREL {
		if err := wr.depositAddends(); err != nil {
			return err
		}
	}

	// Relocation sections need only symbol indexes, which orderSymbols has
	// assigned, so they can be emitted before section indexes exist.
	userSections := len(wr.sections)
	for i := 0; i < userSections; i++ {
		sec := wr.sections[i]
		if len(sec.relocs) == 0 {
			continue
		}
		wr.emitRelocSection(sec, form == elf.RelocRELA)
	}
	if wr.err != nil {
		return wr.err
	}

	// A symbol can only name a section this object defines, so the escape
	// table is needed exactly when those indexes reach the reserved range.
	// Sections are numbered from 1, so the highest is the count.
	needShndx := len(wr.sections) >= elf.SHN_LORESERVE_IDX

	symtabSec := wr.Section(SectionHeader{
		Name: ".symtab", Type: elf.SHT_SYMTAB, Addralign: wordAlign(cl),
		Entsize: uint64(format.SymSize(cl)),
	})
	strtabSec := wr.Section(SectionHeader{
		Name: ".strtab", Type: elf.SHT_STRTAB, Addralign: 1,
	})
	var shndxSec *SectionBuilder
	if needShndx {
		shndxSec = wr.Section(SectionHeader{
			Name: ".symtab_shndx", Type: elf.SHT_SYMTAB_SHNDX, Addralign: 4, Entsize: 4,
		})
	}
	shstrtabSec := wr.Section(SectionHeader{
		Name: ".shstrtab", Type: elf.SHT_STRTAB, Addralign: 1,
	})

	// Index 0 is the null section header, so real sections start at 1.
	for i, sec := range wr.sections {
		sec.index = uint32(i + 1)
		sec.indexed = true
	}

	if err := wr.writeSymtab(symtabSec, strtabSec, shndxSec, cl); err != nil {
		return err
	}
	if err := wr.writeGroups(symtabSec); err != nil {
		return err
	}

	shstrtabB := strtab.NewELF()
	nameRefs := make(map[*SectionBuilder]*strtab.Ref, len(wr.sections))
	for _, sec := range wr.sections {
		nameRefs[sec] = shstrtabB.Add(sec.Name)
	}
	shstrtabSec.buf.Write(shstrtabB.Finish())

	symtabSec.Link = strtabSec.index
	symtabSec.Info = firstNonLocal
	if shndxSec != nil {
		shndxSec.Link = symtabSec.index
	}
	for _, sec := range wr.sections {
		if sec.Type == elf.SHT_REL || sec.Type == elf.SHT_RELA {
			sec.Link = symtabSec.index
		}
	}
	if wr.err != nil {
		return wr.err
	}

	return wr.emit(bo, cl, nameRefs, shstrtabSec, usedGNU)
}

// resolveRelocFormat picks REL or RELA and checks that the machinery the
// choice needs is present.
func (wr *Writer) resolveRelocFormat() (elf.RelocFormat, error) {
	form := wr.opts.RelocFormat
	if form == elf.RelocAuto {
		if wr.opts.Target.Machine().UsesREL() {
			form = elf.RelocREL
		} else {
			form = elf.RelocRELA
		}
	}
	if form == elf.RelocREL && wr.opts.RELEncoder == nil && wr.hasRelocs() {
		return form, fmt.Errorf(
			"obj: %v uses REL relocations, whose addends must be encoded into instruction fields; "+
				"set Options.RELEncoder from the %v backend",
			wr.opts.Target.Machine(), wr.opts.Target.Arch)
	}
	return form, nil
}

func (wr *Writer) hasRelocs() bool {
	for _, sec := range wr.sections {
		if len(sec.relocs) != 0 {
			return true
		}
	}
	return false
}

// orderSymbols sorts symbols local-first, assigns indexes, and reports the
// index of the first non-local symbol along with whether any GNU extension
// was used.
//
// The local-first ordering is required: sh_info of a symbol table is the index
// of its first non-local entry, and that only describes a partition if the
// table is actually partitioned. The sort is stable, so an STT_FILE symbol
// added first stays first among the locals, as convention expects.
func (wr *Writer) orderSymbols() (firstNonLocal uint32, usedGNU bool) {
	sort.SliceStable(wr.symbols, func(i, j int) bool {
		return wr.symbols[i].def.Bind == elf.STB_LOCAL &&
			wr.symbols[j].def.Bind != elf.STB_LOCAL
	})

	// Index 0 is the reserved null symbol, so real symbols start at 1.
	for i, s := range wr.symbols {
		s.index = uint32(i + 1)
		if s.def.Bind == elf.STB_GNU_UNIQUE || s.def.Type == elf.STT_GNU_IFUNC {
			usedGNU = true
		}
	}

	firstNonLocal = uint32(len(wr.symbols) + 1)
	for i, s := range wr.symbols {
		if s.def.Bind != elf.STB_LOCAL {
			firstNonLocal = uint32(i + 1)
			break
		}
	}
	return firstNonLocal, usedGNU
}

// depositAddends writes each REL relocation's addend into the target section's
// contents through the backend encoder.
func (wr *Writer) depositAddends() error {
	enc := wr.opts.RELEncoder
	for _, sec := range wr.sections {
		if len(sec.relocs) == 0 {
			continue
		}
		if sec.Type == elf.SHT_NOBITS {
			return fmt.Errorf(
				"obj: section %q is SHT_NOBITS and has no contents to hold the implicit addends its %d relocations need",
				sec.Name, len(sec.relocs))
		}
		content := sec.buf.Bytes()
		for _, r := range sec.relocs {
			if r.Offset >= uint64(len(content)) {
				return fmt.Errorf("obj: relocation at %#x in %q is past the section's %d bytes",
					r.Offset, sec.Name, len(content))
			}
			if err := enc.EncodeAddend(content, r.Offset, r.Type, r.Addend); err != nil {
				return fmt.Errorf("obj: encoding addend at %#x in %q: %w", r.Offset, sec.Name, err)
			}
		}
	}
	return nil
}

// emitRelocSection creates and fills the .rel or .rela section for target.
func (wr *Writer) emitRelocSection(target *SectionBuilder, rela bool) {
	cl := wr.class()

	typ, prefix, stride := elf.SHT_REL, ".rel", format.RelSize(cl)
	if rela {
		typ, prefix, stride = elf.SHT_RELA, ".rela", format.RelaSize(cl)
	}

	rs := wr.Section(SectionHeader{
		Name:      prefix + target.Name,
		Type:      typ,
		Flags:     elf.SHF_INFO_LINK,
		Addralign: wordAlign(cl),
		Entsize:   uint64(stride),
	})
	// sh_info names the section these relocations apply to. Link is set once
	// the symbol table has an index.
	rs.InfoSection = target

	for _, r := range target.relocs {
		if rela {
			var e format.Rela
			e.Off = r.Offset
			e.SetInfo(cl, r.Sym.Index(), r.Type)
			e.Addend = r.Addend
			e.Encode(rs.buf, cl)
			continue
		}
		var e format.Rel
		e.Off = r.Offset
		e.SetInfo(cl, r.Sym.Index(), r.Type)
		e.Encode(rs.buf, cl)
	}
}

// writeSymtab fills .symtab, .strtab, and the extended index table.
func (wr *Writer) writeSymtab(symtabSec, strtabSec, shndxSec *SectionBuilder, cl elf.Class) error {
	strB := strtab.NewELF()
	refs := make([]*strtab.Ref, len(wr.symbols))
	for i, s := range wr.symbols {
		refs[i] = strB.Add(s.def.Name)
	}
	strtabSec.buf.Write(strB.Finish())

	// Entry 0 is the reserved all-zero symbol.
	var null format.Sym
	null.Encode(symtabSec.buf, cl)

	var shndxTab []uint32
	if shndxSec != nil {
		shndxTab = make([]uint32, len(wr.symbols)+1)
	}

	for i, s := range wr.symbols {
		idx, err := sectionIndexOf(s)
		if err != nil {
			return err
		}

		shndx := uint16(idx)
		if idx >= elf.SHN_LORESERVE_IDX &&
			idx != elf.SHN_ABS_IDX && idx != elf.SHN_COMMON_IDX {
			if shndxTab == nil {
				return fmt.Errorf(
					"obj: symbol %q names section %d, past SHN_LORESERVE, with no SHT_SYMTAB_SHNDX table",
					s.def.Name, idx)
			}
			shndx = elf.SHN_XINDEX_IDX
			shndxTab[i+1] = idx
		}

		var e format.Sym
		e.Name = refs[i].Offset()
		e.SetInfo(s.def.Bind, s.def.Type)
		e.Other = s.def.Other
		e.Shndx = shndx
		e.Value = s.def.Value
		e.Size = s.def.Size
		e.Encode(symtabSec.buf, cl)
	}

	if shndxSec != nil {
		for _, v := range shndxTab {
			shndxSec.buf.U32(v)
		}
	}
	return nil
}

// sectionIndexOf resolves a symbol's placement to a section index.
func sectionIndexOf(s *symbol) (uint32, error) {
	switch s.def.Where {
	case SymUndefined:
		return elf.SHN_UNDEF_IDX, nil
	case SymAbsolute:
		return elf.SHN_ABS_IDX, nil
	case SymCommon:
		return elf.SHN_COMMON_IDX, nil
	case SymInSection:
		if !s.def.Section.indexed {
			return 0, fmt.Errorf("obj: symbol %q names a section that was never added to this writer",
				s.def.Name)
		}
		return s.def.Section.index, nil
	}
	return 0, fmt.Errorf("obj: symbol %q has an unknown placement %d", s.def.Name, s.def.Where)
}

// writeGroups fills each SHT_GROUP section, now that member indexes exist.
func (wr *Writer) writeGroups(symtabSec *SectionBuilder) error {
	for _, g := range wr.groups {
		g.sec.buf.U32(g.flags)
		for _, m := range g.members {
			if m == nil {
				return fmt.Errorf("obj: group %q has a nil member", g.sec.Name)
			}
			if !m.indexed {
				return fmt.Errorf("obj: group %q names a section that was never added to this writer",
					g.sec.Name)
			}
			g.sec.buf.U32(m.index)
		}
		g.sec.Link = symtabSec.index
		g.sec.Info = g.signature.Index()
		if g.flags&elf.GRP_COMDAT != 0 && !g.signature.Valid() {
			return fmt.Errorf("obj: COMDAT group %q has no signature symbol, so it has no deduplication key",
				g.sec.Name)
		}
	}
	return nil
}

// emit lays the file out and writes it.
func (wr *Writer) emit(bo binary.ByteOrder, cl elf.Class,
	nameRefs map[*SectionBuilder]*strtab.Ref, shstrtabSec *SectionBuilder, usedGNU bool) error {

	ehdrSize := format.EhdrSize(cl)
	shdrSize := format.ShdrSize(cl)

	out := binio.NewBuf(bo)
	out.Zero(ehdrSize)

	offsets := make([]uint64, len(wr.sections))
	for i, sec := range wr.sections {
		align := int(sec.Addralign)
		if align > 1 {
			out.Align(align)
		}
		offsets[i] = uint64(out.Len())
		if sec.Type != elf.SHT_NOBITS {
			out.Write(sec.buf.Bytes())
		}
	}

	out.Align(int(wordAlign(cl)))
	shoff := uint64(out.Len())

	// Section header zero is both a null entry and the escape hatch for the
	// two header fields too narrow to hold large values: sh_size carries the
	// section count when e_shnum cannot, and sh_link the .shstrtab index when
	// e_shstrndx cannot.
	shnum := len(wr.sections) + 1
	eShnum := uint16(shnum)
	var nullSize uint64
	if shnum >= elf.SHN_LORESERVE_IDX {
		eShnum = 0
		nullSize = uint64(shnum)
	}

	shstrndx := shstrtabSec.index
	eShstrndx := uint16(shstrndx)
	var nullLink uint32
	if shstrndx >= elf.SHN_LORESERVE_IDX {
		eShstrndx = elf.SHN_XINDEX_IDX
		nullLink = shstrndx
	}

	null := format.Shdr{Type: elf.SHT_NULL, Size: nullSize, Link: nullLink}
	null.Encode(out, cl)

	for i, sec := range wr.sections {
		sh := format.Shdr{
			Name:      nameRefs[sec].Offset(),
			Type:      sec.Type,
			Flags:     sec.Flags,
			Off:       offsets[i],
			Size:      sec.contentSize(),
			Link:      sec.Link,
			Info:      sec.Info,
			Addralign: sec.Addralign,
			Entsize:   sec.Entsize,
		}
		if sec.LinkTo != nil {
			sh.Link = sec.LinkTo.index
		}
		if sec.InfoSection != nil {
			sh.Info = sec.InfoSection.index
		}
		sh.Encode(out, cl)
	}

	eh := format.Ehdr{
		Ident: format.Ident{
			Class:      cl,
			Data:       wr.opts.Target.Data(),
			Version:    elf.EV_CURRENT,
			OSABI:      wr.opts.Target.OSABI(usedGNU),
			ABIVersion: wr.opts.ABIVersion,
		},
		Type:     elf.ET_REL,
		Machine:  wr.opts.Target.Machine(),
		Version:  elf.EV_CURRENT,
		Shoff:    shoff,
		Flags:    wr.opts.Target.Flags,
		Shnum:    eShnum,
		Shstrndx: eShstrndx,
	}
	hdr := binio.NewBufSize(bo, ehdrSize)
	eh.Encode(hdr)
	if hdr.Len() != ehdrSize {
		return fmt.Errorf("obj: internal: header encoded to %d bytes, want %d", hdr.Len(), ehdrSize)
	}
	copy(out.Bytes()[:ehdrSize], hdr.Bytes())

	_ = shdrSize // sizes come from format; kept here only for the shoff alignment intent

	_, err := out.WriteTo(wr.w)
	return err
}

// wordAlign is the natural alignment for tables of class-width words.
func wordAlign(cl elf.Class) uint64 {
	if cl.Wide() {
		return 8
	}
	return 4
}