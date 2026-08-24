package link

import (
	"encoding/binary"
	"fmt"

	"github.com/vertex-language/elf"
	"github.com/vertex-language/elf/image"
	"github.com/vertex-language/elf/internal/binio"
	"github.com/vertex-language/elf/internal/format"
	"github.com/vertex-language/elf/internal/strtab"
)

// registerSynthetics places the linker-generated chunks and builds the symbol
// and string tables.
//
// It is the last step that creates an output section, which is what lets
// ordering run without adding anything and the image be sealed straight
// afterward. The RELRO padding is created here rather than during ordering for
// that reason: a section appearing after .shstrtab has been laid out would
// have no name in it.
func (l *Linker) registerSynthetics(img *image.Image) error {
	in := &image.Input{Name: "<linker>", Target: img.Target}
	img.AddInput(in)

	// Scan created .got, .plt, and friends; they have chunks but no home.
	for _, syn := range img.Synthetics {
		ch := syn.Chunk
		if ch.Out != nil {
			continue
		}
		in.AddChunk(ch)
		img.Section(ch.Name, ch.Type, ch.Flags).Add(ch)
	}

	if l.opts.Relro != RelroNone {
		// Created unconditionally when RELRO is on. An empty one costs a
		// section header; deciding later costs the ordering invariant above.
		pad := img.Section(relroPadName, elf.SHT_NOBITS,
			image.SecFlags(elf.SHF_ALLOC|elf.SHF_WRITE))
		pad.Align = 1
	}

	if l.opts.StripAll {
		return nil
	}
	return l.buildSymtab(img, in)
}

// buildSymtab creates .symtab, .strtab, and .shstrtab.
//
// Symbols are ordered local-first, because sh_info of a symbol table is the
// index of its first non-local entry and that only describes a partition if
// the table is actually partitioned.
func (l *Linker) buildSymtab(img *image.Image, in *image.Input) error {
	var locals, globals []*image.Sym

	for _, fin := range img.Inputs {
		for _, s := range fin.Syms {
			if s == nil || s.Name == "" || !s.Local() || !s.Live() {
				continue
			}
			if s.Type == elf.STT_SECTION || s.Type == elf.STT_FILE {
				continue
			}
			locals = append(locals, s)
		}
	}
	img.Syms.Each(func(s *image.Sym) {
		if s.Defined() && s.Live() && s.Name != "" {
			globals = append(globals, s)
		}
	})

	l.outSyms = append(locals, globals...)

	b := strtab.NewELF()
	refs := make([]*strtab.Ref, len(l.outSyms))
	for i, s := range l.outSyms {
		refs[i] = b.Add(s.Name)
	}
	blob := b.Finish()

	l.symNames = make(map[*image.Sym]uint32, len(l.outSyms))
	for i, s := range l.outSyms {
		l.symNames[s] = refs[i].Offset()
	}

	cl := img.Target.Class

	strSec := image.NewSynthetic(".strtab", elf.SHT_STRTAB, 0, 1, 0,
		func(*image.Image) ([]byte, error) { return blob, nil })
	strSec.SetSize(img, uint64(len(blob)))
	img.AddSynthetic(strSec)
	l.strSec = strSec

	symSec := image.NewSynthetic(".symtab", elf.SHT_SYMTAB, 0,
		wordAlign(cl), uint64(format.SymSize(cl)), l.genSymtab)
	symSec.SetSize(img, uint64(len(l.outSyms)+1)*uint64(format.SymSize(cl)))
	img.AddSynthetic(symSec)
	l.symSec = symSec

	shSec := image.NewSynthetic(".shstrtab", elf.SHT_STRTAB, 0, 1, 0, nil)
	img.AddSynthetic(shSec)
	l.shstrSec = shSec

	// Placed before the section-name table is built, so that their own names
	// are in it.
	for _, syn := range []*image.Synthetic{strSec, symSec, shSec} {
		in.AddChunk(syn.Chunk)
		img.Section(syn.Chunk.Name, syn.Chunk.Type, syn.Chunk.Flags).Add(syn.Chunk)
	}

	l.buildShstrtab(img)

	if sym := img.FindSection(".symtab"); sym != nil {
		sym.LinkTo = img.FindSection(".strtab")
	}
	return nil
}

// buildShstrtab lays out the section name table.
//
// Every output section exists by now — the RELRO padding included — so the
// blob is final and its length can be declared before layout runs.
func (l *Linker) buildShstrtab(img *image.Image) {
	b := strtab.NewELF()
	l.shNames = make(map[*image.OutputSection]*strtab.Ref, len(img.Sections))
	for _, s := range img.Sections {
		l.shNames[s] = b.Add(s.Name)
	}
	blob := b.Finish()

	l.shstrSec.Chunk.SetData(blob)
	l.shstrSec.SetSize(img, uint64(len(blob)))
}

// genSymtab writes the symbol table, after addresses are final.
func (l *Linker) genSymtab(img *image.Image) ([]byte, error) {
	cl := img.Target.Class
	b := binio.NewBufSize(outputOrder(img.Target),
		(len(l.outSyms)+1)*format.SymSize(cl))

	// Entry zero is the reserved all-zero symbol.
	var null format.Sym
	null.Encode(b, cl)

	for _, s := range l.outSyms {
		var e format.Sym
		e.Name = l.symNames[s]
		e.SetInfo(s.Bind, s.Type)
		e.Other = s.Other
		e.Size = s.Size

		switch s.Class {
		case image.SymAbsolute:
			e.Shndx = elf.SHN_ABS_IDX
			e.Value = s.Value
		case image.SymRegular:
			e.Value = s.Addr()
			if s.Chunk != nil && s.Chunk.Out != nil {
				e.Shndx = uint16(s.Chunk.Out.Index)
			}
			if s.Frag != nil {
				w := s.Frag.Winner()
				if w.Out != nil && w.Out.Out != nil {
					e.Shndx = uint16(w.Out.Out.Index)
				}
			}
		default:
			e.Shndx = elf.SHN_UNDEF_IDX
		}
		e.Encode(b, cl)
	}
	return b.Bytes(), nil
}

// bind resolves the values that depend on addresses. It runs once per round of
// the layout fixpoint, so it must recompute rather than accumulate.
func (l *Linker) bind(img *image.Image) error {
	for name, expr := range l.opts.Provide {
		s := img.Syms.Lookup(name)
		if s == nil {
			continue
		}
		sec := img.FindSection(expr.Section)
		if sec == nil {
			continue
		}
		v := uint64(int64(sec.Bound(expr.At)) + expr.Offset)
		if expr.Align > 1 {
			v = alignUp(v, expr.Align)
		}
		s.Class = image.SymAbsolute
		s.Value = v
	}

	if img.EntrySym != nil {
		img.Entry = img.EntrySym.Addr()
	} else if l.opts.EntryAddr != 0 {
		img.Entry = l.opts.EntryAddr
	}
	return nil
}

// commit finalises everything that must not change again: section indexes and
// the checks that depend on them.
func (l *Linker) commit(img *image.Image) error {
	// Index 0 is the null section header, so real sections start at 1.
	for i, s := range img.Sections {
		s.Index = uint32(i + 1)
	}

	if l.opts.Output != OutputRelocatable && img.Entry == 0 && l.opts.EntryAddr == 0 {
		if !l.opts.AllowUndefined {
			return fmt.Errorf("link: %q: %w", l.opts.entryName(), ErrNoEntry)
		}
	}
	return nil
}

// bindDynamic fills in the dynamic linking structures.
//
// A static link has none, which is the whole of this function until
// link/dynamic.go lands with M5.
func (l *Linker) bindDynamic(img *image.Image) error {
	if !l.reqs.Dynamic {
		return nil
	}
	return fmt.Errorf("link: dynamic output is not implemented yet")
}

// emit writes the ELF header, the program headers, and the section header
// table into the output buffer.
//
// Everything goes through internal/format. No literal structure size appears
// here, which is what keeps the one definition of the wire format actually
// singular.
func (l *Linker) emit(img *image.Image) error {
	cl := img.Target.Class
	ord := outputOrder(img.Target)

	if err := l.emitPhdrs(img, cl, ord); err != nil {
		return err
	}
	if err := l.emitShdrs(img, cl, ord); err != nil {
		return err
	}
	return l.emitEhdr(img, cl, ord)
}

func (l *Linker) emitEhdr(img *image.Image, cl elf.Class, ord binary.ByteOrder) error {
	eh := format.Ehdr{
		Ident: format.Ident{
			Class:   cl,
			Data:    img.Target.Data(),
			Version: elf.EV_CURRENT,
			OSABI:   img.Target.OSABI(l.usedGNU(img)),
		},
		Type:     img.Type,
		Machine:  img.Target.Machine(),
		Version:  elf.EV_CURRENT,
		Entry:    img.Entry,
		Flags:    img.Target.Flags,
		Shoff:    img.Shoff,
		Shstrndx: uint16(sectionIndex(img, ".shstrtab")),
	}
	if n := len(img.Segments); n > 0 {
		eh.Phoff = uint64(format.EhdrSize(cl))
		eh.Phnum = uint16(n)
	}

	shnum := len(img.Sections) + 1
	if shnum >= elf.SHN_LORESERVE_IDX {
		// e_shnum is too narrow; the real count lives in sh_size of section
		// header zero, which emitShdrs has already written.
		eh.Shnum = 0
	} else {
		eh.Shnum = uint16(shnum)
	}
	if eh.Shstrndx >= elf.SHN_LORESERVE_IDX {
		eh.Shstrndx = elf.SHN_XINDEX_IDX
	}

	b := binio.NewBufSize(ord, format.EhdrSize(cl))
	eh.Encode(b)
	if b.Len() != format.EhdrSize(cl) {
		return fmt.Errorf("link: internal: header encoded to %d bytes, want %d",
			b.Len(), format.EhdrSize(cl))
	}
	return img.CopyAt(0, b.Bytes())
}

func (l *Linker) emitPhdrs(img *image.Image, cl elf.Class, ord binary.ByteOrder) error {
	if len(img.Segments) == 0 {
		return nil
	}
	b := binio.NewBufSize(ord, len(img.Segments)*format.PhdrSize(cl))
	for _, seg := range img.Segments {
		p := format.Phdr{
			Type:   seg.Type,
			Flags:  uint32(seg.Flags),
			Off:    seg.Off,
			Vaddr:  seg.Vaddr,
			Paddr:  seg.Paddr,
			Filesz: seg.Filesz,
			Memsz:  seg.Memsz,
			Align:  seg.Align,
		}
		p.Encode(b, cl)
	}
	return img.CopyAt(uint64(format.EhdrSize(cl)), b.Bytes())
}

func (l *Linker) emitShdrs(img *image.Image, cl elf.Class, ord binary.ByteOrder) error {
	b := binio.NewBufSize(ord, (len(img.Sections)+1)*format.ShdrSize(cl))

	// Section header zero is both the null entry and the escape hatch for
	// the two header fields too narrow to hold large values.
	shnum := len(img.Sections) + 1
	null := format.Shdr{Type: elf.SHT_NULL}
	if shnum >= elf.SHN_LORESERVE_IDX {
		null.Size = uint64(shnum)
	}
	if idx := sectionIndex(img, ".shstrtab"); idx >= elf.SHN_LORESERVE_IDX {
		null.Link = idx
	}
	null.Encode(b, cl)

	for _, s := range img.Sections {
		sh := format.Shdr{
			Type:      s.Type,
			Flags:     uint64(s.Flags),
			Addr:      s.Addr,
			Off:       s.Off,
			Size:      s.Size,
			Link:      s.Link,
			Info:      s.Info,
			Addralign: s.Align,
			Entsize:   s.Entsize,
		}
		if ref, ok := l.shNames[s]; ok {
			sh.Name = ref.Offset()
		}
		if s.LinkTo != nil {
			sh.Link = s.LinkTo.Index
		}
		if s.InfoTo != nil {
			sh.Info = s.InfoTo.Index
		}
		if s.Name == ".symtab" {
			sh.Info = l.firstNonLocal()
		}
		sh.Encode(b, cl)
	}
	return img.CopyAt(img.Shoff, b.Bytes())
}

// firstNonLocal is sh_info of the symbol table: the index of its first
// non-local entry.
func (l *Linker) firstNonLocal() uint32 {
	for i, s := range l.outSyms {
		if !s.Local() {
			return uint32(i + 1)
		}
	}
	return uint32(len(l.outSyms) + 1)
}

// usedGNU reports whether the output contains a GNU extension, which is the
// only thing that forces ELFOSABI_GNU. The triple does not decide it.
func (l *Linker) usedGNU(img *image.Image) bool {
	used := false
	img.Syms.Each(func(s *image.Sym) {
		if s.Bind == elf.STB_GNU_UNIQUE || s.Type == elf.STT_GNU_IFUNC {
			used = true
		}
	})
	return used
}

func sectionIndex(img *image.Image, name string) uint32 {
	if s := img.FindSection(name); s != nil {
		return s.Index
	}
	return 0
}