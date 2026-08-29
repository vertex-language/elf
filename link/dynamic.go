package link

import (
	"encoding/binary"
	"fmt"

	"github.com/vertex-language/elf"
	"github.com/vertex-language/elf/backend"
	"github.com/vertex-language/elf/image"
	"github.com/vertex-language/elf/internal/binio"
	"github.com/vertex-language/elf/internal/format"
	"github.com/vertex-language/elf/internal/strtab"
)

// Dynamic linking output.
//
// This file is the M5 milestone bindDynamic's doc comment in emit.go used to
// promise: .dynsym, .dynstr, a SysV .hash, .rela.dyn, .rela.plt, .dynamic,
// .interp, and the GOT/PLT content that all of it depends on. Two things run
// in two different pipeline phases:
//
//   - wireGotPlt runs right after Backend.Scan, while sections may still be
//     created and sized. It decides, for every symbol with a GOT or PLT slot,
//     whether that slot is filled by a dynamic relocation or a value the
//     linker can bake in directly, and queues the relocation when it is the
//     former. This runs unconditionally, dynamic output or not: a static,
//     non-PIC link can still have an unrelaxed GOT load, and something has
//     to put the right address in that slot.
//
//   - registerDynamicSections runs from registerSynthetics, also before Seal,
//     and only when the output is dynamic. It decides the .dynsym membership
//     and .dynamic tag list — both fixed by what symbols and relocations
//     exist, not by their final addresses — and gives every new section a
//     generator that resolves the address-dependent parts once layout has
//     run.
//
// Initial-exec TLS GOT content is generated via backend.TlsOffsetter when a
// reference resolves inside this link's own PT_TLS, and via a dynamic TPREL
// relocation when it does not.
//
// .rela.dyn/.rela.plt and .rel.dyn/.rel.plt are both handled: a REL
// architecture's own psABI drops the explicit addend field, so a
// RELATIVE or IRELATIVE relocation's value must already be sitting in the
// memory it targets before generation ever writes an entry — generateGot and
// generateGotPlt pre-fill those slots for a REL target instead of leaving
// them zero, and generateRelocs writes format.Rel rather than format.Rela.
// Symbol-based kinds (GLOB_DAT, JUMP_SLOT, COPY, TPOFF) need no such
// pre-fill on either format.
//
// Deliberately out of scope, and left as a clear generation-time error rather
// than a wrong answer: general- and local-dynamic TLS and TLSDESC (neither
// backend's Apply implements them either), GNU hash and symbol versioning,
// and --as-needed's full precision (a shared input is kept unless nothing it
// defines was ever referenced, which is close but not identical to "nothing
// in the final, GC'd output resolved to it").
type dynEntry struct {
	tag elf.DynTag
	val uint64
	sec *image.Synthetic
	off uint64
}

// wireGotPlt decides how every GOT and PLT slot gets its content and attaches
// the generators that write it.
//
// It must run after Backend.Scan, so every slot Scan is going to assign has
// been assigned, and before registerSynthetics, so the RelaDyn and RelaPlt
// counts it may add to are final by the time .rela.dyn and .rela.plt are
// sized.
func (l *Linker) wireGotPlt(img *image.Image) error {
	reqs := l.reqs
	dynFilled := make(map[*image.Sym]backend.DynKind)

	img.Syms.Each(func(sym *image.Sym) {
		switch {
		case sym.GotIndex != image.NoIndex && sym.Has(image.NeedsTlsGd):
			// General-dynamic, local-dynamic, and TLSDESC references share
			// this slot shape. None of them are wired here; see the package
			// doc.

		case sym.GotIndex != image.NoIndex && sym.Has(image.NeedsTlsIe):
			// A symbol this link cannot resolve to a definition of its own —
			// imported from a shared object, or simply undefined — has its
			// tpoff computed by the loader: its home module and TLS block
			// are not something this link's own PT_TLS describes. Everything
			// else is resolved to a byte inside that PT_TLS, and its tpoff is
			// a plain number available the moment TpOff exists, dynamic
			// output or not.
			if sym.Class == image.SymShared || !sym.Defined() {
				if reqs.Dynamic {
					reqs.AddDyn(backend.DynReloc{
						Kind: backend.DynTpOff, Sym: sym,
						Slot: reqs.Got, Off: uint64(sym.GotIndex) * reqs.GotShape().EntrySize,
					})
					dynFilled[sym] = backend.DynTpOff
				}
				// Left unfilled otherwise: a static link has no loader to
				// defer this to, and no module of its own supplies the
				// value either. generateGot reports the gap.
			}

		case sym.GotIndex != image.NoIndex:
			if needsRuntimeLookup(reqs, sym) {
				reqs.AddDyn(backend.DynReloc{
					Kind: backend.DynGlobDat, Sym: sym,
					Slot: reqs.Got, Off: uint64(sym.GotIndex) * reqs.GotShape().EntrySize,
				})
				dynFilled[sym] = backend.DynGlobDat
			} else if reqs.Pic {
				reqs.AddDyn(backend.DynReloc{
					Kind: backend.DynRelative, Sym: sym,
					Slot: reqs.Got, Off: uint64(sym.GotIndex) * reqs.GotShape().EntrySize,
				})
				dynFilled[sym] = backend.DynRelative
			}
			// Otherwise left for direct fill: a non-PIC output has this
			// symbol's address available at link time.
		}

		if sym.PltIndex != image.NoIndex {
			kind := backend.DynJumpSlot
			if sym.Type == elf.STT_GNU_IFUNC {
				kind = backend.DynIRelative
			}
			if !reqs.Dynamic {
				// needsPlt gates ordinary PLT entries on reqs.Dynamic, but an
				// ifunc gets one unconditionally for static ifunc support —
				// which needs .rela.iplt and __rela_iplt_start/_end, neither
				// implemented here yet.
				return
			}
			reqs.AddDyn(backend.DynReloc{
				Kind: kind, Sym: sym,
				Slot: reqs.GotPlt, Off: uint64(sym.GotPltIndex) * reqs.GotShape().EntrySize,
			})
		}
	})

	if reqs.Got != nil {
		reqs.Got.SetGen(func(img *image.Image) ([]byte, error) {
			return l.generateGot(img, dynFilled)
		})
	}
	if reqs.GotPlt != nil {
		reqs.GotPlt.SetGen(func(img *image.Image) ([]byte, error) { return l.generateGotPlt(img) })
	}
	d, ok := backend.AsDynamic(l.be)
	if !ok {
		if reqs.Plt != nil || reqs.GotPlt != nil || reqs.IPlt != nil {
			// A PLT was allocated — something Scan decided needed one — but
			// this backend cannot fill it in. Left alone, Synthetic.Generate
			// treats a nil generator as "no content" and the section reaches
			// the file as all zeroes: a PLT that silently jumps through a
			// null pointer on its first call, and no error anywhere to say
			// why. Reaching this point means link and this backend disagree
			// about what it supports, and that is a configuration mistake
			// worth failing loudly on rather than shipping a broken binary.
			return fmt.Errorf("link: %v has a procedure linkage table but no backend.Dynamic implementation to fill it",
				l.be.Arch())
		}
		return nil
	}
	if reqs.Plt != nil {
		reqs.Plt.SetGen(func(img *image.Image) ([]byte, error) { return l.generatePlt(img, d) })
	}
	if reqs.SecPlt != nil {
		reqs.SecPlt.SetGen(func(img *image.Image) ([]byte, error) { return l.generateSecPlt(img, d) })
	}
	if reqs.IPlt != nil {
		reqs.IPlt.SetGen(func(img *image.Image) ([]byte, error) { return l.generateIPlt(img, d) })
	}
	return nil
}

// processCopyRelocs gives every symbol Scan queued a copy relocation for its
// own storage in .bss, redirects the symbol to it, and queues the dynamic
// relocation that makes the loader fill it in before the program runs.
//
// It must run after Backend.Scan, which is what decides reqs.Copy, and
// before registerSynthetics, which sizes .rela.dyn from the relocations
// queued here. It runs after merge's own .bss allocation for common symbols,
// which is unavoidable — a copy relocation is not known to be needed until
// Scan sees the reference — so this chunk joins that section as a second
// contribution rather than growing the first.
func (l *Linker) processCopyRelocs(img *image.Image) error {
	syms := l.reqs.Copy
	if len(syms) == 0 {
		return nil
	}

	in := &image.Input{Name: "<copy>", Target: img.Target}
	img.AddInput(in)

	var size, maxAlign uint64 = 0, 1
	offs := make([]uint64, len(syms))
	for i, s := range syms {
		align := copyAlign(s)
		if align > maxAlign {
			maxAlign = align
		}
		size = alignUp(size, align)
		offs[i] = size
		size += s.Size
	}

	ch := image.NewChunk(".bss", elf.SHT_NOBITS,
		image.SecFlags(elf.SHF_ALLOC|elf.SHF_WRITE), maxAlign, size, nil)
	ch.Reachable = true
	in.AddChunk(ch)
	img.Section(ch.Name, ch.Type, ch.Flags).Add(ch)

	for i, s := range syms {
		// The symbol keeps its name, dynamic-symbol eligibility, and every
		// existing reference — only where it points changes. A defined
		// dynsym entry for it, once generateDynsym runs, is exactly what a
		// copy relocation is supposed to produce: this output becomes the
		// symbol's new, authoritative home, so that another shared object
		// loaded afterward and referencing the same name is interposed onto
		// this copy rather than the library's own storage.
		s.Class = image.SymRegular
		s.Chunk = ch
		s.Value = offs[i]
		s.Input = in

		l.reqs.AddDyn(backend.DynReloc{
			Kind: backend.DynCopy, Sym: s,
			Chunk: ch, Off: offs[i],
		})
	}
	return nil
}

// copyAlign estimates the alignment a copy-relocated symbol's storage needs.
//
// Nothing in an ELF symbol table records a symbol's alignment directly —
// only sh_addralign, which describes a whole section — so this falls back to
// every general-purpose linker's own heuristic: the number of trailing zero
// bits in the symbol's original address is the alignment the section that
// defined it was actually built to, capped at a reasonable maximum so one
// suspiciously round address does not demand a multi-megabyte alignment.
func copyAlign(sym *image.Sym) uint64 {
	const max = 16
	v := sym.Value
	if v == 0 {
		return max
	}
	align := v & -v
	if align > max {
		align = max
	}
	return align
}

// needsRuntimeLookup reports whether a GOT slot's value can only be known by
// the dynamic loader: the symbol is imported, unresolved, or preemptible in
// an output the loader might load alongside a component that overrides it.
func needsRuntimeLookup(reqs *backend.Reqs, sym *image.Sym) bool {
	if !reqs.Dynamic {
		return false
	}
	return sym.Class == image.SymShared || !sym.Defined() || sym.Preemptible()
}

// generateGot fills .got: a resolved address (or, for initial-exec TLS, a
// thread-pointer offset) for a slot nothing dynamic will touch, zero for one
// a queued relocation will overwrite at load time on a RELA architecture.
//
// A REL architecture is the exception: its dynamic relocation entries have
// no addend field, so a RELATIVE (or IRELATIVE) relocation's value must
// already be sitting in the memory it targets before the loader adds its
// load bias — the addend that would carry it on RELA has nowhere else to
// live. GLOB_DAT, JUMP_SLOT, COPY, and TPOFF need no such pre-fill on either
// format: the loader replaces their slot outright rather than adding to it.
func (l *Linker) generateGot(img *image.Image, dynFilled map[*image.Sym]backend.DynKind) ([]byte, error) {
	reqs := l.reqs
	buf := make([]byte, reqs.Got.Chunk.Size)
	ord := outputOrder(img.Target)
	entrySize := reqs.GotShape().EntrySize
	tls, hasTls := backend.AsTlsOffsetter(l.be)
	rel := img.Target.Machine().UsesREL()

	var err error
	img.Syms.Each(func(sym *image.Sym) {
		if err != nil || sym.GotIndex == image.NoIndex || sym.Has(image.NeedsTlsGd) {
			return
		}
		off := uint64(sym.GotIndex) * entrySize
		if kind, ok := dynFilled[sym]; ok {
			if rel && relocIsAddressBased(kind) {
				putWord(buf[off:], ord, sym.Addr(), entrySize)
			}
			return // Otherwise zero until the loader writes it.
		}
		if sym.Has(image.NeedsTlsIe) {
			if !hasTls {
				err = fmt.Errorf("link: %s: %v has no TpOff to fill an initial-exec GOT slot",
					sym, l.be.Arch())
				return
			}
			if reqs.TlsSize == 0 {
				err = fmt.Errorf("link: %s: initial-exec TLS reference in an output with no TLS block", sym)
				return
			}
			v := tls.TpOff(reqs.TlsAddr, reqs.TlsSize, reqs.TlsAlign, sym.Addr())
			putWord(buf[off:], ord, uint64(v), entrySize)
			return
		}
		putWord(buf[off:], ord, sym.Addr(), entrySize)
	})
	return buf, err
}

// generateGotPlt fills .got.plt: the reserved loader-owned prefix, then one
// slot per PLT entry.
func (l *Linker) generateGotPlt(img *image.Image) ([]byte, error) {
	reqs := l.reqs
	d, ok := backend.AsDynamic(l.be)
	if !ok {
		return nil, fmt.Errorf("link: .got.plt exists but %v has no Dynamic support", l.be.Arch())
	}
	buf := make([]byte, reqs.GotPlt.Chunk.Size)

	site := l.dynSite(img, reqs.GotPlt.Chunk)
	hdrSize := reqs.GotShape().GotPltHeaderSize()
	if hdrSize > 0 {
		if err := d.WriteGotPltHeader(buf[:hdrSize], site); err != nil {
			return nil, err
		}
	}

	entrySize := reqs.GotShape().EntrySize
	var err error
	img.Syms.Each(func(sym *image.Sym) {
		if err != nil || sym.GotPltIndex == image.NoIndex {
			return
		}
		off := uint64(sym.GotPltIndex) * entrySize
		err = d.WriteGotPlt(buf[off:off+entrySize], site, sym)
	})
	return buf, err
}

// generatePlt fills .plt: PLT0 followed by one entry per non-ifunc PLT slot.
func (l *Linker) generatePlt(img *image.Image, d backend.Dynamic) ([]byte, error) {
	reqs := l.reqs
	shape := d.Plt()
	buf := make([]byte, reqs.Plt.Chunk.Size)
	site := l.dynSite(img, reqs.Plt.Chunk)

	if shape.HeaderSize > 0 {
		if err := d.WritePltHeader(buf[:shape.HeaderSize], site); err != nil {
			return nil, err
		}
	}

	var err error
	img.Syms.Each(func(sym *image.Sym) {
		if err != nil || sym.PltIndex == image.NoIndex || sym.Type == elf.STT_GNU_IFUNC {
			return
		}
		off := shape.EntryOffset(int(sym.PltIndex))
		gotAddr, e := reqs.GotPltSlotAddr(sym)
		if e != nil {
			err = e
			return
		}
		err = d.WritePlt(buf[off:off+shape.EntrySize], site, sym, reqs.PltAddr()+off, gotAddr, int(sym.PltIndex))
	})
	return buf, err
}

// generateSecPlt fills .plt.sec, the Intel-CET indirect-jump table, for
// formats that have one.
func (l *Linker) generateSecPlt(img *image.Image, d backend.Dynamic) ([]byte, error) {
	reqs := l.reqs
	shape := d.Plt()
	buf := make([]byte, reqs.SecPlt.Chunk.Size)
	site := l.dynSite(img, reqs.SecPlt.Chunk)

	var err error
	img.Syms.Each(func(sym *image.Sym) {
		if err != nil || sym.PltIndex == image.NoIndex || sym.Type == elf.STT_GNU_IFUNC {
			return
		}
		off := uint64(sym.PltIndex) * shape.SecEntrySize
		pltOff := shape.EntryOffset(int(sym.PltIndex))
		gotAddr, e := reqs.GotPltSlotAddr(sym)
		if e != nil {
			err = e
			return
		}
		err = d.WriteSecPlt(buf[off:off+shape.SecEntrySize], site, sym,
			reqs.PltAddr()+pltOff, gotAddr, int(sym.PltIndex))
	})
	return buf, err
}

// generateIPlt fills .iplt, one entry per non-preemptible ifunc.
//
// An ifunc entry has the same shape as an ordinary lazy PLT entry — load its
// .got.plt slot, jump through it — because there is nothing to lazily bind:
// IRELATIVE resolves the slot eagerly, before the program runs, so the entry
// WritePlt writes for a lazy format works unchanged here too.
func (l *Linker) generateIPlt(img *image.Image, d backend.Dynamic) ([]byte, error) {
	reqs := l.reqs
	shape := d.Plt()
	buf := make([]byte, reqs.IPlt.Chunk.Size)
	site := l.dynSite(img, reqs.IPlt.Chunk)

	var err error
	img.Syms.Each(func(sym *image.Sym) {
		if err != nil || sym.PltIndex == image.NoIndex || sym.Type != elf.STT_GNU_IFUNC {
			return
		}
		off := uint64(sym.PltIndex) * shape.IPltEntrySize
		gotAddr, e := reqs.GotPltSlotAddr(sym)
		if e != nil {
			err = e
			return
		}
		err = d.WritePlt(buf[off:off+shape.IPltEntrySize], site, sym,
			reqs.IPlt.Chunk.Addr()+off, gotAddr, int(sym.PltIndex))
	})
	return buf, err
}

// dynSite builds the backend.Site a Dynamic method needs to write into a
// synthetic chunk's own bytes, addressed from the start of that chunk.
func (l *Linker) dynSite(img *image.Image, ch *image.Chunk) *backend.Site {
	return &backend.Site{
		Img: img, Chunk: ch, Data: nil, Addr: ch.Addr(),
		Class: img.Target.Class, Order: outputOrder(img.Target), Reqs: l.reqs,
	}
}

// putWord writes a class-width address, little- or big-endian per the
// target, into a slot the backend never needed to see.
func putWord(b []byte, ord binary.ByteOrder, v, width uint64) {
	if width == 8 {
		ord.PutUint64(b, v)
	} else {
		ord.PutUint32(b, uint32(v))
	}
}

// registerDynamicSections creates and sizes .dynsym, .dynstr, .hash,
// .rela.dyn, .rela.plt, .dynamic, and .interp.
//
// It runs from registerSynthetics, before Seal: everything it decides —
// which symbols are dynamic, how many relocations exist, which .dynamic tags
// apply — depends only on facts Scan and wireGotPlt already settled, never on
// an address.
func (l *Linker) registerDynamicSections(img *image.Image, in *image.Input) error {
	if !l.reqs.Dynamic {
		return nil
	}
	rel := img.Target.Machine().UsesREL()

	l.buildNeeded(img)

	dynSyms := l.collectDynSyms(img)
	dynStr := strtab.NewELF()
	dynRefs := make(map[*image.Sym]*strtab.Ref, len(dynSyms))
	for _, s := range dynSyms {
		dynRefs[s] = dynStr.Add(s.Name)
	}

	// DT_NEEDED, DT_SONAME, DT_RPATH, and DT_RUNPATH point into .dynstr too,
	// so their strings must join the same table before it is finished.
	neededRefs := make([]*strtab.Ref, len(l.reqs.Needed))
	for i, name := range l.reqs.Needed {
		neededRefs[i] = dynStr.Add(name)
	}
	var sonameRef, rpathRef, runpathRef *strtab.Ref
	if l.opts.SOName != "" {
		sonameRef = dynStr.Add(l.opts.SOName)
	}
	if len(l.opts.RPath) > 0 {
		rpathRef = dynStr.Add(joinPath(l.opts.RPath))
	}
	if len(l.opts.RunPath) > 0 {
		runpathRef = dynStr.Add(joinPath(l.opts.RunPath))
	}

	blob := dynStr.Finish()

	cl := img.Target.Class

	dynStrSec := image.NewSynthetic(".dynstr", elf.SHT_STRTAB, image.SecFlags(elf.SHF_ALLOC), 1, 0,
		func(*image.Image) ([]byte, error) { return blob, nil })
	dynStrSec.SetSize(img, uint64(len(blob)))
	img.AddSynthetic(dynStrSec)

	dynSymSec := image.NewSynthetic(".dynsym", elf.SHT_DYNSYM, image.SecFlags(elf.SHF_ALLOC),
		wordAlign(cl), uint64(format.SymSize(cl)), nil)
	dynSymSec.SetSize(img, uint64(len(dynSyms)+1)*uint64(format.SymSize(cl)))
	dynSymSec.SetGen(func(img *image.Image) ([]byte, error) {
		return l.generateDynsym(img, dynSyms, dynRefs)
	})
	img.AddSynthetic(dynSymSec)

	hashSec := image.NewSynthetic(".hash", elf.SHT_HASH, image.SecFlags(elf.SHF_ALLOC), 4, 4, nil)
	hashSec.SetSize(img, hashSize(len(dynSyms)))
	hashSec.SetGen(func(img *image.Image) ([]byte, error) {
		return generateHash(dynSyms, outputOrder(img.Target)), nil
	})
	img.AddSynthetic(hashSec)

	relName, relType := ".rela", elf.SHT_RELA
	relSize := uint64(format.RelaSize(cl))
	if rel {
		relName, relType = ".rel", elf.SHT_REL
		relSize = uint64(format.RelSize(cl))
	}

	var relaDynSec, relaPltSec *image.Synthetic
	if n := len(l.reqs.RelaDyn); n > 0 {
		relaDynSec = image.NewSynthetic(relName+".dyn", relType, image.SecFlags(elf.SHF_ALLOC),
			wordAlign(cl), relSize, nil)
		relaDynSec.SetSize(img, uint64(n)*relSize)
		relaDynSec.SetGen(func(*image.Image) ([]byte, error) {
			return l.generateRelocs(l.reqs.RelaDyn, cl, rel)
		})
		img.AddSynthetic(relaDynSec)
	}
	if n := len(l.reqs.RelaPlt); n > 0 {
		relaPltSec = image.NewSynthetic(relName+".plt", relType, image.SecFlags(elf.SHF_ALLOC),
			wordAlign(cl), relSize, nil)
		relaPltSec.SetSize(img, uint64(n)*relSize)
		relaPltSec.SetGen(func(*image.Image) ([]byte, error) {
			return l.generateRelocs(l.reqs.RelaPlt, cl, rel)
		})
		img.AddSynthetic(relaPltSec)
	}

	var interpSec *image.Synthetic
	if l.needsInterp() {
		interp := l.opts.Interp
		if interp == "" {
			var err error
			interp, err = defaultInterp(img.Target)
			if err != nil {
				return err
			}
		}
		b := append([]byte(interp), 0)
		interpSec = image.NewSynthetic(".interp", elf.SHT_PROGBITS, image.SecFlags(elf.SHF_ALLOC), 1, 0,
			func(*image.Image) ([]byte, error) { return b, nil })
		interpSec.SetSize(img, uint64(len(b)))
		img.AddSynthetic(interpSec)
	}

	entries := l.buildDynEntries(dynStrSec, dynSymSec, hashSec, relaDynSec, relaPltSec, rel,
		neededRefs, sonameRef, rpathRef, runpathRef)
	dynSec := image.NewSynthetic(".dynamic", elf.SHT_DYNAMIC, image.SecFlags(elf.SHF_ALLOC|elf.SHF_WRITE),
		wordAlign(cl), uint64(format.DynSize(cl)), nil)
	dynSec.SetSize(img, uint64(len(entries))*uint64(format.DynSize(cl)))
	dynSec.SetGen(func(*image.Image) ([]byte, error) { return l.generateDynamic(entries, cl) })
	img.AddSynthetic(dynSec)

	for _, syn := range []*image.Synthetic{dynStrSec, dynSymSec, hashSec, relaDynSec, relaPltSec, interpSec, dynSec} {
		if syn == nil {
			continue
		}
		in.AddChunk(syn.Chunk)
		img.Section(syn.Chunk.Name, syn.Chunk.Type, syn.Chunk.Flags).Add(syn.Chunk)
	}

	if s := img.FindSection(".dynsym"); s != nil {
		s.LinkTo = img.FindSection(".dynstr")
		s.Info = 1 // Index 0 is the null entry; nothing here is STB_LOCAL.
	}
	if s := img.FindSection(".hash"); s != nil {
		s.LinkTo = img.FindSection(".dynsym")
	}
	if s := img.FindSection(relName + ".dyn"); s != nil {
		s.LinkTo = img.FindSection(".dynsym")
	}
	if s := img.FindSection(relName + ".plt"); s != nil {
		s.LinkTo = img.FindSection(".dynsym")
		if p := img.FindSection(".plt"); p != nil {
			s.InfoTo = p
		}
	}
	if s := img.FindSection(".dynamic"); s != nil {
		s.LinkTo = img.FindSection(".dynstr")
	}
	return nil
}

// needsInterp reports whether the output is a kind the kernel loads directly
// and so needs a PT_INTERP telling it which dynamic linker to run first. A
// shared object is loaded by an interpreter, not by one.
func (l *Linker) needsInterp() bool {
	return l.opts.Output == OutputExec || l.opts.Output == OutputPIE
}

// buildNeeded resolves l.needed, the shared inputs in link order, into the
// SONAMEs that become DT_NEEDED entries, applying --as-needed and dropping
// duplicates.
func (l *Linker) buildNeeded(img *image.Image) {
	seen := make(map[string]bool)
	for _, in := range l.needed {
		if l.opts.AsNeeded && !l.inputUsed(img, in) {
			continue
		}
		if seen[in.SOName] {
			continue
		}
		seen[in.SOName] = true
		l.reqs.Needed = append(l.reqs.Needed, in.SOName)
	}
}

// inputUsed reports whether anything in the final link resolved to a
// definition from in.
func (l *Linker) inputUsed(img *image.Image, in *image.Input) bool {
	used := false
	img.Syms.Each(func(s *image.Sym) {
		if s.Class == image.SymShared && s.Input == in && s.Referenced && s.Live() {
			used = true
		}
	})
	return used
}

// collectDynSyms decides .dynsym's membership: every imported definition
// that is actually referenced, and every locally defined symbol this output
// exports, in a stable order with DynIndex assigned starting at 1.
func (l *Linker) collectDynSyms(img *image.Image) []*image.Sym {
	seen := make(map[*image.Sym]bool)
	var out []*image.Sym
	add := func(s *image.Sym) {
		if s == nil || seen[s] {
			return
		}
		seen[s] = true
		out = append(out, s)
	}

	export := l.opts.Output == OutputShared || l.opts.ExportDynamic
	img.Syms.Each(func(s *image.Sym) {
		switch {
		case s.Class == image.SymShared:
			if s.Referenced && s.Live() {
				add(s)
			}
		case s.Defined() && s.Live() && !s.Local() && (export || s.ExportDynamic):
			add(s)
		}
	})

	// Anything a queued dynamic relocation names must be present regardless
	// of the policy above — GLOB_DAT and JUMP_SLOT relocations exist only
	// against symbols the loader must look up, which the rules already
	// cover, but a defensive sweep costs little and a missing dynsym entry
	// produces a relocation with no symbol to name.
	for _, rel := range l.reqs.RelaDyn {
		add(rel.Sym)
	}
	for _, rel := range l.reqs.RelaPlt {
		add(rel.Sym)
	}

	for i, s := range out {
		s.DynIndex = int32(i + 1)
	}
	return out
}

// generateDynsym writes .dynsym once addresses are final.
func (l *Linker) generateDynsym(img *image.Image, syms []*image.Sym, refs map[*image.Sym]*strtab.Ref) ([]byte, error) {
	cl := img.Target.Class
	b := binio.NewBufSize(outputOrder(img.Target), (len(syms)+1)*format.SymSize(cl))

	var null format.Sym
	null.Encode(b, cl)

	for _, s := range syms {
		var e format.Sym
		e.Name = refs[s].Offset()
		e.SetInfo(s.Bind, s.Type)
		e.Other = s.Other
		e.Size = s.Size

		if s.Class == image.SymShared || !s.Defined() {
			e.Shndx = elf.SHN_UNDEF_IDX
		} else {
			e.Value = s.Addr()
			if s.Chunk != nil && s.Chunk.Out != nil {
				e.Shndx = uint16(s.Chunk.Out.Index)
			}
			if s.Frag != nil {
				if w := s.Frag.Winner(); w.Out != nil && w.Out.Out != nil {
					e.Shndx = uint16(w.Out.Out.Index)
				}
			}
		}
		e.Encode(b, cl)
	}
	return b.Bytes(), nil
}

// hashSize returns .hash's byte length for n dynamic symbols: the
// nbucket/nchain header plus both arrays, always as 32-bit words regardless
// of class — SysV .hash is one of the few structures the gABI fixes at that
// width on every architecture.
func hashSize(n int) uint64 {
	nbucket := n
	if nbucket < 1 {
		nbucket = 1
	}
	nchain := n + 1
	return uint64(2+nbucket+nchain) * 4
}

// generateHash builds a SysV .hash from the final .dynsym order. Bucket count
// equals the symbol count rather than a tuned prime: correctness does not
// depend on load factor, only on every chain terminating. Every field is a
// 32-bit word in the target's own byte order — .hash fixes the width at 32
// bits on every architecture this module targets, but not the endianness.
func generateHash(syms []*image.Sym, ord binary.ByteOrder) []byte {
	nbucket := len(syms)
	if nbucket < 1 {
		nbucket = 1
	}
	nchain := len(syms) + 1

	buf := make([]byte, (2+nbucket+nchain)*4)
	ord.PutUint32(buf[0:], uint32(nbucket))
	ord.PutUint32(buf[4:], uint32(nchain))

	bucket := buf[8 : 8+nbucket*4]
	chain := buf[8+nbucket*4:]
	for i, s := range syms {
		symIdx := uint32(i + 1)
		b := elfHash(s.Name) % uint32(nbucket)
		bOff := b * 4
		prev := ord.Uint32(bucket[bOff : bOff+4])
		ord.PutUint32(bucket[bOff:bOff+4], symIdx)
		ord.PutUint32(chain[symIdx*4:symIdx*4+4], prev)
	}
	return buf
}

// elfHash is the System V ABI's own string hash, gABI section 5-13 ("Hash
// Table"), reproduced verbatim. Every SysV .hash on every architecture uses
// exactly this function; it has not changed since the original System V
// Release 4 ABI.
func elfHash(name string) uint32 {
	var h, g uint32
	for i := 0; i < len(name); i++ {
		h = (h << 4) + uint32(name[i])
		g = h & 0xf0000000
		if g != 0 {
			h ^= g >> 24
		}
		h &^= g
	}
	return h
}

// generateRelocs writes one .rela or .rel section from queued relocations,
// resolving each one's final address, symbol index, and — for RELA — addend
// now that layout is done.
//
// A REL entry has no addend field: for an address-based kind (RELATIVE,
// IRELATIVE) the resolved value was already written into the target memory
// by generateGot or generateGotPlt, since that is the only place left for it
// to live, and for a symbol-based kind there is no addend to carry at all —
// every architecture this module targets treats those as an unconditional
// replacement, RELA's explicit-zero-addend convention included.
func (l *Linker) generateRelocs(dynRelocs []backend.DynReloc, cl elf.Class, rel bool) ([]byte, error) {
	entSize := format.RelaSize(cl)
	if rel {
		entSize = format.RelSize(cl)
	}
	b := binio.NewBufSize(outputOrder(l.img.Target), len(dynRelocs)*entSize)

	for _, dr := range dynRelocs {
		typ, ok := l.be.DynType(dr.Kind)
		if !ok {
			return nil, fmt.Errorf("link: %v has no dynamic relocation for %v", l.be.Arch(), dr.Kind)
		}
		off := dr.Address()

		var symIdx uint32
		if !relocIsAddressBased(dr.Kind) {
			if dr.Sym == nil || dr.Sym.DynIndex <= 0 {
				return nil, fmt.Errorf("link: %v relocation at %#x names no dynamic symbol", dr.Kind, off)
			}
			symIdx = uint32(dr.Sym.DynIndex)
		}

		if rel {
			var e format.Rel
			e.Off = off
			e.SetInfo(cl, symIdx, typ)
			e.Encode(b, cl)
			continue
		}

		var e format.Rela
		e.Off = off
		e.SetInfo(cl, symIdx, typ)
		if relocIsAddressBased(dr.Kind) {
			// RELATIVE and IRELATIVE carry the fully resolved value in the
			// addend and name no symbol: the loader adds its load bias and
			// writes the result without a lookup.
			addr := dr.Addend
			if dr.Sym != nil {
				addr += int64(dr.Sym.Addr())
			}
			e.Addend = addr
		} else {
			e.Addend = dr.Addend
		}
		e.Encode(b, cl)
	}
	return b.Bytes(), nil
}

// relocIsAddressBased reports whether a dynamic relocation kind carries its
// value in the addend rather than naming a symbol for the loader to look up.
func relocIsAddressBased(k backend.DynKind) bool {
	return k == backend.DynRelative || k == backend.DynIRelative
}

// buildDynEntries decides the fixed list of .dynamic tags. Every Val here is
// either already final (a count, a flag word, a string's offset into
// .dynstr) or deferred to a section's address, resolved by generateDynamic
// once layout has run.
func (l *Linker) buildDynEntries(dynStr, dynSym, hash, relaDyn, relaPlt *image.Synthetic, rel bool,
	neededRefs []*strtab.Ref, sonameRef, rpathRef, runpathRef *strtab.Ref) []dynEntry {

	var e []dynEntry
	add := func(tag elf.DynTag, val uint64) { e = append(e, dynEntry{tag: tag, val: val}) }
	addSec := func(tag elf.DynTag, sec *image.Synthetic) {
		e = append(e, dynEntry{tag: tag, sec: sec})
	}

	for _, ref := range neededRefs {
		add(elf.DT_NEEDED, uint64(ref.Offset()))
	}
	if sonameRef != nil {
		add(elf.DT_SONAME, uint64(sonameRef.Offset()))
	}
	if rpathRef != nil {
		add(elf.DT_RPATH, uint64(rpathRef.Offset()))
	}
	if runpathRef != nil {
		add(elf.DT_RUNPATH, uint64(runpathRef.Offset()))
	}

	addSec(elf.DT_HASH, hash)
	addSec(elf.DT_STRTAB, dynStr)
	addSec(elf.DT_SYMTAB, dynSym)
	add(elf.DT_STRSZ, dynStr.Chunk.Size)
	add(elf.DT_SYMENT, uint64(format.SymSize(l.img.Target.Class)))

	relTag, relSzTag, relEntTag, entSize := elf.DT_RELA, elf.DT_RELASZ, elf.DT_RELAENT, uint64(format.RelaSize(l.img.Target.Class))
	pltRelTag := elf.DT_RELA
	if rel {
		relTag, relSzTag, relEntTag, entSize = elf.DT_REL, elf.DT_RELSZ, elf.DT_RELENT, uint64(format.RelSize(l.img.Target.Class))
		pltRelTag = elf.DT_REL
	}

	if relaDyn != nil {
		addSec(relTag, relaDyn)
		add(relSzTag, relaDyn.Chunk.Size)
		add(relEntTag, entSize)
	}
	if relaPlt != nil {
		addSec(elf.DT_JMPREL, relaPlt)
		add(elf.DT_PLTRELSZ, relaPlt.Chunk.Size)
		add(elf.DT_PLTREL, uint64(pltRelTag))
		if l.reqs.GotPlt != nil {
			addSec(elf.DT_PLTGOT, l.reqs.GotPlt)
		} else if l.reqs.Got != nil {
			addSec(elf.DT_PLTGOT, l.reqs.Got)
		}
	}

	var flags, flags1 uint32
	if l.reqs.TextRelocs {
		add(elf.DT_TEXTREL, 0)
		flags |= elf.DF_TEXTREL
	}
	if l.opts.bindNow() {
		flags |= elf.DF_BIND_NOW
		flags1 |= elf.DF_1_NOW
	}
	if l.opts.Output == OutputPIE {
		flags1 |= elf.DF_1_PIE
	}
	if flags != 0 {
		add(elf.DT_FLAGS, uint64(flags))
	}
	if flags1 != 0 {
		add(elf.DT_FLAGS_1, uint64(flags1))
	}

	add(elf.DT_DEBUG, 0)
	add(elf.DT_NULL, 0)
	return e
}

// generateDynamic writes .dynamic once every section it references has an
// address.
func (l *Linker) generateDynamic(entries []dynEntry, cl elf.Class) ([]byte, error) {
	b := binio.NewBufSize(outputOrder(l.img.Target), len(entries)*format.DynSize(cl))
	for _, ent := range entries {
		v := ent.val
		if ent.sec != nil {
			v = ent.sec.Chunk.Addr() + ent.off
		}
		d := format.Dyn{Tag: ent.tag, Val: v}
		d.Encode(b, cl)
	}
	return b.Bytes(), nil
}

// joinPath joins RPATH/RUNPATH entries the way the dynamic loader expects:
// colon-separated, same as $PATH.
func joinPath(paths []string) string {
	s := ""
	for i, p := range paths {
		if i > 0 {
			s += ":"
		}
		s += p
	}
	return s
}

// defaultInterp returns the platform's dynamic linker path for a target that
// did not name one explicitly. Only the psABIs this module has a shipped
// backend for are covered; anything else must set Options.Interp.
func defaultInterp(t elf.Target) (string, error) {
	switch t.Arch {
	case elf.ArchAMD64:
		return "/lib64/ld-linux-x86-64.so.2", nil
	case elf.ArchARM64:
		return "/lib/ld-linux-aarch64.so.1", nil
	case elf.ArchI386:
		return "/lib/ld-linux.so.2", nil
	}
	return "", fmt.Errorf("link: no default interpreter known for %v; set Options.Interp", t.Arch)
}
