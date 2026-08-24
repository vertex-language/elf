package link

import (
	"github.com/vertex-language/elf"
	"github.com/vertex-language/elf/image"
	"github.com/vertex-language/elf/internal/format"
)

// assign gives every output section an address and a file offset, and builds
// the program headers over them.
//
// It runs once per iteration of the layout fixpoint and must be idempotent:
// nothing it computes may depend on what a previous round computed, or the
// loop converges on a state that depends on how many times it ran. The RELRO
// padding is reset below for exactly that reason — carrying last round's size
// forward would make the region grow by a page every time.
func (l *Linker) assign(img *image.Image) error {
	if pad := img.FindSection(relroPadName); pad != nil {
		pad.Size = 0
	}

	plan := l.planSegments(img)

	// The ELF header and the program headers occupy the front of the file,
	// and no section may be placed into them. The count has to be known
	// before any address is assigned, which is why the segments are planned
	// before they are filled.
	nphdr := len(plan) + l.extraSegments(img)
	img.HeaderSize = format.HeaderRegion(img.Target.Class, nphdr)

	page := l.opts.maxPage(img.Target)
	addr := l.opts.base(img.Target)
	off := uint64(0)

	img.Segments = img.Segments[:0]

	for i, p := range plan {
		seg := image.NewSegment(elf.PT_LOAD, p.flags, page)

		if i == 0 {
			// The first segment covers the headers, so it starts at the load
			// base with offset zero and the first section follows them.
			seg.Off, seg.Vaddr, seg.Paddr = 0, addr, addr
			addr += img.HeaderSize
			off = img.HeaderSize
		} else {
			// A new segment needs different permissions, so it must begin on
			// a fresh page. The file offset then has to be made congruent
			// with the address modulo the page size, which is what lets the
			// loader map the file directly rather than copying.
			addr = alignUp(addr, page)
			off = congruent(off, addr, page)
			seg.Off, seg.Vaddr, seg.Paddr = off, addr, addr
		}

		segAddr, segOff := addr, off
		for _, s := range p.sections {
			s.Addr = alignUp(addr, s.Align)

			// Within one segment the file offset tracks the address exactly.
			// That preserves congruence for free and is why no section
			// needs its own padding computation.
			s.Off = segOff + (s.Addr - segAddr)
			s.Size = sectionSize(s)

			addr = s.Addr + s.Size

			// A NOBITS section occupies memory but no file space, so the
			// next section reuses its offset. Only trailing NOBITS sections
			// are safe here, which the ordering guarantees by ranking .bss
			// and .tbss last in their segments.
			if s.HasBits() {
				off = s.Off + s.Size
			}
			seg.Add(s)
		}

		// RELRO must end on a page boundary for the loader to protect it.
		if l.opts.Relro != RelroNone {
			addr = l.closeRelro(p, addr, page)
		}

		seg.Cover()
		img.AddSegment(seg)
	}

	if err := l.assignNonAlloc(img, &off); err != nil {
		return err
	}

	off = alignUp(off, wordAlign(img.Target.Class))
	img.Shoff = off
	off += uint64(len(img.Sections)+1) * uint64(format.ShdrSize(img.Target.Class))
	img.FileSize = off

	l.metaSegments(img)
	return nil
}

// congruent advances off to the smallest value at or above it that is
// congruent to addr modulo page.
//
// The requirement is p_offset ≡ p_vaddr (mod p_align), not p_offset ==
// p_vaddr mod p_align — a distinction that has confused enough people to be
// worth writing down. Aligning both fully to the page would satisfy it too,
// but wastes up to a page per segment.
func congruent(off, addr, page uint64) uint64 {
	if page <= 1 {
		return off
	}
	return off + ((addr - off) & (page - 1))
}

// closeRelro rounds the address past the end of the RELRO region and sizes the
// padding section that fills the gap.
//
// The loader mprotects whole pages, so a region ending mid-page either leaves
// its tail writable or takes the following section read-only with it. The
// padding is NOBITS, so it costs no file bytes.
func (l *Linker) closeRelro(p segPlan, addr, page uint64) uint64 {
	var pad *image.OutputSection
	inRelro := false
	for _, s := range p.sections {
		if relroSection(s) {
			inRelro = true
		}
		if s.Name == relroPadName {
			pad = s
		}
	}
	if !inRelro || pad == nil {
		return addr
	}
	end := alignUp(addr, page)
	pad.Size = end - pad.Addr
	return end
}

// segPlan is one PT_LOAD before addresses exist.
type segPlan struct {
	flags    image.SegFlags
	sections []*image.OutputSection
}

// planSegments groups the ordered sections into loadable segments.
//
// A new segment starts whenever permissions change, since a segment has one
// set of them. With SeparateCode the executable sections get their own even
// when read-only data could have shared it, so that no page is both adjacent
// to writable data and executable.
func (l *Linker) planSegments(img *image.Image) []segPlan {
	var out []segPlan
	for _, s := range img.Sections {
		if !s.Alloc() {
			continue
		}
		f := s.Flags.Seg()
		if n := len(out); n > 0 && out[n-1].flags == f && !l.forcesBreak(s) {
			out[n-1].sections = append(out[n-1].sections, s)
			continue
		}
		out = append(out, segPlan{flags: f, sections: []*image.OutputSection{s}})
	}
	return out
}

// forcesBreak reports whether a section must start a new segment despite
// matching permissions.
func (l *Linker) forcesBreak(s *image.OutputSection) bool {
	if l.opts.SectionAddress == nil {
		return false
	}
	// A section pinned to an explicit address cannot share a segment with
	// whatever happened to precede it.
	_, pinned := l.opts.SectionAddress[s.Name]
	return pinned
}

// extraSegments counts the non-PT_LOAD program headers, which must be included
// in the reserved header region before any of them can be built.
//
// It must agree exactly with metaSegments below. If the two drift, the
// reserved region is the wrong size and every address in the output shifts,
// which is why they sit next to each other and read the same conditions.
func (l *Linker) extraSegments(img *image.Image) int {
	n := 1 // PT_PHDR
	if img.FindSection(".interp") != nil {
		n++
	}
	if img.FindSection(".dynamic") != nil {
		n++
	}
	if img.FindSection(".tdata") != nil || img.FindSection(".tbss") != nil {
		n++
	}
	if img.FindSection(".eh_frame_hdr") != nil {
		n++
	}
	if l.opts.Relro != RelroNone && l.hasRelro(img) {
		n++
	}
	n++ // PT_GNU_STACK, always emitted
	for _, s := range img.Sections {
		if s.Type == elf.SHT_NOTE && s.Alloc() {
			n++
		}
	}
	return n
}

// hasRelro reports whether any section belongs in PT_GNU_RELRO.
func (l *Linker) hasRelro(img *image.Image) bool {
	for _, s := range img.Sections {
		if relroSection(s) {
			return true
		}
	}
	return false
}

// metaSegments builds the program headers that describe rather than load.
func (l *Linker) metaSegments(img *image.Image) {
	add := func(typ elf.ProgType, flags image.SegFlags, secs ...*image.OutputSection) {
		if len(secs) == 0 || secs[0] == nil {
			return
		}
		seg := image.NewSegment(typ, flags, secs[0].Align)
		for _, s := range secs {
			if s != nil {
				seg.Sections = append(seg.Sections, s)
			}
		}
		seg.Cover()
		img.AddSegment(seg)
	}

	if s := img.FindSection(".interp"); s != nil {
		add(elf.PT_INTERP, elf.PF_R, s)
	}
	if s := img.FindSection(".dynamic"); s != nil {
		add(elf.PT_DYNAMIC, elf.PF_R|elf.PF_W, s)
	}

	// PT_TLS covers .tdata and .tbss and nothing else, which is why the
	// ordering keeps them adjacent and at the head of the writable region.
	tdata, tbss := img.FindSection(".tdata"), img.FindSection(".tbss")
	if tdata != nil || tbss != nil {
		var secs []*image.OutputSection
		if tdata != nil {
			secs = append(secs, tdata)
		}
		if tbss != nil {
			secs = append(secs, tbss)
		}
		add(elf.PT_TLS, elf.PF_R, secs...)

		l.reqs.TlsAddr = secs[0].Addr
		l.reqs.TlsAlign = secs[0].Align
		var end uint64
		for _, s := range secs {
			if e := s.End(); e > end {
				end = e
			}
		}
		l.reqs.TlsSize = end - secs[0].Addr
	}

	if s := img.FindSection(".eh_frame_hdr"); s != nil {
		add(elf.PT_GNU_EH_FRAME, elf.PF_R, s)
	}

	if l.opts.Relro != RelroNone {
		var secs []*image.OutputSection
		for _, s := range img.Sections {
			if relroSection(s) {
				secs = append(secs, s)
			}
		}
		if len(secs) > 0 {
			seg := image.NewSegment(elf.PT_GNU_RELRO, elf.PF_R, 1)
			for _, s := range secs {
				seg.Sections = append(seg.Sections, s)
			}
			seg.Cover()
			img.AddSegment(seg)
		}
	}

	// An omitted PT_GNU_STACK makes the kernel assume an executable stack,
	// so the header is always written and the flags carry the decision.
	img.AddSegment(image.NewSegment(elf.PT_GNU_STACK, elf.PF_R|elf.PF_W, 0))
}

// assignNonAlloc places the sections that occupy file space but no memory.
func (l *Linker) assignNonAlloc(img *image.Image, off *uint64) error {
	for _, s := range img.Sections {
		if s.Alloc() {
			continue
		}
		s.Addr = 0
		s.Off = alignUp(*off, s.Align)
		s.Size = sectionSize(s)
		if s.HasBits() {
			*off = s.Off + s.Size
		} else {
			*off = s.Off
		}
	}
	return nil
}

// sectionSize lays the chunks out inside a section and returns its length.
func sectionSize(s *image.OutputSection) uint64 {
	if len(s.Chunks) == 0 {
		// A section with no chunks carries its size directly: the RELRO
		// padding and any caller-declared NOBITS section.
		return s.Size
	}
	var size uint64
	for _, ch := range s.Chunks {
		a := ch.Align
		if a == 0 {
			a = 1
		}
		size = alignUp(size, a)
		ch.OutOffset = size
		size += ch.Size
	}
	return size
}

// wordAlign is the natural alignment for class-width tables.
func wordAlign(cl elf.Class) uint64 {
	if cl.Wide() {
		return 8
	}
	return 4
}