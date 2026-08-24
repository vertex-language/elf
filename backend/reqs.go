package backend

import (
	"fmt"

	"github.com/vertex-language/elf"
	"github.com/vertex-language/elf/image"
)

// Reqs is what the scan pass decided the output needs.
//
// It exists because sizing and filling the synthetic sections happen at
// opposite ends of layout. Scan knows how many GOT slots there are — it has
// seen every reference — but not what goes in them, because addresses do not
// exist yet. Reqs carries the decisions across that gap: slot assignments and
// counts made during scan, read back during generation and application.
type Reqs struct {
	// Got, GotPlt, Plt, SecPlt, and IPlt are the synthetic sections, created
	// lazily by the Need* methods so that a link needing no PLT emits no
	// empty .plt.
	Got    *image.Synthetic
	GotPlt *image.Synthetic
	Plt    *image.Synthetic
	SecPlt *image.Synthetic
	IPlt   *image.Synthetic

	// RelaDyn and RelaPlt are the dynamic relocations to emit. They are kept
	// apart because DT_JMPREL points at the PLT ones alone, and lazy binding
	// requires that they be contiguous and separate.
	RelaDyn []DynReloc
	RelaPlt []DynReloc

	// Copy are symbols needing a copy relocation: data defined in a shared
	// object that a non-PIC executable references directly, and so must have
	// its own storage for in .bss.
	Copy []*image.Sym

	// Needed are the DT_NEEDED entries, by SONAME rather than by path.
	Needed []string

	// TlsAddr, TlsSize, and TlsAlign describe the output's TLS block, set by
	// layout from the PT_TLS segment. Backends compute thread-pointer
	// offsets from these; the two TLS variants place the block on opposite
	// sides of the pointer, which is why this is raw data rather than a
	// computed offset.
	TlsAddr  uint64
	TlsSize  uint64
	TlsAlign uint64

	// TlsIndexOff is the offset of the module-index GOT pair used by
	// local-dynamic references, or NoSlot. Every local-dynamic reference in
	// the output shares one.
	TlsIndexOff int64

	// Pic reports whether the output is position-independent, which decides
	// whether an absolute reference needs a dynamic relocation or can be
	// resolved at link time.
	Pic bool

	// Dynamic reports whether the output has a .dynamic section at all. A
	// static executable with ifuncs still needs IRELATIVE relocations, so
	// this is not the same question as "are there dynamic relocations".
	Dynamic bool

	// TextRelocs records that a dynamic relocation landed in a
	// non-writable section, which forces DT_TEXTREL and makes the loader
	// write to executable pages.
	TextRelocs bool

	shape    GotShape
	pltShape PltShape
	gotSlots int
	pltSlots int
	ipltSlots int
}

// NoSlot marks an unassigned table offset. Zero is a real offset, so the
// unassigned state needs its own value.
const NoSlot int64 = -1

// DynReloc is one relocation for the dynamic loader to apply.
//
// Offset is a run-time address rather than a file offset, which is what
// r_offset holds in a linked object; it is filled in during generation, once
// the slot it names has an address.
type DynReloc struct {
	Offset uint64
	Kind   DynKind

	// Sym is the symbol the loader must look up, or nil for the relocations
	// that need none — RELATIVE and IRELATIVE carry a value, not a name.
	Sym *image.Sym

	Addend int64

	// Slot is the synthetic and offset this relocation targets, so that
	// generation can resolve Offset after addresses exist without
	// re-deriving which table the slot was in.
	Slot     *image.Synthetic
	SlotOff  uint64
}

// NewReqs returns an empty Reqs for a backend's geometry.
func NewReqs(b Backend, pic, dynamic bool) *Reqs {
	r := &Reqs{Pic: pic, Dynamic: dynamic, TlsIndexOff: NoSlot}
	if d, ok := AsDynamic(b); ok {
		r.shape, r.pltShape = d.Got(), d.Plt()
	}
	return r
}

// GotShape and PltShape return the geometry this Reqs was built with.
func (r *Reqs) GotShape() GotShape { return r.shape }
func (r *Reqs) PltShape() PltShape { return r.pltShape }

// NeedGot creates .got if it does not exist and returns it.
func (r *Reqs) NeedGot(img *image.Image) *image.Synthetic {
	if r.Got == nil {
		r.Got = image.NewSynthetic(".got", elf.SHT_PROGBITS,
			image.SecFlags(elf.SHF_ALLOC|elf.SHF_WRITE),
			r.shape.Align, r.shape.EntrySize, nil)
		r.Got.SetSize(img, uint64(r.shape.Reserved)*r.shape.EntrySize)
		img.AddSynthetic(r.Got)
	}
	return r.Got
}

// NeedGotPlt creates .got.plt with its reserved prefix already accounted for.
func (r *Reqs) NeedGotPlt(img *image.Image) *image.Synthetic {
	if r.GotPlt == nil {
		r.GotPlt = image.NewSynthetic(".got.plt", elf.SHT_PROGBITS,
			image.SecFlags(elf.SHF_ALLOC|elf.SHF_WRITE),
			r.shape.Align, r.shape.EntrySize, nil)
		r.GotPlt.SetSize(img, r.shape.GotPltHeaderSize())
		img.AddSynthetic(r.GotPlt)
	}
	return r.GotPlt
}

// NeedPlt creates .plt, and .plt.sec alongside it when the format has one.
func (r *Reqs) NeedPlt(img *image.Image) *image.Synthetic {
	if r.Plt == nil {
		flags := image.SecFlags(elf.SHF_ALLOC | elf.SHF_EXECINSTR)
		r.Plt = image.NewSynthetic(".plt", elf.SHT_PROGBITS, flags,
			r.pltShape.Align, 0, nil)
		r.Plt.SetSize(img, r.pltShape.HeaderSize)
		img.AddSynthetic(r.Plt)

		if r.pltShape.SecEntrySize != 0 {
			r.SecPlt = image.NewSynthetic(".plt.sec", elf.SHT_PROGBITS, flags,
				r.pltShape.Align, 0, nil)
			img.AddSynthetic(r.SecPlt)
		}
	}
	return r.Plt
}

// NeedIPlt creates .iplt, which holds the entries for non-preemptible ifuncs.
func (r *Reqs) NeedIPlt(img *image.Image) *image.Synthetic {
	if r.IPlt == nil {
		r.IPlt = image.NewSynthetic(".iplt", elf.SHT_PROGBITS,
			image.SecFlags(elf.SHF_ALLOC|elf.SHF_EXECINSTR),
			r.pltShape.Align, 0, nil)
		img.AddSynthetic(r.IPlt)
	}
	return r.IPlt
}

// AddGot assigns sym a GOT slot if it has none, and returns the slot's offset
// within .got.
func (r *Reqs) AddGot(img *image.Image, sym *image.Sym) uint64 {
	got := r.NeedGot(img)
	if sym.GotIndex != image.NoIndex {
		return uint64(sym.GotIndex) * r.shape.EntrySize
	}
	off := got.Grow(img, r.shape.EntrySize)
	sym.GotIndex = int32(off / r.shape.EntrySize)
	sym.Set(image.NeedsGot)
	r.gotSlots++
	return off
}

// AddTlsGot assigns sym the consecutive slots a general-dynamic reference
// needs, and returns the first slot's offset.
func (r *Reqs) AddTlsGot(img *image.Image, sym *image.Sym) uint64 {
	got := r.NeedGot(img)
	n := r.shape.TlsGdEntries
	if n < 1 {
		n = 2
	}
	off := got.Grow(img, uint64(n)*r.shape.EntrySize)
	if sym != nil {
		sym.GotIndex = int32(off / r.shape.EntrySize)
		sym.Set(image.NeedsTlsGd)
	}
	r.gotSlots += n
	return off
}

// AddTlsIndex reserves the single module-index pair that every local-dynamic
// reference in the output shares, and returns its offset.
func (r *Reqs) AddTlsIndex(img *image.Image) uint64 {
	if r.TlsIndexOff != NoSlot {
		return uint64(r.TlsIndexOff)
	}
	off := r.AddTlsGot(img, nil)
	r.TlsIndexOff = int64(off)
	return off
}

// AddPlt assigns sym a PLT entry and its .got.plt slot, and returns the entry's
// index. Repeated calls for the same symbol return the existing index.
func (r *Reqs) AddPlt(img *image.Image, sym *image.Sym) int {
	if sym.PltIndex != image.NoIndex {
		return int(sym.PltIndex)
	}
	plt := r.NeedPlt(img)
	gotplt := r.NeedGotPlt(img)

	idx := r.pltSlots
	r.pltSlots++
	plt.Grow(img, r.pltShape.EntrySize)
	if r.SecPlt != nil {
		r.SecPlt.Grow(img, r.pltShape.SecEntrySize)
	}
	gotplt.Grow(img, r.shape.EntrySize)

	sym.PltIndex = int32(idx)
	sym.Set(image.NeedsPlt)
	return idx
}

// AddIPlt assigns sym an .iplt entry for a non-preemptible ifunc.
func (r *Reqs) AddIPlt(img *image.Image, sym *image.Sym) int {
	if sym.PltIndex != image.NoIndex {
		return int(sym.PltIndex)
	}
	iplt := r.NeedIPlt(img)
	gotplt := r.NeedGotPlt(img)

	idx := r.ipltSlots
	r.ipltSlots++
	iplt.Grow(img, r.pltShape.IPltEntrySize)
	gotplt.Grow(img, r.shape.EntrySize)

	sym.PltIndex = int32(idx)
	sym.Set(image.NeedsPlt)
	return idx
}

// GotAddr returns the run-time address of the GOT base, which GOT-relative
// relocations are measured from. It is meaningful only after layout.
func (r *Reqs) GotAddr() uint64 {
	if r.Got == nil || r.Got.Chunk.Out == nil {
		return 0
	}
	return r.Got.Chunk.Addr()
}

// GotPltAddr returns the run-time address of .got.plt.
func (r *Reqs) GotPltAddr() uint64 {
	if r.GotPlt == nil || r.GotPlt.Chunk.Out == nil {
		return 0
	}
	return r.GotPlt.Chunk.Addr()
}

// PltAddr returns the run-time address of .plt.
func (r *Reqs) PltAddr() uint64 {
	if r.Plt == nil || r.Plt.Chunk.Out == nil {
		return 0
	}
	return r.Plt.Chunk.Addr()
}

// GotSlotAddr returns the address of sym's GOT slot.
func (r *Reqs) GotSlotAddr(sym *image.Sym) (uint64, error) {
	if sym.GotIndex == image.NoIndex {
		return 0, fmt.Errorf("backend: %s has no GOT slot", sym)
	}
	return r.GotAddr() + uint64(sym.GotIndex)*r.shape.EntrySize, nil
}

// GotPltSlotAddr returns the address of the .got.plt slot belonging to sym's
// PLT entry, reserved prefix included.
func (r *Reqs) GotPltSlotAddr(sym *image.Sym) (uint64, error) {
	if sym.PltIndex == image.NoIndex {
		return 0, fmt.Errorf("backend: %s has no PLT entry", sym)
	}
	i := uint64(r.shape.PltReserved) + uint64(sym.PltIndex)
	return r.GotPltAddr() + i*r.shape.EntrySize, nil
}

// PltEntryAddr returns the address a call to sym should branch to: the
// .plt.sec entry when the format has a second table, the .plt entry otherwise.
func (r *Reqs) PltEntryAddr(sym *image.Sym) (uint64, error) {
	if sym.PltIndex == image.NoIndex {
		return 0, fmt.Errorf("backend: %s has no PLT entry", sym)
	}
	i := uint64(sym.PltIndex)
	if r.SecPlt != nil {
		return r.SecPlt.Chunk.Addr() + i*r.pltShape.SecEntrySize, nil
	}
	return r.PltAddr() + r.pltShape.EntryOffset(int(i)), nil
}

// AddDyn records a dynamic relocation against a slot in a synthetic section.
//
// PLT relocations go to RelaPlt and everything else to RelaDyn, because
// DT_JMPREL names a contiguous run of the former alone.
func (r *Reqs) AddDyn(rel DynReloc) {
	if rel.Kind == DynJumpSlot || rel.Kind == DynIRelative {
		r.RelaPlt = append(r.RelaPlt, rel)
		return
	}
	r.RelaDyn = append(r.RelaDyn, rel)
}

// Counts returns the number of GOT slots, PLT entries, and IPLT entries
// assigned, for diagnostics and for sizing the tables that describe them.
func (r *Reqs) Counts() (got, plt, iplt int) {
	return r.gotSlots, r.pltSlots, r.ipltSlots
}