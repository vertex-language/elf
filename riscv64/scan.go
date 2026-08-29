package riscv64

import (
	"fmt"

	"github.com/vertex-language/elf/backend"
	"github.com/vertex-language/elf/image"
)

// Scan records what every live relocation needs from the output.
//
// It runs before layout, so it may assign slots and grow synthetic sections
// but must not compute an address: none exist yet.
func (b Backend) Scan(img *image.Image, reqs *backend.Reqs) error {
	var err error
	img.Chunks(func(ch *image.Chunk) {
		if err != nil || ch.Out == nil {
			return
		}
		var relocs []image.Reloc
		relocs, err = ch.Relocs()
		if err != nil {
			return
		}
		for _, r := range relocs {
			if e := b.scanOne(img, reqs, ch, r); e != nil {
				err = e
				return
			}
		}
	})
	return err
}

func (b Backend) scanOne(img *image.Image, reqs *backend.Reqs,
	ch *image.Chunk, r image.Reloc) error {

	k := b.Classify(r.Type)
	if k == backend.KindNone || k == backend.KindRelax {
		return nil
	}
	if k == backend.KindUnknown {
		return fmt.Errorf("riscv64: %s+%#x: relocation type %d: %w",
			ch, r.Offset, r.Type, backend.ErrUnsupportedReloc)
	}

	// A PCREL_LO12 names a local label at its paired HI20's address, not the
	// real target, so it never itself needs a GOT or PLT slot — whatever the
	// pair's real target needs was already decided when the HI20 relocation
	// at that address was scanned. Nothing here can tell a LO12 apart from
	// one pairing with an ordinary PCREL_HI20, but KindPC.NeedsGot and
	// NeedsPlt are both false, so the switch below is a no-op for it anyway.
	if r.Sym == nil {
		return nil
	}

	switch {
	case k.NeedsGot():
		switch k {
		case backend.KindTlsGd:
			reqs.AddTlsGot(img, r.Sym)
		case backend.KindTlsIe:
			reqs.AddGot(img, r.Sym)
			r.Sym.Set(image.NeedsTlsIe)
		default:
			reqs.AddGot(img, r.Sym)
		}
		return nil

	case k.NeedsPlt():
		if needsPlt(reqs, r.Sym) {
			reqs.AddPlt(img, r.Sym)
		}
		// Otherwise CALL_PLT is reduced to a direct PC-relative call, which
		// the psABI permits for a locally defined, non-preemptible target.
		return nil

	case k == backend.KindAbs && reqs.Pic:
		if !ch.Flags.Write() {
			reqs.TextRelocs = true
		}
		kind := backend.DynRelative
		if r.Sym.Preemptible() {
			kind = backend.DynAbsolute
		}
		reqs.AddDyn(backend.DynReloc{
			Kind: kind, Sym: r.Sym, Addend: r.Addend,
			Chunk: ch, Off: r.Offset,
		})
		return nil

	case k == backend.KindAbs && !reqs.Pic && r.Sym.Class == image.SymShared:
		// A non-PIC output reading a shared object's data directly, with no
		// GOT indirection, needs its own copy: the address baked into this
		// instruction is fixed at link time, so it cannot be the shared
		// library's copy, whose address the loader picks at run time.
		reqs.NeedCopy(r.Sym)
		return nil
	}
	return nil
}

// needsPlt reports whether a call to sym must go through a procedure linkage
// entry rather than branching directly.
func needsPlt(reqs *backend.Reqs, sym *image.Sym) bool {
	if !reqs.Dynamic {
		return false
	}
	if sym.Class == image.SymShared || !sym.Defined() {
		return true
	}
	return sym.Preemptible()
}
