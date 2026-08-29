package arm64

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
		return fmt.Errorf("arm64: %s+%#x: relocation type %d: %w",
			ch, r.Offset, r.Type, backend.ErrUnsupportedReloc)
	}
	if r.Sym == nil {
		return nil
	}

	switch {
	case k.NeedsGot():
		switch k {
		case backend.KindTlsGd, backend.KindTlsDesc:
			// A general-dynamic or TLSDESC reference here is an ADRP/ADD (or
			// ADRP/LDR/ADD) pair — two or three relocations against the same
			// symbol for one logical access. AddTlsGot returns the same slot
			// on every call for a given symbol, so each one agrees on where
			// the pair lives.
			reqs.AddTlsGot(img, r.Sym)
		case backend.KindTlsLd:
			reqs.AddTlsIndex(img)
		case backend.KindTlsIe:
			reqs.AddGot(img, r.Sym)
			r.Sym.Set(image.NeedsTlsIe)
		default:
			reqs.AddGot(img, r.Sym)
		}
		return nil

	case k.NeedsPlt():
		if ifunc(r.Sym) {
			reqs.AddIPlt(img, r.Sym)
			return nil
		}
		if needsPlt(reqs, r.Sym) {
			reqs.AddPlt(img, r.Sym)
		}
		// Otherwise the branch is reduced to a direct PC-relative call,
		// which the psABI explicitly permits for a locally defined target.
		return nil

	case k == backend.KindAbs && reqs.Pic:
		// An absolute address in a position-independent output is not known
		// until load time. A non-preemptible target gets a RELATIVE
		// relocation, which needs no symbol lookup; anything else needs the
		// full form.
		if !ch.Flags.Write() {
			// A dynamic relocation into read-only memory forces DT_TEXTREL,
			// which makes the loader write to pages that were meant to stay
			// clean. It is legal and it is a smell.
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
		// A static link resolves every call at link time; there is nothing
		// for a PLT to defer to.
		return false
	}
	if sym.Class == image.SymShared || !sym.Defined() {
		return true
	}
	return sym.Preemptible()
}
