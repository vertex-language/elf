package i386

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
		return fmt.Errorf("i386: %s+%#x: relocation type %d: %w",
			ch, r.Offset, r.Type, backend.ErrUnsupportedReloc)
	}
	if r.Sym == nil {
		return nil
	}

	switch {
	case k.NeedsGot():
		switch k {
		case backend.KindTlsGd:
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
		if needsPlt(reqs, r.Sym) {
			reqs.AddPlt(img, r.Sym)
		}
		// Otherwise the branch is reduced to a direct PC-relative call,
		// which the psABI permits for a locally defined, non-preemptible
		// target.
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
