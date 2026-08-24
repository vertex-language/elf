package x86_64

import (
	"fmt"

	"github.com/vertex-language/elf"
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
		return fmt.Errorf("x86_64: %s+%#x: relocation type %d: %w",
			ch, r.Offset, r.Type, backend.ErrUnsupportedReloc)
	}
	if r.Sym == nil {
		return nil
	}

	switch {
	case k == backend.KindGotPC && canRelaxGot(reqs, r):
		// The load will be rewritten to a direct lea, so no slot is needed.
		// Apply calls this same predicate, which is what keeps the two
		// halves of the decision from drifting apart.
		return nil

	case k.NeedsGot():
		if k == backend.KindTlsGd {
			reqs.AddTlsGot(img, r.Sym)
			return nil
		}
		if k == backend.KindTlsLd {
			reqs.AddTlsIndex(img)
			return nil
		}
		reqs.AddGot(img, r.Sym)
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
			Slot: nil, SlotOff: ch.OutOffset + r.Offset,
		})
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

// canRelaxGot reports whether a GOT load may be rewritten as a direct lea.
//
// Three conditions, and the third is the one that is easy to miss. The symbol
// must be non-preemptible, or the indirection is what makes preemption work.
// The relocation type must be one of the relaxable forms. And the addend must
// be exactly -4: the assembler also emits these types for instructions that
// load part of a GOT entry rather than the whole of it — movl x@GOTPCREL+4(%rip)
// reads the high half — and rewriting one of those to an lea produces code
// that computes an address nobody asked for.
func canRelaxGot(reqs *backend.Reqs, r image.Reloc) bool {
	if r.Sym == nil || !r.Sym.Defined() || r.Sym.Preemptible() {
		return false
	}
	if ifunc(r.Sym) {
		// An ifunc's address is what its resolver returns, so the
		// indirection is the entire point.
		return false
	}
	if r.Sym.Class == image.SymShared {
		return false
	}
	if r.Addend != -4 {
		return false
	}
	switch elf.RelocX86_64(r.Type) {
	case elf.R_X86_64_GOTPCRELX, elf.R_X86_64_REX_GOTPCRELX,
		elf.R_X86_64_CODE_4_GOTPCRELX:
		return true
	}
	return false
}