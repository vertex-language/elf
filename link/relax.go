package link

import (
	"fmt"

	"github.com/vertex-language/elf"
	"github.com/vertex-language/elf/backend"
	"github.com/vertex-language/elf/image"
)

// thunkKey identifies a trampoline: one per target per output section.
//
// Per section rather than per output, because a thunk only helps if the branch
// can reach the thunk. One shared trampoline in .text would be as unreachable
// from a distant caller as the original target was.
type thunkKey struct {
	sym *image.Sym
	out *image.OutputSection
}

// relocSite identifies one relocation, for recording that it was redirected.
type relocSite struct {
	chunk *image.Chunk
	off   uint64
}

type thunkEntry struct {
	sym   *image.Sym
	chunk *image.Chunk
	off   uint64
}

// addr returns the trampoline's run-time address.
func (t *thunkEntry) addr() uint64 { return t.chunk.Addr() + t.off }

// growThunks inserts range extension trampolines for branches that cannot
// reach their targets, and reports whether it added any.
//
// It runs inside the layout fixpoint because inserting a thunk moves
// everything after it, which can push another branch out of range. Thunks are
// never removed once created: a branch that came back into range because
// something shrank would oscillate against a branch that went out of range for
// the same reason, and the loop would never settle. Keeping a thunk nothing
// needs costs a few bytes; oscillating costs the link.
func (l *Linker) growThunks(img *image.Image) (bool, error) {
	th, ok := backend.AsThunker(l.be)
	if !ok {
		// x86-64 and the other architectures whose branches span the address
		// space have no Thunker, so this is the whole pass for them.
		return false, nil
	}
	if l.thunks == nil {
		l.thunks = make(map[thunkKey]*thunkEntry)
		l.redirect = make(map[relocSite]uint64)
	}

	shape := th.Thunk()
	grew := false
	var err error

	img.Chunks(func(ch *image.Chunk) {
		if err != nil || ch.Out == nil || !ch.Flags.Exec() {
			return
		}
		var relocs []image.Reloc
		relocs, err = ch.Relocs()
		if err != nil {
			return
		}

		for _, r := range relocs {
			if r.Sym == nil || !r.Sym.Defined() {
				continue
			}
			k := l.be.Classify(r.Type)
			if k != backend.KindPltPC && k != backend.KindPC {
				continue
			}

			src := ch.Addr() + r.Offset
			dst, derr := l.branchTarget(r)
			if derr != nil {
				continue
			}

			site := relocSite{ch, r.Offset}
			if prev, ok := l.redirect[site]; ok {
				// Already redirected. Re-point it, since the trampoline may
				// have moved since the last round.
				if e, ok := l.thunks[thunkKey{r.Sym, ch.Out}]; ok {
					l.redirect[site] = e.addr()
					_ = prev
				}
				continue
			}
			if th.InRange(r.Type, src, dst) {
				continue
			}

			e, added := l.thunkFor(img, r.Sym, ch.Out, shape)
			l.redirect[site] = e.addr()
			if added {
				grew = true
			}
		}
	})
	return grew, err
}

// branchTarget is where a call actually goes: the PLT entry when the symbol
// has one, the symbol itself otherwise.
func (l *Linker) branchTarget(r image.Reloc) (uint64, error) {
	if r.Sym.PltIndex != image.NoIndex {
		return l.reqs.PltEntryAddr(r.Sym)
	}
	return r.Sym.Addr() + uint64(r.Addend), nil
}

// thunkFor returns the trampoline reaching sym from out, creating it if there
// is none. The bool reports whether one was created.
func (l *Linker) thunkFor(img *image.Image, sym *image.Sym,
	out *image.OutputSection, shape backend.ThunkShape) (*thunkEntry, bool) {

	k := thunkKey{sym, out}
	if e, ok := l.thunks[k]; ok {
		return e, false
	}

	ch := l.thunkChunk(img, out, shape)
	e := &thunkEntry{sym: sym, chunk: ch, off: ch.Size}
	ch.Size += shape.Size
	l.thunks[k] = e
	return e, true
}

// thunkChunk returns the trampoline chunk appended to an output section,
// creating it on first use.
//
// It is placed at the end of the section it serves, which is the only position
// reachable from every branch inside that section.
func (l *Linker) thunkChunk(img *image.Image, out *image.OutputSection,
	shape backend.ThunkShape) *image.Chunk {

	last := len(out.Chunks) - 1
	if last >= 0 && out.Chunks[last].Name == ".text.thunk" {
		return out.Chunks[last]
	}

	align := shape.Align
	if align == 0 {
		align = 4
	}
	ch := image.NewChunk(".text.thunk", elf.SHT_PROGBITS,
		image.SecFlags(elf.SHF_ALLOC|elf.SHF_EXECINSTR), align, 0, nil)
	ch.Reachable = true
	out.Add(ch)
	return ch
}

// writeThunks fills every trampoline's instructions. It runs after Freeze,
// with addresses final.
func (l *Linker) writeThunks(img *image.Image) error {
	th, ok := backend.AsThunker(l.be)
	if !ok || len(l.thunks) == 0 {
		return nil
	}
	shape := th.Thunk()

	for _, e := range l.thunks {
		s, err := l.site(img, e.chunk)
		if err != nil {
			return err
		}
		buf, err := s.Slice(e.off, shape.Size)
		if err != nil {
			return err
		}
		target, err := l.branchTarget(image.Reloc{Sym: e.sym})
		if err != nil {
			return err
		}
		if err := th.WriteThunk(buf, s, target, e.chunk.Addr()+e.off); err != nil {
			return fmt.Errorf("link: thunk to %s: %w", e.sym, err)
		}
	}
	return nil
}