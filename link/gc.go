package link

import (
	"path"

	"github.com/vertex-language/elf"
	"github.com/vertex-language/elf/image"
)

// gc marks every chunk reachable from a root.
//
// It sets Reachable and never touches Discarded. Collapsing the two would let
// a relocation into a chunk that lost its COMDAT election bring it back,
// producing an output with two copies of an inline function and, worse, two
// addresses for what the language guarantees is one entity.
//
// With GC off every chunk is live, which is the same sweep with every chunk a
// root; writing it that way rather than as a separate path means the two modes
// cannot disagree about what "live" means.
func (l *Linker) gc(img *image.Image) error {
	if !l.opts.GC {
		for _, in := range img.Inputs {
			for _, ch := range in.Chunks {
				ch.Reachable = true
			}
		}
		return nil
	}

	groups := groupIndex(img)

	var queue []*image.Chunk
	mark := func(ch *image.Chunk) {
		if ch == nil || ch.Discarded || ch.Reachable {
			return
		}
		ch.Reachable = true
		queue = append(queue, ch)

		// Section groups are associative: a group exists so its members live
		// and die together, so reaching one member reaches all of them.
		if ch.Group != "" && ch.Input != nil {
			for _, sib := range groups[groupKey{ch.Input, ch.Group}] {
				if !sib.Reachable && !sib.Discarded {
					sib.Reachable = true
					queue = append(queue, sib)
				}
			}
		}
	}

	l.roots(img, mark)

	for len(queue) > 0 {
		ch := queue[len(queue)-1]
		queue = queue[:len(queue)-1]

		relocs, err := ch.Relocs()
		if err != nil {
			return err
		}
		for _, r := range relocs {
			if r.Sym == nil {
				continue
			}
			r.Sym.Referenced = true
			mark(r.Sym.Chunk)
			if r.Sym.Frag != nil {
				r.Sym.Frag.Live = true
				mark(r.Sym.Frag.Parent)
			}
		}

		// SHF_LINK_ORDER ties a chunk's placement to another's, so the other
		// must survive if this one does.
		mark(ch.LinkOrder)
	}
	return nil
}

// groupKey identifies a section group within one input. The signature alone is
// not enough: two objects contribute groups with the same signature, and only
// one of them won.
type groupKey struct {
	in   *image.Input
	name string
}

func groupIndex(img *image.Image) map[groupKey][]*image.Chunk {
	out := make(map[groupKey][]*image.Chunk)
	for _, in := range img.Inputs {
		for _, ch := range in.Chunks {
			if ch.Group == "" {
				continue
			}
			k := groupKey{in, ch.Group}
			out[k] = append(out[k], ch)
		}
	}
	return out
}

// roots marks the chunks the sweep starts from.
//
// The list is conventional rather than specified — the gABI says nothing about
// garbage collection — so it follows what the mainstream linkers agree on.
func (l *Linker) roots(img *image.Image, mark func(*image.Chunk)) {
	markSym := func(name string) {
		if s := img.Syms.Lookup(name); s != nil {
			s.Referenced = true
			mark(s.Chunk)
		}
	}

	// The entry point, and anything the caller named explicitly.
	if l.opts.Output != OutputRelocatable {
		markSym(l.opts.entryName())
	}
	markSym("_init")
	markSym("_fini")
	for _, name := range l.opts.Undefined {
		markSym(name)
	}
	for name := range l.opts.Provide {
		markSym(name)
	}

	for _, in := range img.Inputs {
		for _, ch := range in.Chunks {
			if ch.Discarded {
				continue
			}
			switch {
			case isRootType(ch.Type):
				// Initialiser and finaliser arrays run whether or not
				// anything references them, so nothing ever would.
				mark(ch)

			case ch.Type == elf.SHT_NOTE && ch.Group == "":
				// A standalone note is metadata about the whole object and
				// has no referrer. One inside a group belongs to that group
				// and is swept with it.
				mark(ch)

			case ch.Flags&image.SecFlags(elf.SHF_GNU_RETAIN) != 0:
				mark(ch)

			case !ch.Flags.Alloc() && ch.Group == "":
				// Debug information is never reachable from code. Discarding
				// it would defeat the reason it was emitted.
				mark(ch)
			}

			for _, pat := range l.opts.Keep {
				if ok, _ := path.Match(pat, ch.Name); ok {
					mark(ch)
					break
				}
			}
		}
	}

	// Anything exported to the dynamic symbol table is reachable from
	// outside the link, so nothing inside it can prove otherwise.
	if l.reqs.Dynamic || l.opts.ExportDynamic {
		img.Syms.Each(func(s *image.Sym) {
			if s.Defined() && !s.Local() && (l.opts.ExportDynamic || s.ExportDynamic) {
				s.Referenced = true
				mark(s.Chunk)
			}
		})
	}
}

func isRootType(t elf.SHType) bool {
	switch t {
	case elf.SHT_INIT_ARRAY, elf.SHT_FINI_ARRAY, elf.SHT_PREINIT_ARRAY:
		return true
	}
	return false
}

// checkUndefined reports references that nothing defines.
//
// It runs after the sweep, so a reference from a section that turned out to be
// dead does not fail the link — which is the point of garbage collection, and
// checking earlier would make -gc-sections unable to drop code that references
// something absent.
func (l *Linker) checkUndefined(img *image.Image) error {
	if l.opts.AllowUndefined || l.opts.Output == OutputShared ||
		l.opts.Output == OutputRelocatable {
		return nil
	}

	var first *UndefinedError
	count := 0

	img.Syms.Each(func(s *image.Sym) {
		if s.Defined() || !s.Referenced {
			return
		}
		// A weak reference resolving to zero is the documented behaviour,
		// not a failure: code that takes one tests it before calling.
		if s.Bind == elf.STB_WEAK {
			return
		}
		count++
		if first == nil {
			from, in, off := l.findReference(img, s)
			first = &UndefinedError{Name: s.Name, From: from, In: in, Offset: off}
		}
	})

	if first == nil {
		return nil
	}
	if count > 1 {
		// Report one with full provenance rather than a wall of names; the
		// first is almost always the same mistake as the rest.
		return &multiUndefined{first: first, more: count - 1}
	}
	return first
}

// multiUndefined reports the first undefined reference and how many followed.
type multiUndefined struct {
	first *UndefinedError
	more  int
}

func (e *multiUndefined) Error() string {
	return e.first.Error() + " (and " + itoa(e.more) + " more)"
}

func (e *multiUndefined) Unwrap() error { return e.first }

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// findReference locates a live use of a symbol, so the error can say which
// object wanted it.
func (l *Linker) findReference(img *image.Image, sym *image.Sym) (*image.Input, *image.Chunk, uint64) {
	var found *image.Input
	var chunk *image.Chunk
	var off uint64

	img.Chunks(func(ch *image.Chunk) {
		if found != nil {
			return
		}
		relocs, err := ch.Relocs()
		if err != nil {
			return
		}
		for _, r := range relocs {
			if r.Sym == sym {
				found, chunk, off = ch.Input, ch, r.Offset
				return
			}
		}
	})
	return found, chunk, off
}