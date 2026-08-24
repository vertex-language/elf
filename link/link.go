// Package link is the link pipeline: symbol resolution, garbage collection,
// layout, relocation, and emission.
//
// It is one package on purpose. An earlier cut split resolve, gc, and layout
// into three, and the boundaries cost five injected callbacks — RelocsFunc,
// RetainFunc, AttachFunc, SegmentFunc, GrowFunc — whose contracts were written
// down nowhere and none of which had a second caller. The steps here take
// *image.Image and *Options directly.
//
// Link is a straight-line sequence with exactly one convergence loop. The
// earlier cut nested a growth fixpoint inside address assignment and then
// wrapped assignment in a relaxation fixpoint, which is how a link
// non-converges only on inputs large enough that nobody can reduce them.
//
// link never imports a backend. It reaches architecture-specific behavior
// through backend.Backend, which the user supplies by blank-importing the
// backend package.
package link

import (
	"fmt"

	"github.com/vertex-language/elf"
	"github.com/vertex-language/elf/backend"
	"github.com/vertex-language/elf/image"
	"github.com/vertex-language/elf/internal/strtab"
)

// Linker performs one link. It is not reusable: Link may be called once.
type Linker struct {
	target elf.Target
	opts   Options

	files []*inputFile
	be    backend.Backend

	img  *image.Image
	reqs *backend.Reqs

	// thunks maps a branch target to the trampoline that reaches it, one per
	// output section. redirect records which relocation sites were sent
	// through one, so that Apply can substitute the trampoline's address for
	// the target's.
	//
	// Both are keyed rather than stored on the chunk because a chunk does
	// not own its relocations — they are read through its source and cached,
	// and rewriting them in place would make the cache lie about the input.
	thunks   map[thunkKey]*thunkEntry
	redirect map[relocSite]uint64

	// The output symbol table and the string tables that describe it. Built
	// once, before the image is sealed, because a symbol's name is known
	// then even though its value is not. genSymtab fills in the values after
	// layout has settled.
	outSyms  []*image.Sym
	symNames map[*image.Sym]uint32
	shNames  map[*image.OutputSection]*strtab.Ref

	strSec   *image.Synthetic
	symSec   *image.Synthetic
	shstrSec *image.Synthetic

	done bool
}

// New returns a Linker for a target with default options.
func New(t elf.Target) *Linker {
	return &Linker{
		target: t,
		opts: Options{
			Output:  OutputExec,
			Relro:   RelroPartial,
			Provide: make(map[string]SymbolExpr),
		},
	}
}

// Target returns the output target.
func (l *Linker) Target() elf.Target { return l.target }

// Options returns a pointer to the configuration, for callers that would
// rather set fields than call setters.
func (l *Linker) Options() *Options { return &l.opts }

// SetOptions replaces the configuration wholesale.
func (l *Linker) SetOptions(o Options) {
	if o.Provide == nil {
		o.Provide = make(map[string]SymbolExpr)
	}
	l.opts = o
}

// SetEntry sets the entry point symbol.
func (l *Linker) SetEntry(name string) { l.opts.Entry = name }

// SetSectionOrder pins the leading output sections.
func (l *Linker) SetSectionOrder(names []string) { l.opts.SectionOrder = names }

// SetSectionAddress pins an output section to an address.
func (l *Linker) SetSectionAddress(name string, addr uint64) {
	if l.opts.SectionAddress == nil {
		l.opts.SectionAddress = make(map[string]uint64)
	}
	l.opts.SectionAddress[name] = addr
}

// Provide defines a symbol at a position in the output.
func (l *Linker) Provide(name string, e SymbolExpr) {
	if l.opts.Provide == nil {
		l.opts.Provide = make(map[string]SymbolExpr)
	}
	l.opts.Provide[name] = e
}

// Keep adds a GC root pattern.
func (l *Linker) Keep(pattern string) { l.opts.Keep = append(l.opts.Keep, pattern) }

// Undefined forces a symbol to be treated as referenced, which pulls in the
// archive member defining it.
func (l *Linker) Undefined(name string) { l.opts.Undefined = append(l.opts.Undefined, name) }

// Link runs the pipeline and returns the finished image.
//
// The sequence below is the whole design. Each step reads what the previous
// ones wrote and writes into the same *image.Image; the phase transitions —
// Seal, Freeze — are what stop a later step from invalidating an earlier
// one's results.
func (l *Linker) Link() (*image.Image, error) {
	if l.done {
		return nil, fmt.Errorf("link: Link called twice")
	}
	l.done = true

	if !l.target.Valid() {
		return nil, fmt.Errorf("link: %w: %v", elf.ErrInvalidTarget, l.target)
	}

	be, err := backend.For(l.target)
	if err != nil {
		return nil, err
	}
	l.be = be

	img := image.New(l.target)
	img.Type = l.opts.Output.Type()
	l.img = img

	dynamic := !l.opts.Static && l.opts.Output != OutputRelocatable
	l.reqs = backend.NewReqs(be, l.opts.Pic(), dynamic)

	// 1. Symbols: load inputs in link order, run the archive fixpoint, and
	//    settle COMDAT elections.
	if err := l.resolve(img); err != nil {
		return nil, err
	}

	// 1a. __start_/__stop_ brackets, which can only be declared once every
	//     reference in the link is known.
	img.DeclareStartStop()

	// 2. Split .eh_frame into CIEs and FDEs, and mergeable sections into
	//    fragments. Before GC, so the sweep works at fragment granularity.
	if err := l.split(img); err != nil {
		return nil, err
	}

	// 3. Reachability. Sets Chunk.Reachable; never clears Discarded.
	if err := l.gc(img); err != nil {
		return nil, err
	}

	// After the sweep, so a reference from a section that turned out to be
	// dead does not fail the link.
	if err := l.checkUndefined(img); err != nil {
		return nil, err
	}

	// 4. Allocate commons, decompress, deduplicate, and group chunks into
	//    output sections.
	if err := l.merge(img); err != nil {
		return nil, err
	}

	// 5. Scan relocations: GOT, PLT, copy relocations, TLS, dynamic
	//    relocations. This is what sizes the synthetic sections.
	if err := l.be.Scan(img, l.reqs); err != nil {
		return nil, err
	}
	if err := l.registerSynthetics(img); err != nil {
		return nil, err
	}

	// 6. Ordering, including RELRO grouping. This is the last step that may
	//    create an output section: the RELRO region needs a padding section
	//    to reach a page boundary, and it cannot know that until the
	//    region's extent is known.
	if err := l.order(img); err != nil {
		return nil, err
	}

	// The set of output sections is now fixed.
	img.Seal()

	// 7. The one fixpoint. Addresses, thunk growth, and relaxation feed each
	//    other; nothing else in the pipeline iterates.
	relaxer, canRelax := backend.AsRelaxer(l.be)
	for round := 0; ; round++ {
		if round >= l.opts.rounds() {
			return nil, fmt.Errorf("link: %w after %d rounds", ErrLayoutDivergence, round)
		}

		if err := l.assign(img); err != nil {
			return nil, err
		}
		img.BindReserved()
		if err := l.bind(img); err != nil {
			return nil, err
		}

		grew, err := l.growThunks(img)
		if err != nil {
			return nil, err
		}

		relaxed := false
		if canRelax {
			relaxed, err = relaxer.Relax(img, l.reqs)
			if err != nil {
				return nil, err
			}
		}

		if !grew && !relaxed {
			break
		}
	}

	// 8. Final binding, now that nothing will move again.
	if err := l.commit(img); err != nil {
		return nil, err
	}
	if err := l.bindDynamic(img); err != nil {
		return nil, err
	}

	// Addresses and sizes are final; the output buffer exists from here on.
	if err := img.Freeze(); err != nil {
		return nil, err
	}

	// 9. Contents, then relocations.
	if err := l.writeChunks(img); err != nil {
		return nil, err
	}
	if err := image.GenerateSynthetics(img); err != nil {
		return nil, err
	}
	if err := l.applyAll(img); err != nil {
		return nil, err
	}

	// 10. Headers.
	if err := l.emit(img); err != nil {
		return nil, err
	}

	// 11. Anything that had to see the finished file, such as a build-id.
	if err := image.Finalize(img); err != nil {
		return nil, err
	}
	return img, nil
}