// Package image is the output model: the linked side of the module.
//
// An Image owns everything the emitter needs and nothing it does not. Input
// files contribute Chunks; the link pipeline groups those into OutputSections,
// covers the allocated ones with Segments, resolves names through a
// SymbolTable, and finally writes bytes into the Image's buffer.
//
// The Image moves through three one-way phases, and each pipeline step is
// legal in exactly one of them:
//
//	open    — inputs, chunks, output sections, and synthetics may be added
//	sealed  — the set of sections is fixed; ordering and addresses are assigned
//	frozen  — sizes and addresses are final; the byte buffer exists and is written
//
// Seal and Freeze are the transitions. They exist because the fixpoint in
// link.Link assigns addresses repeatedly, and a section appearing partway
// through that loop silently invalidates every address computed before it.
// Adding one after Seal panics: it is a bug in the pipeline, not bad input.
//
// This package performs no I/O and holds no file handles. It never panics on
// anything derived from an input file's contents; the panics it does have are
// documented on the methods that have them and all report caller sequencing
// errors.
package image

import (
	"errors"
	"fmt"

	"github.com/vertex-language/elf"
)

var (
	// ErrNotFrozen reports an attempt to touch the output buffer before
	// Freeze allocated it.
	ErrNotFrozen = errors.New("image: output buffer does not exist until Freeze")

	// ErrOutOfBounds reports a write outside the output buffer.
	ErrOutOfBounds = errors.New("image: write outside the output buffer")

	// ErrNoSize reports Freeze with no file size assigned. Address assignment
	// sets it; freezing before that would allocate a zero-length buffer and
	// turn every later write into an out-of-bounds error far from the cause.
	ErrNoSize = errors.New("image: file size was never assigned")
)

// phase is the Image's position in the open → sealed → frozen sequence.
type phase uint8

const (
	phaseOpen phase = iota
	phaseSealed
	phaseFrozen
)

func (p phase) String() string {
	switch p {
	case phaseSealed:
		return "sealed"
	case phaseFrozen:
		return "frozen"
	}
	return "open"
}

// Anchor names one end of a section or symbol range.
//
// It is the single anchor vocabulary for the module: link.SymbolExpr and the
// __start_/__stop_ machinery below use these same two constants rather than
// each inventing a "start or end?" bool.
type Anchor uint8

const (
	AnchorStart Anchor = iota
	AnchorEnd
)

func (a Anchor) String() string {
	if a == AnchorEnd {
		return "end"
	}
	return "start"
}

// Image is one link's output.
type Image struct {
	// Target is what is being produced. Every input is checked against it;
	// see link.ErrMachineMismatch.
	Target elf.Target

	// Type is e_type of the output: ET_EXEC, ET_DYN, or ET_REL for a
	// relocatable link.
	Type elf.Type

	// Entry is e_entry. Bound from EntrySym when that is set, so that
	// -e name and -e 0x1000 land in the same field by different routes.
	Entry    uint64
	EntrySym *Sym

	// Inputs are the contributing files, in link-line order.
	Inputs []*Input

	// Sections are the output sections. Ordering rewrites this slice; Index
	// is only meaningful once emit assigns it.
	Sections []*OutputSection

	// Segments are the program headers, in the order they will be written.
	Segments []*Segment

	// Syms is the global symbol table: one entry per name, whatever the
	// number of definitions that competed for it.
	Syms *SymbolTable

	// Synthetics are linker-generated chunks — .got, .plt, .dynamic, merged
	// string blobs — awaiting content generation.
	Synthetics []*Synthetic

	// FileSize is the total output length, set by address assignment. Freeze
	// allocates exactly this many bytes.
	FileSize uint64

	// Shoff is the file offset of the section header table, or zero when the
	// output has none. Set by assignment, written by emit.
	Shoff uint64

	// HeaderSize is the reserved prefix — the ELF header plus the program
	// headers — that no section may be placed into.
	HeaderSize uint64

	buf        []byte
	ph         phase
	sections   map[secKey]*OutputSection
	reserved   []*reserved
	finalizers []Finalizer
}

// New returns an open Image for the given target.
func New(t elf.Target) *Image {
	return &Image{
		Target:   t,
		Type:     elf.ET_EXEC,
		Syms:     NewSymbolTable(),
		sections: make(map[secKey]*OutputSection),
	}
}

// Sealed reports whether the set of output sections is fixed.
func (img *Image) Sealed() bool { return img.ph >= phaseSealed }

// Frozen reports whether addresses are final and the buffer exists.
func (img *Image) Frozen() bool { return img.ph >= phaseFrozen }

// Seal fixes the set of output sections. It panics if called twice, which
// would mean the pipeline ran a phase out of order.
func (img *Image) Seal() {
	if img.ph != phaseOpen {
		panic("image: Seal on an image that is already " + img.ph.String())
	}
	img.ph = phaseSealed
}

// Freeze fixes addresses and sizes and allocates the output buffer.
//
// FileSize must already be set. Freeze is the boundary between "deciding where
// bytes go" and "writing bytes": nothing before it may write, and nothing
// after it may move anything.
func (img *Image) Freeze() error {
	if img.ph == phaseFrozen {
		panic("image: Freeze called twice")
	}
	if img.ph != phaseSealed {
		panic("image: Freeze before Seal")
	}
	if img.FileSize == 0 {
		return ErrNoSize
	}
	if img.FileSize > uint64(maxInt) {
		return fmt.Errorf("image: output of %d bytes exceeds the maximum slice size", img.FileSize)
	}
	img.buf = make([]byte, img.FileSize)
	img.ph = phaseFrozen
	return nil
}

// maxInt is the largest value an int holds on this platform.
const maxInt = int(^uint(0) >> 1)

// Bytes returns the output buffer. It returns nil before Freeze.
//
// The result aliases the Image; writing through it is how emit and relocation
// application work, and is why this is not a copy.
func (img *Image) Bytes() []byte { return img.buf }

// SliceAt returns a writable view of n bytes at file offset off.
//
// Every write into the output goes through this or CopyAt, so that a bad
// offset is one error here rather than a panic somewhere in a backend's Apply.
func (img *Image) SliceAt(off, n uint64) ([]byte, error) {
	if img.buf == nil {
		return nil, ErrNotFrozen
	}
	total := uint64(len(img.buf))
	if off > total || n > total-off {
		return nil, fmt.Errorf("image: %d bytes at %#x in a %d-byte output: %w",
			n, off, total, ErrOutOfBounds)
	}
	return img.buf[off : off+n], nil
}

// CopyAt writes b at file offset off.
func (img *Image) CopyAt(off uint64, b []byte) error {
	dst, err := img.SliceAt(off, uint64(len(b)))
	if err != nil {
		return err
	}
	copy(dst, b)
	return nil
}

// Section returns the output section with the given identity, creating it if
// it does not exist.
//
// Sections are keyed by name, flags, and type rather than by name alone. ELF
// permits two .text sections in one output, and a linker that renames the
// second to .text$1 on its way to disk is producing a file that does not say
// what it was asked to say. Type is part of the key because merging an
// SHT_NOBITS section into an SHT_PROGBITS one of the same name and flags would
// silently give the result file contents it must not have.
//
// It panics if the image is sealed.
func (img *Image) Section(name string, typ elf.SHType, flags SecFlags) *OutputSection {
	if img.Sealed() {
		panic("image: Section(" + name + ") on a sealed image")
	}
	k := secKey{name: name, typ: typ, flags: flags}
	if s, ok := img.sections[k]; ok {
		return s
	}
	s := &OutputSection{Name: name, Type: typ, Flags: flags, Align: 1}
	img.sections[k] = s
	img.Sections = append(img.Sections, s)
	return s
}

// FindSection returns the first output section with the given name, or nil.
//
// Names are not unique, so this is for the cases where the caller knows there
// is at most one — the __start_/__stop_ brackets, .dynamic, .got. Use
// Sections when that is not known.
func (img *Image) FindSection(name string) *OutputSection {
	for _, s := range img.Sections {
		if s.Name == name {
			return s
		}
	}
	return nil
}

// AddSegment appends a program header.
func (img *Image) AddSegment(seg *Segment) {
	img.Segments = append(img.Segments, seg)
}

// AddInput records a contributing file.
func (img *Image) AddInput(in *Input) {
	in.Ordinal = len(img.Inputs)
	img.Inputs = append(img.Inputs, in)
}

// AddSynthetic registers a linker-generated chunk. It panics if the image is
// sealed: a synthetic that appears after sealing has no output section to be
// placed in.
func (img *Image) AddSynthetic(s *Synthetic) {
	if img.Sealed() {
		panic("image: AddSynthetic(" + s.Chunk.Name + ") on a sealed image")
	}
	img.Synthetics = append(img.Synthetics, s)
}

// AddFinalizer registers work that must run after every byte of the output has
// been written. A build-id hash is the motivating case: it covers the whole
// file, so it can only be computed once the file is complete, and it then
// patches bytes that were written earlier.
func (img *Image) AddFinalizer(f Finalizer) { img.finalizers = append(img.finalizers, f) }

// reserved is a symbol whose value is a fact about the output — the end of
// .bss, the start of a section — and so cannot be known until addresses exist.
type reserved struct {
	sym   *Sym
	value func(*Image) uint64
}

// Reserve defines a symbol whose value is computed at bind time.
//
// The symbol is created immediately, so that references to it resolve and the
// undefined check passes, but its value stays zero until BindReserved runs
// inside the layout fixpoint. Defining it eagerly with a wrong value instead
// would produce an output that links cleanly and jumps to the wrong address.
func (img *Image) Reserve(name string, value func(*Image) uint64) *Sym {
	s, _ := img.Syms.Insert(name)
	s.Class = SymAbsolute
	s.Bind = elf.STB_GLOBAL
	s.Other = elf.WithVisibility(s.Other, elf.STV_HIDDEN)
	s.Reserved = true
	img.reserved = append(img.reserved, &reserved{sym: s, value: value})
	return s
}

// BindReserved recomputes every reserved symbol's value. It runs once per
// iteration of the layout fixpoint, because relaxation can move the addresses
// these symbols describe.
func (img *Image) BindReserved() {
	for _, r := range img.reserved {
		r.sym.Value = r.value(img)
	}
}

// DeclareStartStop defines the __start_NAME and __stop_NAME brackets.
//
// The gABI convention: a reference to __start_foo or __stop_foo is satisfied by
// the linker with the bounds of the output section named foo, for any name that
// is a C identifier. Only referenced brackets are defined — declaring all of
// them would retain every such section against the GC sweep.
//
// This runs before output sections exist, so the bounds are looked up lazily by
// name at bind time. A bracket whose section is discarded entirely resolves to
// zero, which is what other linkers produce.
func (img *Image) DeclareStartStop() {
	seen := make(map[string]bool)
	for _, in := range img.Inputs {
		for _, ch := range in.Chunks {
			name := ch.Name
			if seen[name] || !isCIdentifier(name) {
				continue
			}
			seen[name] = true

			if s := img.Syms.Lookup("__start_" + name); s != nil && !s.Defined() {
				n := name
				img.Reserve("__start_"+n, func(i *Image) uint64 {
					return sectionBound(i, n, AnchorStart)
				})
			}
			if s := img.Syms.Lookup("__stop_" + name); s != nil && !s.Defined() {
				n := name
				img.Reserve("__stop_"+n, func(i *Image) uint64 {
					return sectionBound(i, n, AnchorEnd)
				})
			}
		}
	}
}

func sectionBound(img *Image, name string, at Anchor) uint64 {
	sec := img.FindSection(name)
	if sec == nil {
		return 0
	}
	if at == AnchorEnd {
		return sec.Addr + sec.Size
	}
	return sec.Addr
}

// isCIdentifier reports whether s can appear in a __start_/__stop_ bracket.
// Section names beginning with a dot — .text, .data — are excluded by the
// leading-digit-or-letter rule, which is the intent: there is no __start_.text.
func isCIdentifier(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c == '_':
		case c >= '0' && c <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}

// Chunks calls fn for every live chunk of every input, in input order and then
// chunk order. Discarded and unreachable chunks are skipped, so callers cannot
// forget to check both flags.
func (img *Image) Chunks(fn func(*Chunk)) {
	for _, in := range img.Inputs {
		for _, ch := range in.Chunks {
			if ch.Live() {
				fn(ch)
			}
		}
	}
}

// GenerateSynthetics fills every registered synthetic chunk's contents.
//
// It runs after addresses are final, because a .got entry holds an address and
// .dynamic holds section offsets. Each generator's output is checked against
// the size the chunk was laid out with: a synthetic that grows after layout has
// already overrun its neighbour, and saying so here beats debugging the
// resulting overlap.
func GenerateSynthetics(img *Image) error {
	for _, s := range img.Synthetics {
		if err := s.Generate(img); err != nil {
			return err
		}
	}
	return nil
}

// Finalize runs every registered Finalizer, in registration order.
//
// This is the hash-then-patch step: the output is complete, and a finalizer may
// read all of it and write back into it, but may not change its length.
func Finalize(img *Image) error {
	if !img.Frozen() {
		return ErrNotFrozen
	}
	for _, f := range img.finalizers {
		if err := f.Finalize(img); err != nil {
			return err
		}
	}
	return nil
}