// Package backend is the boundary between the generic linker and everything a
// psABI decides.
//
// Addend widths, instruction-field encodings, PLT and GOT shapes, relaxation,
// thunk insertion, and REL implicit-addend recovery are all architecture
// properties. link calls only through this interface and never guesses them;
// a generic reader that assumes an addend is a machine word at the relocation
// offset is wrong on ARM before it reaches the second instruction.
//
// The interface is deliberately in two layers. Backend itself is what every
// architecture must provide to link a static executable — classify, scan,
// apply, recover. Everything beyond that is an optional interface a backend
// may also implement: Dynamic for PLT and GOT generation, Relaxer for
// instruction rewriting, Thunker for range extension, Flagger for e_flags
// merging. A backend that supports only static linking implements Backend and
// nothing else, and link discovers the rest by asking.
//
// This package is public. Backends are blank-imported by users, so they cannot
// reach into link's internals, and link must never import a backend: the
// registry below is the only thing that connects them.
package backend

import (
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/vertex-language/elf"
	"github.com/vertex-language/elf/image"
)

var (
	// ErrNoBackend reports a target with no registered backend. The usual
	// cause is a missing blank import of the architecture's package.
	ErrNoBackend = errors.New("backend: no backend registered for this architecture")

	// ErrUnsupportedReloc reports a relocation type the backend does not
	// implement. It is distinct from a malformed type: the object is valid,
	// this linker just cannot handle that relocation yet.
	ErrUnsupportedReloc = errors.New("backend: unsupported relocation type")
)

// Backend is the per-architecture behavior every link needs.
type Backend interface {
	// Arch identifies the architecture this backend serves.
	//
	// Arch, not Machine. EM_MIPS, EM_RISCV, and EM_LOONGARCH each cover a
	// 32- and a 64-bit architecture, so a registry keyed by e_machine would
	// hand a 64-bit backend to a 32-bit link and produce an output whose
	// every address is twice the width it should be.
	Arch() elf.Arch

	// Classify maps a relocation type to its architecture-independent
	// meaning, so that scan, garbage collection, and dynamic relocation
	// generation can reason about relocations without a table per machine.
	//
	// An unrecognised type returns KindUnknown rather than an error: the
	// caller decides whether that is fatal, and Apply reports it with the
	// section and offset that make it actionable.
	Classify(typ uint32) Kind

	// Scan walks every live relocation and records what the output needs:
	// GOT and PLT slots, copy relocations, TLS blocks, dynamic relocations.
	// It runs before layout, because those decisions determine the size of
	// the synthetic sections layout has to place.
	//
	// Scan assigns slot indexes and grows synthetics; it must not compute
	// addresses, which do not exist yet.
	Scan(img *image.Image, reqs *Reqs) error

	// Apply writes one relocation into the output.
	//
	// It runs after Freeze, so every address is final and the only failures
	// are semantic: an out-of-range displacement, an unsupported type, a
	// relocation naming no symbol.
	Apply(s *Site, r image.Reloc) error

	// RelAddend recovers the implicit addend of a REL relocation from the
	// section contents.
	//
	// The bool is false when the type has no implicit addend or the backend
	// cannot recover it. This is not a machine word read: on ARM an
	// R_ARM_CALL addend is a sign-extended 24-bit immediate inside the
	// instruction, and reading four raw bytes there gets the opcode too.
	RelAddend(content []byte, off uint64, typ uint32) (int64, bool)

	// DynType maps a dynamic relocation's meaning to this psABI's number for
	// it. The bool is false when the architecture has no such relocation.
	DynType(k DynKind) (uint32, bool)
}

// Dynamic is implemented by backends that can produce dynamic executables and
// shared objects. Static-only backends omit it, and link reports a clear
// failure rather than emitting a PLT of zeroes.
type Dynamic interface {
	// Got and Plt describe the table geometry: entry sizes, alignment, and
	// the reserved slots the dynamic loader owns.
	Got() GotShape
	Plt() PltShape

	// WriteGotPltHeader fills the reserved slots at the start of .got.plt.
	// buf is exactly Got().PltReserved * Got().EntrySize bytes.
	WriteGotPltHeader(buf []byte, s *Site) error

	// WriteGotPlt fills the .got.plt slot belonging to a PLT entry. For lazy
	// binding this points back into the PLT so the first call reaches the
	// resolver; for an ifunc it points at the resolver itself.
	WriteGotPlt(buf []byte, s *Site, sym *image.Sym) error

	// WritePltHeader fills PLT0, the resolver trampoline. buf is exactly
	// Plt().HeaderSize bytes. A backend with no lazy binding writes nothing
	// and reports HeaderSize zero.
	WritePltHeader(buf []byte, s *Site) error

	// WritePlt fills one PLT entry. pltAddr is the entry's run-time address
	// and gotAddr its .got.plt slot's; index is its position, which lazy
	// formats encode as the relocation index to push.
	WritePlt(buf []byte, s *Site, sym *image.Sym, pltAddr, gotAddr uint64, index int) error

	// WriteSecPlt fills the second-PLT entry for sym, when the format has
	// one. Intel CET splits each entry into a lazy stub in .plt and an
	// indirect jump in .plt.sec; buf is Plt().SecEntrySize bytes. Backends
	// reporting SecEntrySize zero are never called here.
	WriteSecPlt(buf []byte, s *Site, sym *image.Sym, pltAddr, gotAddr uint64, index int) error
}

// Relaxer is implemented by backends that rewrite instruction sequences during
// layout: GOT loads that became direct references, TLS access models narrowed
// from general-dynamic toward local-exec, RISC-V call sequences shrunk once
// the target turned out to be near.
//
// Relax runs inside the layout fixpoint and reports whether it changed
// anything. Returning true forces another round, so a backend that keeps
// reporting change without converging produces link.ErrLayoutDivergence rather
// than an infinite loop.
type Relaxer interface {
	Relax(img *image.Image, reqs *Reqs) (changed bool, err error)
}

// Thunker is implemented by architectures whose branches cannot reach the whole
// address space. x86-64 does not implement it: its call and jmp displacements
// cover ±2 GiB, and the compiler has already relaxed anything shorter.
type Thunker interface {
	// Thunk describes thunk geometry.
	Thunk() ThunkShape

	// InRange reports whether a branch of this relocation type at src can
	// reach dst directly. Ranges differ per type within one architecture —
	// ARM has several — so this takes the type rather than a single constant.
	InRange(typ uint32, src, dst uint64) bool

	// WriteThunk emits a trampoline to target at addr. buf is exactly
	// Thunk().Size bytes.
	WriteThunk(buf []byte, s *Site, target uint64, addr uint64) error
}

// Flagger is implemented by architectures where e_flags carries ABI facts that
// must agree across inputs — ARM's float ABI, MIPS's ABI and ISA levels.
//
// MergeFlags folds one input's flags into the accumulated output flags, or
// returns an error naming the incompatibility. Architectures whose e_flags is
// zero or advisory omit this, and link carries the first input's value.
type Flagger interface {
	MergeFlags(out, in uint32) (uint32, error)
}

// TlsOffsetter is implemented by backends that can compute the link-time
// offset from the thread pointer to a symbol in the output's static TLS
// block.
//
// This is the one piece of thread-local addressing link needs to do itself
// rather than leaving entirely to Apply: an initial-exec GOT slot's content,
// for a symbol this link resolves locally, is a plain number generated the
// same way regardless of which chunk or synthetic section it ends up in, and
// generating it does not belong in a backend's Apply, which only ever writes
// into one chunk's own bytes at a relocation site. Architectures split the
// static block relative to the thread pointer two different ways — variant
// II (x86) subtracts from the block's end and lands negative; variant I
// (ARM, RISC-V) adds a fixed or ABI-defined header to an offset from the
// start — and TpOff is where that difference lives.
type TlsOffsetter interface {
	// TpOff returns the thread-pointer-relative offset of the byte at
	// symAddr, which lies within the static TLS block described by tlsAddr,
	// tlsSize, and tlsAlign — the same three values link.Reqs.TlsAddr,
	// TlsSize, and TlsAlign carry once layout has placed PT_TLS.
	TpOff(tlsAddr, tlsSize, tlsAlign, symAddr uint64) int64
}

// AsDynamic, AsRelaxer, AsThunker, AsFlagger, and AsTlsOffsetter report
// whether a backend implements an optional interface. They exist so that
// link asks in one place and every call site reads the same way.

func AsDynamic(b Backend) (Dynamic, bool)           { d, ok := b.(Dynamic); return d, ok }
func AsRelaxer(b Backend) (Relaxer, bool)           { r, ok := b.(Relaxer); return r, ok }
func AsThunker(b Backend) (Thunker, bool)           { t, ok := b.(Thunker); return t, ok }
func AsFlagger(b Backend) (Flagger, bool)           { f, ok := b.(Flagger); return f, ok }
func AsTlsOffsetter(b Backend) (TlsOffsetter, bool) { t, ok := b.(TlsOffsetter); return t, ok }

var (
	mu       sync.RWMutex
	registry = make(map[elf.Arch]Backend)
)

// Register records a backend for its architecture. Backends call it from an
// init function, so that a blank import is all a user needs.
//
// It panics on a nil backend, an unknown architecture, or a second
// registration for one already taken. All three are build-time mistakes — two
// backends for the same architecture in one binary means the link's behavior
// depends on package initialisation order — and none is reachable from a file's
// contents.
func Register(b Backend) {
	if b == nil {
		panic("backend: Register(nil)")
	}
	a := b.Arch()
	if a == elf.ArchUnknown {
		panic("backend: Register of a backend reporting ArchUnknown")
	}

	mu.Lock()
	defer mu.Unlock()
	if prev, ok := registry[a]; ok {
		panic(fmt.Sprintf("backend: %v registered twice (%T and %T)", a, prev, b))
	}
	registry[a] = b
}

// For returns the backend for a target.
//
// The lookup is by Arch, which Target already carries in resolved form, so
// nothing here has to re-derive a width from e_machine.
func For(t elf.Target) (Backend, error) {
	if !t.Valid() {
		return nil, fmt.Errorf("backend: %v: %w", t, elf.ErrInvalidTarget)
	}
	return ForArch(t.Arch)
}

// ForArch returns the backend registered for an architecture.
func ForArch(a elf.Arch) (Backend, error) {
	mu.RLock()
	b, ok := registry[a]
	mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("backend: %v: %w (import the %v backend package for its side effects)",
			a, ErrNoBackend, a)
	}
	return b, nil
}

// Registered returns the architectures that have backends, sorted, for
// diagnostics that tell a user what this binary can actually link.
func Registered() []elf.Arch {
	mu.RLock()
	out := make([]elf.Arch, 0, len(registry))
	for a := range registry {
		out = append(out, a)
	}
	mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
