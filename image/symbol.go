package image

import (
	"fmt"

	"github.com/vertex-language/elf"
)

// SymClass says what kind of thing a symbol names, and therefore how to read
// its Value.
//
// Deliberately not called Class: elf.Class is the module's single
// representation of 32-vs-64, and a second Class in a package the linker uses
// constantly would make img.Class read as a width to everyone who has read the
// design rules.
type SymClass uint8

const (
	// SymUndefined is a reference with no definition yet.
	SymUndefined SymClass = iota

	// SymRegular is defined at Value bytes into Chunk, or at FragOff bytes
	// into Frag when the definition landed in a mergeable section.
	SymRegular

	// SymAbsolute has Value as its address, not subject to relocation.
	SymAbsolute

	// SymCommon is an unallocated block: Value is an alignment and Size the
	// number of bytes required. Resolution converts survivors to SymRegular
	// against a .bss chunk, so nothing after that phase should see one.
	SymCommon

	// SymShared is defined by a dependency shared object. It has no chunk in
	// this link; the dynamic loader supplies the address.
	SymShared
)

func (c SymClass) String() string {
	switch c {
	case SymRegular:
		return "regular"
	case SymAbsolute:
		return "absolute"
	case SymCommon:
		return "common"
	case SymShared:
		return "shared"
	}
	return "undefined"
}

// NoIndex marks a table slot a symbol has not been assigned.
//
// Zero is a real GOT, PLT, and dynamic symbol index, so the unassigned state
// needs its own value. Symbols must therefore be created through
// SymbolTable.Insert, which sets these; a Sym built with a struct literal
// claims to own entry zero of every table.
const NoIndex int32 = -1

// Sym is one name in the output, whatever the number of definitions that
// competed for it.
//
// Info and Other are kept in their raw ELF forms where the psABI puts meaning
// above the part the gABI defines — PPC64's local entry offset lives in the top
// bits of st_other — so a read-modify-write preserves what this module does not
// interpret.
type Sym struct {
	Name  string
	Class SymClass
	Bind  elf.SymBind
	Type  elf.SymType

	// Other is the raw st_other byte. Use elf.WithVisibility to change the
	// visibility field without disturbing the psABI bits above it.
	Other uint8

	// Value means different things per Class: an offset into Chunk for
	// SymRegular, an address for SymAbsolute, an alignment for SymCommon.
	Value uint64
	Size  uint64

	// Chunk is the definition's home, or nil. Frag and FragOff are set
	// instead when the definition is inside a mergeable section, because the
	// piece may be deduplicated into a different chunk than the one it was
	// read from.
	Chunk   *Chunk
	Frag    *Fragment
	FragOff uint64

	// Input is the file the winning definition came from, for diagnostics and
	// for duplicate-definition errors that must name both sides.
	Input *Input

	// Reserved marks a symbol the linker defines itself, whose value is
	// recomputed by Image.BindReserved on every layout iteration.
	Reserved bool

	// Referenced records that some relocation or command-line option names
	// this symbol. GC roots and the undefined check both read it.
	Referenced bool

	// ExportDynamic forces the symbol into .dynsym even when nothing in the
	// link requires it.
	ExportDynamic bool

	// Flags are the backend's scan decisions.
	Flags SymFlags

	// GotIndex, PltIndex, DynIndex, and GotPltIndex are slot assignments,
	// NoIndex until assigned.
	GotIndex int32
	PltIndex int32
	DynIndex int32

	// GotPltIndex is the symbol's slot in .got.plt, separate from PltIndex:
	// .plt and .iplt entries share one .got.plt, allocated by AddPlt and
	// AddIPlt in call order, and PltIndex alone is ambiguous once both kinds
	// of entry appear in the same link. See Reqs.GotPltSlotAddr.
	GotPltIndex int32
}

// SymFlags records what the scan pass decided this symbol needs.
type SymFlags uint16

const (
	// NeedsGot: the symbol is referenced through the global offset table.
	NeedsGot SymFlags = 1 << iota

	// NeedsPlt: calls to the symbol go through a procedure linkage entry.
	NeedsPlt

	// NeedsCopy: a definition in a shared object must be copied into the
	// executable's .bss so that non-PIC references keep working.
	NeedsCopy

	// NeedsTlsGd, NeedsTlsLd, NeedsTlsIe: the symbol is reached through the
	// corresponding thread-local access model and needs its GOT pair.
	NeedsTlsGd
	NeedsTlsLd
	NeedsTlsIe
)

// Has reports whether every flag in f is set on the symbol.
func (s *Sym) Has(f SymFlags) bool { return s.Flags&f == f }

// Set adds flags.
func (s *Sym) Set(f SymFlags) { s.Flags |= f }

// Visibility returns the symbol's visibility from st_other.
func (s *Sym) Visibility() elf.SymVisibility { return elf.Visibility(s.Other) }

// SetVisibility replaces the visibility, preserving psABI bits above it.
func (s *Sym) SetVisibility(v elf.SymVisibility) { s.Other = elf.WithVisibility(s.Other, v) }

// Defined reports whether this link has a definition for the symbol. A shared
// definition counts: the name resolves, even though the address does not exist
// until run time.
func (s *Sym) Defined() bool { return s.Class != SymUndefined }

// Local reports whether the symbol is invisible outside the output.
func (s *Sym) Local() bool {
	return s.Bind == elf.STB_LOCAL || !s.Visibility().Exported()
}

// Weak reports whether an undefined reference to this symbol is permitted to
// go unresolved, resolving to zero instead.
func (s *Sym) Weak() bool { return s.Bind == elf.STB_WEAK }

// Preemptible reports whether a definition of this symbol may be overridden at
// run time by one of the same name in another component.
func (s *Sym) Preemptible() bool {
	return s.Visibility().Preemptible() && s.Bind != elf.STB_LOCAL
}

// Addr returns the symbol's run-time address.
//
// A fragment definition follows the dedup redirect, so a symbol pointing at a
// deduplicated string resolves to the surviving copy rather than to space that
// no longer exists.
func (s *Sym) Addr() uint64 {
	switch s.Class {
	case SymAbsolute:
		return s.Value
	case SymRegular:
		if s.Frag != nil {
			return s.Frag.Addr() + s.FragOff
		}
		if s.Chunk != nil {
			return s.Chunk.Addr() + s.Value
		}
	}
	return 0
}

// Live reports whether the symbol's definition survived COMDAT election and
// the GC sweep. Undefined, absolute, and shared symbols are always live: they
// have no chunk to be swept.
func (s *Sym) Live() bool {
	if s.Chunk == nil {
		return true
	}
	return s.Chunk.Live()
}

func (s *Sym) String() string {
	if s.Name == "" {
		return fmt.Sprintf("<anonymous %v>", s.Class)
	}
	return s.Name
}

// SymbolTable is the link's global namespace: one Sym per name.
//
// Resolution policy — which of several definitions wins, when an archive
// member is pulled in, how a COMDAT election is decided — lives in link, not
// here. This type owns identity and iteration order and nothing else.
type SymbolTable struct {
	byName map[string]*Sym
	order  []*Sym
}

// NewSymbolTable returns an empty table.
func NewSymbolTable() *SymbolTable {
	return &SymbolTable{byName: make(map[string]*Sym)}
}

// Lookup returns the symbol with this name, or nil.
func (t *SymbolTable) Lookup(name string) *Sym { return t.byName[name] }

// Insert returns the symbol with this name, creating an undefined one if it
// does not exist. The bool reports whether the symbol is new.
//
// This is the only constructor for a Sym: it is what sets GotIndex, PltIndex,
// and DynIndex to NoIndex, and a symbol built any other way silently claims
// entry zero of all three tables.
func (t *SymbolTable) Insert(name string) (*Sym, bool) {
	if s, ok := t.byName[name]; ok {
		return s, false
	}
	s := &Sym{
		Name:        name,
		Class:       SymUndefined,
		GotIndex:    NoIndex,
		PltIndex:    NoIndex,
		DynIndex:    NoIndex,
		GotPltIndex: NoIndex,
	}
	t.byName[name] = s
	t.order = append(t.order, s)
	return s, true
}

// Local returns a symbol that is not entered into the namespace.
//
// File-local symbols — STB_LOCAL entries, section symbols — do not participate
// in resolution: two objects may each define a local "tmp" without conflict.
// They still need to exist as Syms because relocations point at them.
func (t *SymbolTable) Local(name string) *Sym {
	return &Sym{
		Name:        name,
		Class:       SymUndefined,
		Bind:        elf.STB_LOCAL,
		GotIndex:    NoIndex,
		PltIndex:    NoIndex,
		DynIndex:    NoIndex,
		GotPltIndex: NoIndex,
	}
}

// Len returns the number of global symbols.
func (t *SymbolTable) Len() int { return len(t.order) }

// All returns every global symbol in insertion order. The result aliases the
// table's own slice; callers that mutate it must copy first.
func (t *SymbolTable) All() []*Sym { return t.order }

// Each calls fn for every global symbol, in insertion order.
func (t *SymbolTable) Each(fn func(*Sym)) {
	for _, s := range t.order {
		fn(s)
	}
}