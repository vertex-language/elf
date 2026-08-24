package link

import (
	"github.com/vertex-language/elf"
	"github.com/vertex-language/elf/image"
)

// Relro selects how much of the output is made read-only after the dynamic
// loader has applied relocations.
type Relro uint8

const (
	// RelroNone emits no PT_GNU_RELRO.
	RelroNone Relro = iota

	// RelroPartial covers .data.rel.ro, .init_array, .fini_array, and .got,
	// leaving .got.plt writable so lazy binding still works.
	RelroPartial

	// RelroFull additionally forces eager binding, which lets .got.plt join
	// the read-only region. It implies BindNow; the two are one decision
	// wearing two names, because a read-only .got.plt with lazy binding is a
	// program that faults on its first library call.
	RelroFull
)

func (r Relro) String() string {
	switch r {
	case RelroPartial:
		return "partial"
	case RelroFull:
		return "full"
	}
	return "none"
}

// Output selects what kind of file the link produces.
type Output uint8

const (
	// OutputExec is a non-PIE executable at a fixed base address.
	OutputExec Output = iota

	// OutputPIE is a position-independent executable: ET_DYN with an entry
	// point.
	OutputPIE

	// OutputShared is a shared object.
	OutputShared

	// OutputRelocatable is a partial link: ET_REL in, ET_REL out, with
	// relocations preserved rather than applied.
	OutputRelocatable
)

func (o Output) String() string {
	switch o {
	case OutputPIE:
		return "pie"
	case OutputShared:
		return "shared"
	case OutputRelocatable:
		return "relocatable"
	}
	return "exec"
}

// Type returns the e_type this output kind writes.
func (o Output) Type() elf.Type {
	switch o {
	case OutputPIE, OutputShared:
		return elf.ET_DYN
	case OutputRelocatable:
		return elf.ET_REL
	}
	return elf.ET_EXEC
}

// Pic reports whether the output must be position-independent, and therefore
// whether an absolute reference needs a dynamic relocation rather than a
// link-time value.
func (o Output) Pic() bool { return o == OutputPIE || o == OutputShared }

// SymbolExpr describes a symbol the caller wants defined at a position in the
// output, for the bare-metal and embedded layouts that would otherwise need a
// linker script.
type SymbolExpr struct {
	// Section names the output section the symbol is anchored to.
	Section string

	// At selects which end. It is image.Anchor rather than a local bool
	// because this module has one anchor vocabulary.
	At image.Anchor

	// Offset is added to the anchor.
	Offset int64

	// Align rounds the result up, for a stack or heap boundary that must sit
	// on a known multiple. Zero means no rounding.
	Align uint64
}

// Options is the single configuration truth for a link.
//
// Everything the caller can decide is here, in one struct, rather than spread
// across setter methods with implicit ordering. Linker exposes convenience
// setters for the common cases, but they write into this.
type Options struct {
	// Output selects the kind of file produced.
	Output Output

	// Entry is the entry point symbol. Empty means the default, "_start".
	// EntryAddr overrides it with a raw address when non-zero.
	Entry     string
	EntryAddr uint64

	// Static suppresses dynamic linking entirely: no .dynamic, no PLT, no
	// interpreter. Shared inputs are rejected rather than silently ignored.
	Static bool

	// Interp is the program interpreter path written to .interp. Empty uses
	// the platform default for the target.
	Interp string

	// SOName is DT_SONAME for a shared object.
	SOName string

	// RPath and RunPath become DT_RPATH and DT_RUNPATH. Prefer RunPath;
	// DT_RPATH is deprecated and is searched before LD_LIBRARY_PATH, which
	// is rarely what anyone wants.
	RPath   []string
	RunPath []string

	// AsNeeded omits a DT_NEEDED for a shared input that nothing in the link
	// actually references.
	AsNeeded bool

	// Relro selects the read-only-after-relocation region. RelroFull implies
	// BindNow.
	Relro Relro

	// BindNow sets DF_BIND_NOW and DF_1_NOW, making the loader resolve every
	// PLT slot before the program runs.
	BindNow bool

	// GC discards sections no root reaches.
	GC bool

	// Keep are section name patterns that are GC roots regardless of
	// reachability, matched with path.Match semantics. ".init_array*" is the
	// usual case.
	Keep []string

	// Undefined are symbols to treat as referenced before the link starts,
	// which is what forces an archive member in that nothing else needs.
	Undefined []string

	// ExportDynamic puts every global definition into .dynsym, not just the
	// ones something requires.
	ExportDynamic bool

	// AllowMultipleDefinition downgrades a duplicate definition to a warning
	// and keeps the first.
	AllowMultipleDefinition bool

	// AllowUndefined permits unresolved references in the output. It is the
	// default for a shared object and never the default for an executable,
	// where an unresolved name is a program that fails at load.
	AllowUndefined bool

	// StripDebug drops non-allocated debug sections. StripAll additionally
	// drops .symtab and .strtab.
	StripDebug bool
	StripAll   bool

	// BuildID emits a .note.gnu.build-id whose contents hash the finished
	// file. The hash is computed by a Finalizer, since it covers bytes that
	// do not exist until the output is complete.
	BuildID bool

	// ImageBase overrides the target's default load address for a
	// non-PIE executable. Zero uses elf.Arch.BaseAddress.
	ImageBase uint64

	// MaxPageSize and CommonPageSize override the target's defaults. Zero
	// uses elf.Arch.MaxPageSize and elf.Arch.CommonPageSize.
	MaxPageSize    uint64
	CommonPageSize uint64

	// SeparateCode gives executable content its own PT_LOAD rather than
	// sharing one with read-only data, so that no page is both writable-
	// adjacent and executable.
	SeparateCode bool

	// SectionOrder names output sections that must come first, in this
	// order. Sections not listed follow, ordered by the default rank table.
	SectionOrder []string

	// SectionAddress pins output sections to fixed addresses, for bare-metal
	// and UEFI layouts.
	SectionAddress map[string]uint64

	// Provide defines symbols at positions in the output.
	Provide map[string]SymbolExpr

	// Groups are index ranges over the input file list that are re-scanned
	// until no new member is extracted, the equivalent of --start-group and
	// --end-group. Archives inside one behave as a single archive.
	Groups []Group

	// MaxLayoutRounds bounds the relax and thunk fixpoint. Zero uses
	// DefaultMaxLayoutRounds. Exceeding it is ErrLayoutDivergence, never a
	// silent truncation of the loop.
	MaxLayoutRounds int
}

// Group is a half-open range of input file indexes scanned to a fixpoint.
type Group struct{ First, Last int }

// DefaultMaxLayoutRounds bounds the convergence loop.
//
// Relaxation shrinks sequences and thunk growth expands them, so a pathological
// input can oscillate: shrinking a call brings a branch into range, removing a
// thunk, which pushes the call back out of range. Real links converge in a
// handful of rounds; anything approaching this bound is a bug in a backend's
// relaxation, not a large program.
const DefaultMaxLayoutRounds = 32

// rounds returns the configured bound.
func (o *Options) rounds() int {
	if o.MaxLayoutRounds > 0 {
		return o.MaxLayoutRounds
	}
	return DefaultMaxLayoutRounds
}

// maxPage and commonPage resolve the page sizes for a target.
func (o *Options) maxPage(t elf.Target) uint64 {
	if o.MaxPageSize != 0 {
		return o.MaxPageSize
	}
	return t.Arch.MaxPageSize()
}

func (o *Options) commonPage(t elf.Target) uint64 {
	if o.CommonPageSize != 0 {
		return o.CommonPageSize
	}
	return t.Arch.CommonPageSize()
}

// base resolves the load address for a non-PIE executable.
func (o *Options) base(t elf.Target) uint64 {
	if o.Pic() {
		return 0
	}
	if o.ImageBase != 0 {
		return o.ImageBase
	}
	return t.Arch.BaseAddress()
}

// Pic reports whether the output must be position-independent.
func (o *Options) Pic() bool { return o.Output.Pic() }

// bindNow folds the two ways of asking for eager binding into one answer.
func (o *Options) bindNow() bool { return o.BindNow || o.Relro == RelroFull }

// entryName returns the entry symbol to look up.
func (o *Options) entryName() string {
	if o.Entry != "" {
		return o.Entry
	}
	return "_start"
}