package backend

// GotShape describes the global offset table's geometry.
//
// There are two tables, not one. .got holds slots referenced directly by code;
// .got.plt holds the slots PLT entries jump through, and begins with slots the
// dynamic loader writes rather than the linker. Keeping them separate is what
// lets .got be mapped read-only after relocation while .got.plt stays writable
// for lazy binding.
type GotShape struct {
	// EntrySize is one slot's width — the class width on every architecture
	// this module targets.
	EntrySize uint64

	// Align is the alignment both tables require.
	Align uint64

	// Reserved is the number of slots at the start of .got the linker must
	// leave alone. Zero on most architectures.
	Reserved int

	// PltReserved is the number of slots at the start of .got.plt owned by
	// the dynamic loader, so the first entry belonging to a PLT entry is at
	// index PltReserved.
	//
	// x86-64 reserves three: _DYNAMIC, the link_map the loader fills in, and
	// the resolver address it also fills in. AArch64 and RISC-V reserve two.
	// Writing a PLT's slot at index 0 overwrites _DYNAMIC and the program
	// fails before main.
	PltReserved int

	// TlsGdEntries is how many consecutive slots a general-dynamic reference
	// occupies: two on every current architecture, holding the module id and
	// the offset within it.
	TlsGdEntries int
}

// GotPltHeaderSize is the byte length of the reserved prefix of .got.plt.
func (g GotShape) GotPltHeaderSize() uint64 {
	return uint64(g.PltReserved) * g.EntrySize
}

// PltShape describes the procedure linkage table's geometry.
//
// Three sizes rather than one, because the formats in use differ structurally
// and not just in length. A lazy-binding format opens with a header (PLT0) that
// calls the resolver and is a different size from the entries following it. An
// Intel CET format splits each entry in two: a stub in .plt that keeps the lazy
// path, and an indirect jump in .plt.sec that call sites actually target. An
// ifunc entry lives in .iplt and is resolved eagerly through IRELATIVE.
type PltShape struct {
	// HeaderSize is PLT0's length, or zero when the format has no header
	// because it does not support lazy binding.
	HeaderSize uint64

	// EntrySize is one ordinary entry's length.
	EntrySize uint64

	// SecEntrySize is one .plt.sec entry's length, or zero when the format
	// has no second table. When it is non-zero, a call site's target is the
	// .plt.sec entry, not the .plt one.
	SecEntrySize uint64

	// IPltEntrySize is one .iplt entry's length. Usually equal to
	// EntrySize; zero means the backend has no ifunc support.
	IPltEntrySize uint64

	// Align is the alignment every PLT section requires.
	Align uint64

	// Lazy reports whether entries may be resolved on first call. When
	// false, every entry's slot is bound eagerly and DT_BIND_NOW is implied.
	Lazy bool
}

// PltSize returns the byte length of a .plt holding n entries.
func (p PltShape) PltSize(n int) uint64 {
	if n == 0 {
		return 0
	}
	return p.HeaderSize + uint64(n)*p.EntrySize
}

// SecPltSize returns the byte length of a .plt.sec holding n entries, or zero
// when the format has no second table.
func (p PltShape) SecPltSize(n int) uint64 {
	if p.SecEntrySize == 0 || n == 0 {
		return 0
	}
	return uint64(n) * p.SecEntrySize
}

// IPltSize returns the byte length of an .iplt holding n entries.
func (p PltShape) IPltSize(n int) uint64 {
	if p.IPltEntrySize == 0 || n == 0 {
		return 0
	}
	return uint64(n) * p.IPltEntrySize
}

// EntryOffset returns the offset of entry i within .plt, header included.
func (p PltShape) EntryOffset(i int) uint64 {
	return p.HeaderSize + uint64(i)*p.EntrySize
}

// CallTarget reports which table a call site should branch to: .plt.sec when
// the format has one, .plt otherwise. Getting this backwards produces a binary
// that runs correctly with lazy binding and crashes under BIND_NOW, which is a
// miserable thing to debug.
func (p PltShape) CallTarget() PltTable {
	if p.SecEntrySize != 0 {
		return PltSec
	}
	return PltMain
}

// PltTable names one of the procedure linkage sections.
type PltTable uint8

const (
	PltMain PltTable = iota
	PltSec
	PltI
)

func (t PltTable) String() string {
	switch t {
	case PltSec:
		return ".plt.sec"
	case PltI:
		return ".iplt"
	}
	return ".plt"
}

// ThunkShape describes range extension trampolines.
type ThunkShape struct {
	// Size is one thunk's length in bytes.
	Size uint64

	// Align is the alignment thunks require.
	Align uint64

	// Scratch names the register a thunk may clobber, for diagnostics. Both
	// the ARM and RISC-V ABIs designate one for exactly this use.
	Scratch string
}