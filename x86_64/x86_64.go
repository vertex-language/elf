// Package x86_64 is the linker backend for the AMD64 architecture.
//
// Blank-import it to make x86-64 links possible:
//
//	import _ "github.com/vertex-language/elf/x86_64"
//
// The backend implements backend.Backend and backend.Dynamic. It deliberately
// implements neither backend.Relaxer nor backend.Thunker:
//
//   - No thunks. A call or jmp displacement spans ±2 GiB, and the compiler has
//     already relaxed anything shorter within a function. lld and the GNU
//     linkers do not implement range extension thunks for x86-64 either.
//
//   - No Relaxer. The one relaxation this psABI defines — a GOT load becoming
//     a direct lea — rewrites an instruction, and instructions do not exist
//     until the output buffer does. The decision is made during Scan, where it
//     determines whether a GOT slot is allocated, and carried out during
//     Apply, where the bytes are writable. Both call the same predicate, so
//     they cannot disagree.
package x86_64

import (
	"github.com/vertex-language/elf"
	"github.com/vertex-language/elf/backend"
	"github.com/vertex-language/elf/image"
)

func init() { backend.Register(Backend{}) }

// Backend implements the linker's per-architecture interface for AMD64. It
// holds no state: everything a link needs lives in *image.Image and *Reqs.
type Backend struct{}

// Arch identifies this backend. Arch rather than Machine, so that nothing has
// to re-derive a width from e_machine.
func (Backend) Arch() elf.Arch { return elf.ArchAMD64 }

// Classify maps a relocation type to its architecture-independent meaning.
func (Backend) Classify(typ uint32) backend.Kind {
	switch elf.RelocX86_64(typ) {
	case elf.R_X86_64_NONE:
		return backend.KindNone

	// Absolute. In a position-independent output these are the ones that
	// need a dynamic relocation, which is the reason the distinction from
	// the PC-relative group below matters.
	case elf.R_X86_64_64, elf.R_X86_64_32, elf.R_X86_64_32S,
		elf.R_X86_64_16, elf.R_X86_64_8:
		return backend.KindAbs

	case elf.R_X86_64_PC64, elf.R_X86_64_PC32,
		elf.R_X86_64_PC16, elf.R_X86_64_PC8:
		return backend.KindPC

	case elf.R_X86_64_GOT32, elf.R_X86_64_GOT64:
		return backend.KindGot

	case elf.R_X86_64_GOTPCREL, elf.R_X86_64_GOTPCREL64,
		elf.R_X86_64_GOTPCRELX, elf.R_X86_64_REX_GOTPCRELX,
		elf.R_X86_64_CODE_4_GOTPCRELX, elf.R_X86_64_CODE_5_GOTPCRELX,
		elf.R_X86_64_CODE_6_GOTPCRELX:
		return backend.KindGotPC

	case elf.R_X86_64_GOTOFF64:
		return backend.KindGotOff

	case elf.R_X86_64_GOTPC32, elf.R_X86_64_GOTPC64:
		return backend.KindGotBase

	// PLT32 is the marker for a 32-bit PC-relative branch, not a demand for
	// a PLT entry. The linker reduces it to PC32 whenever the target turns
	// out to be local, which is what makes a static link need no PLT.
	case elf.R_X86_64_PLT32, elf.R_X86_64_PLT32_BND:
		return backend.KindPltPC

	case elf.R_X86_64_PLTOFF64:
		return backend.KindPlt

	case elf.R_X86_64_SIZE32, elf.R_X86_64_SIZE64:
		return backend.KindSize

	case elf.R_X86_64_TLSGD:
		return backend.KindTlsGd
	case elf.R_X86_64_TLSLD:
		return backend.KindTlsLd
	case elf.R_X86_64_DTPOFF32, elf.R_X86_64_DTPOFF64:
		return backend.KindTlsLdOff
	case elf.R_X86_64_GOTTPOFF, elf.R_X86_64_CODE_4_GOTTPOFF,
		elf.R_X86_64_CODE_5_GOTTPOFF, elf.R_X86_64_CODE_6_GOTTPOFF:
		return backend.KindTlsIe
	case elf.R_X86_64_TPOFF32, elf.R_X86_64_TPOFF64:
		return backend.KindTlsLe
	case elf.R_X86_64_GOTPC32_TLSDESC, elf.R_X86_64_TLSDESC_CALL,
		elf.R_X86_64_CODE_4_GOTPC32_TLSDESC,
		elf.R_X86_64_CODE_5_GOTPC32_TLSDESC,
		elf.R_X86_64_CODE_6_GOTPC32_TLSDESC:
		return backend.KindTlsDesc

	// The remaining types — COPY, GLOB_DAT, JUMP_SLOT, RELATIVE, IRELATIVE,
	// DTPMOD64 — are written by the linker for the dynamic loader and never
	// appear in an input object. Reaching one here means the input is
	// malformed, so it is left unknown rather than given a meaning.
	}
	return backend.KindUnknown
}

// RelAddend always reports failure, because there is nothing to recover.
//
// The AMD64 psABI uses RELA exclusively: every addend is explicit in the
// relocation entry. This exists to satisfy the interface, and returning false
// is the honest answer rather than reading four bytes that mean something else.
func (Backend) RelAddend(content []byte, off uint64, typ uint32) (int64, bool) {
	return 0, false
}

// DynType maps a dynamic relocation's meaning to this psABI's number.
func (Backend) DynType(k backend.DynKind) (uint32, bool) {
	switch k {
	case backend.DynNone:
		return uint32(elf.R_X86_64_NONE), true
	case backend.DynAbsolute:
		return uint32(elf.R_X86_64_64), true
	case backend.DynRelative:
		return uint32(elf.R_X86_64_RELATIVE), true
	case backend.DynGlobDat:
		return uint32(elf.R_X86_64_GLOB_DAT), true
	case backend.DynJumpSlot:
		return uint32(elf.R_X86_64_JUMP_SLOT), true
	case backend.DynCopy:
		return uint32(elf.R_X86_64_COPY), true
	case backend.DynIRelative:
		return uint32(elf.R_X86_64_IRELATIVE), true
	case backend.DynDtpMod:
		return uint32(elf.R_X86_64_DTPMOD64), true
	case backend.DynDtpOff:
		return uint32(elf.R_X86_64_DTPOFF64), true
	case backend.DynTpOff:
		return uint32(elf.R_X86_64_TPOFF64), true
	}
	return 0, false
}

// ifunc reports whether a symbol is a GNU indirect function, which always goes
// through a PLT entry even when it is local, because the address a reference
// wants is what the resolver returns rather than the resolver itself.
func ifunc(s *image.Sym) bool { return s != nil && s.Type == elf.STT_GNU_IFUNC }