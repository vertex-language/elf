// Package i386 is the linker backend for the Intel 386 architecture.
//
// Blank-import it to make i386 links possible:
//
//	import _ "github.com/vertex-language/elf/i386"
//
// The backend implements backend.Backend and backend.Dynamic, and — unlike
// the version of this file before link/dynamic.go learned to emit REL rather
// than RELA for an architecture that needs it — Dynamic works for real,
// with one deliberate exception: every PLT-filling method (WritePltHeader,
// WriteGotPlt, WritePlt, and the rest) still returns a clear error instead
// of bytes, so this backend supports dynamic linking wherever nothing needs
// a procedure linkage table.
//
// The reason is a genuine i386 wrinkle none of this module's other
// architectures share: PLT and ordinary GOT-relative code both address the
// table through one register, %ebx, loaded once by the caller's own
// prologue from a single _GLOBAL_OFFSET_TABLE_ symbol — meaning .got and
// .got.plt must resolve every displacement against the *same* base address
// for the two kinds of code to agree on where the table actually is. This
// module already keeps Got and GotPlt as independent synthetics with
// independent addresses, which every other backend's addressing modes
// (RIP-relative, ADRP-relative, AUIPC-relative) never needed to be reconciled
// with a shared base register in the first place, and unifying that base
// correctly — which one of the two conventionally hosts
// _GLOBAL_OFFSET_TABLE_, and whether GOTOFF must therefore measure from it
// rather than from Got() — is not something this file has verified against
// a real i386 dynamic linker. Getting it wrong produces PIC code that
// computes a plausible-looking but wrong %ebx-relative offset, which is
// worse than refusing outright.
//
// What works today: relocatable objects, static (non-PIE) executables, and
// dynamic output (a shared object or a PIE) as long as nothing in it needs a
// PLT entry — GOTOFF, GOTPC, and GOT32 access to preemptible data, GLOB_DAT
// and RELATIVE relocations included, all correctly REL-formatted.
//
// It implements neither backend.Relaxer nor backend.Thunker: PLT32's field
// spans the same full 32-bit displacement CALL26 on AArch64 does not, and no
// current toolchain relaxes an i386 call sequence the way it does for
// RISC-V.
//
// Local-exec and initial-exec TLS are implemented, but only the GNU model —
// R_386_TLS_LE, R_386_TLS_IE, R_386_TLS_GOTIE, and the GOT-slot R_386_TLS_TPOFF
// dynamic relocation — which is what every current assembler emits by
// default and uses the same negative, variant-II offset TpOff below and
// x86_64's own TpOff already compute. The older Sun/legacy model
// (R_386_TLS_LE_32, R_386_TLS_IE_32, R_386_TLS_TPOFF32) encodes the *positive*
// offset instead, subtracted rather than added by the instructions that
// consume it: verified against Ulrich Drepper's "ELF Handling For
// Thread-Local Storage" (the ABI's own reference document), not guessed at,
// but not implemented — no toolchain in ordinary use still emits it, and
// getting a sign flipped between two conventions this easy to confuse is a
// worse failure mode than simply not answering for it.
package i386

import (
	"encoding/binary"

	"github.com/vertex-language/elf"
	"github.com/vertex-language/elf/backend"
)

func init() { backend.Register(Backend{}) }

// Backend implements the linker's per-architecture interface for i386. It
// holds no state: everything a link needs lives in *image.Image and *Reqs.
type Backend struct{}

// Arch identifies this backend.
func (Backend) Arch() elf.Arch { return elf.ArchI386 }

// Classify maps a relocation type to its architecture-independent meaning.
func (Backend) Classify(typ uint32) backend.Kind {
	switch elf.RelocI386(typ) {
	case elf.R_386_NONE:
		return backend.KindNone

	case elf.R_386_32, elf.R_386_16, elf.R_386_8, elf.R_386_SIZE32:
		return backend.KindAbs

	case elf.R_386_PC32, elf.R_386_PC16, elf.R_386_PC8:
		return backend.KindPC

	case elf.R_386_GOT32, elf.R_386_GOT32X:
		return backend.KindGot

	case elf.R_386_PLT32:
		return backend.KindPltPC

	case elf.R_386_GOTOFF:
		return backend.KindGotOff

	case elf.R_386_GOTPC:
		return backend.KindGotBase

	case elf.R_386_TLS_GD:
		return backend.KindTlsGd
	case elf.R_386_TLS_LDM:
		return backend.KindTlsLd
	case elf.R_386_TLS_LDO_32:
		return backend.KindTlsLdOff
	case elf.R_386_TLS_IE, elf.R_386_TLS_GOTIE, elf.R_386_TLS_IE_32:
		return backend.KindTlsIe
	case elf.R_386_TLS_LE, elf.R_386_TLS_LE_32:
		return backend.KindTlsLe

		// The remaining types — COPY, GLOB_DAT, JMP_SLOT, RELATIVE, IRELATIVE,
		// TLS_DTPMOD32, TLS_DTPOFF32, TLS_TPOFF, TLS_TPOFF32 — are written by
		// the linker for the dynamic loader and never appear in an input
		// object.
	}
	return backend.KindUnknown
}

// RelAddend recovers a REL relocation's implicit addend.
//
// Unlike ARM or RISC-V, this is never an instruction-field decode: every
// i386 relocation names a plain, byte-aligned, little-endian field of the
// relocation's own width, because x86 displacements and immediates are
// encoded as literal bytes rather than packed into opcode bits. The value
// already sitting there is exactly the addend an assembler would have
// written into a RELA entry for the same reference — including, for a
// PC-relative type, whatever fixed adjustment (typically -4) accounts for
// the instruction's own length, since the assembler computes that the same
// way whichever format it is about to emit.
func (Backend) RelAddend(content []byte, off uint64, typ uint32) (int64, bool) {
	width := addendWidth(typ)
	if width == 0 {
		return 0, false
	}
	if off+uint64(width) > uint64(len(content)) {
		return 0, false
	}
	switch width {
	case 1:
		return int64(int8(content[off])), true
	case 2:
		return int64(int16(binary.LittleEndian.Uint16(content[off:]))), true
	case 4:
		return int64(int32(binary.LittleEndian.Uint32(content[off:]))), true
	}
	return 0, false
}

// addendWidth returns the byte width of the field a relocation type's
// implicit addend lives in, or zero for a type with none.
func addendWidth(typ uint32) int {
	switch elf.RelocI386(typ) {
	case elf.R_386_32, elf.R_386_PC32, elf.R_386_GOT32, elf.R_386_GOT32X,
		elf.R_386_PLT32, elf.R_386_GOTOFF, elf.R_386_GOTPC, elf.R_386_SIZE32,
		elf.R_386_TLS_LDO_32, elf.R_386_TLS_IE_32, elf.R_386_TLS_LE_32,
		elf.R_386_TLS_GD, elf.R_386_TLS_LDM:
		return 4
	case elf.R_386_16, elf.R_386_PC16:
		return 2
	case elf.R_386_8, elf.R_386_PC8:
		return 1
	}
	return 0
}

// DynType maps a dynamic relocation's meaning to this psABI's number.
//
// This is answered fully even though Backend does not implement
// backend.Dynamic: Reqs.AddDyn is reachable from the ordinary KindAbs-in-PIC
// and copy-relocation paths in Scan regardless, and a PIC i386 object with no
// PLT-needing call in it is exactly the case this backend does support.
func (Backend) DynType(k backend.DynKind) (uint32, bool) {
	switch k {
	case backend.DynNone:
		return uint32(elf.R_386_NONE), true
	case backend.DynAbsolute:
		// Reuses the ordinary static absolute type, the same way this
		// backend's RISC-V sibling reuses R_RISCV_64: the psABI's own
		// GLOB_DAT is specifically "GOT entry gets a data address," and a
		// non-GOT absolute slot needing runtime resolution is a distinct,
		// rarer case in PIC i386 code, which normally reaches a preemptible
		// symbol's data through GOTOFF instead.
		return uint32(elf.R_386_32), true
	case backend.DynGlobDat:
		return uint32(elf.R_386_GLOB_DAT), true
	case backend.DynRelative:
		return uint32(elf.R_386_RELATIVE), true
	case backend.DynJumpSlot:
		return uint32(elf.R_386_JMP_SLOT), true
	case backend.DynCopy:
		return uint32(elf.R_386_COPY), true
	case backend.DynIRelative:
		return uint32(elf.R_386_IRELATIVE), true
	case backend.DynDtpMod:
		return uint32(elf.R_386_TLS_DTPMOD32), true
	case backend.DynDtpOff:
		return uint32(elf.R_386_TLS_DTPOFF32), true
	case backend.DynTpOff:
		// The GNU model's number, not the Sun/legacy TPOFF32: the two carry
		// opposite-sign values, and TpOff below computes the GNU model's
		// negative one. See the package doc.
		return uint32(elf.R_386_TLS_TPOFF), true
	}
	return 0, false
}

// TpOff implements backend.TlsOffsetter.
//
// i386 uses TLS variant II, the same placement x86-64 uses and the same
// formula: the static block sits immediately below the thread pointer, so a
// symbol's offset is its position within the block minus the block's own
// aligned size, and is therefore negative. This is the GNU model's sign
// convention (R_386_TLS_LE, R_386_TLS_IE/GOTIE, R_386_TLS_TPOFF); the older
// Sun model's R_386_TLS_LE_32/IE_32/TPOFF32 want the same magnitude with the
// opposite sign, and are not implemented — see the package doc.
func (Backend) TpOff(tlsAddr, tlsSize, tlsAlign, symAddr uint64) int64 {
	if tlsAlign == 0 {
		tlsAlign = 1
	}
	size := (tlsSize + tlsAlign - 1) &^ (tlsAlign - 1)
	return int64(symAddr) - int64(tlsAddr) - int64(size)
}
