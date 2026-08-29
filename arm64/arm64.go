// Package arm64 is the linker backend for the AArch64 architecture.
//
// Blank-import it to make AArch64 links possible:
//
//	import _ "github.com/vertex-language/elf/arm64"
//
// The backend implements backend.Backend, backend.Dynamic, backend.Thunker,
// and backend.TlsOffsetter. It deliberately implements no backend.Relaxer:
//
//   - Thunker covers only CALL26 and JUMP26, the two branch forms that go
//     through a PLT and so are the ones link's own thunk insertion ever asks
//     about (see Classify and InRange). TSTBR14, CONDBR19, and every
//     PC-relative data form still fail loudly with a RangeError if a real
//     program manages to place them more than their own field allows from
//     their target — extending those needs relaxing them into a different
//     instruction sequence, not redirecting them to a trampoline, and that
//     is what the missing Relaxer below would do.
//
//   - No Relaxer. AArch64 relaxation narrows TLS access models (general- or
//     local-dynamic down to initial-exec or local-exec) and can rewrite an
//     ADRP/LDR GOT pair into ADRP/ADD once a symbol turns out to be local.
//     Neither is implemented: TLSDESC and TLSLD are classified but not
//     applied (see Classify and Apply), and every GOT load goes through the
//     table even when the target is known at link time.
//
// Scope. This backend implements the relocations a normal small/PIC-model
// AArch64 compilation unit emits: absolute and PC-relative data, the
// ADRP/ADD/LDR page pairs (including their GOT and initial-exec-TLS forms),
// the branch and test-branch fields, and local-exec TLS. It classifies but
// does not apply the general-dynamic and local-dynamic TLS relocations, and
// the TLSDESC family: reaching one of those in Apply fails with
// ErrUnsupportedReloc rather than silently emitting wrong code, which is the
// same posture x86_64 takes toward its own TLSDESC forms. The large code
// model's MOVW/MOVK absolute sequences and the ILP32 (P32) relocation space
// are not implemented at all, since no toolchain in ordinary use emits them.
package arm64

import (
	"github.com/vertex-language/elf"
	"github.com/vertex-language/elf/backend"
	"github.com/vertex-language/elf/image"
)

func init() { backend.Register(Backend{}) }

// Backend implements the linker's per-architecture interface for AArch64. It
// holds no state: everything a link needs lives in *image.Image and *Reqs.
type Backend struct{}

// Arch identifies this backend.
func (Backend) Arch() elf.Arch { return elf.ArchARM64 }

// Classify maps a relocation type to its architecture-independent meaning.
func (Backend) Classify(typ uint32) backend.Kind {
	switch elf.RelocAArch64(typ) {
	case elf.R_AARCH64_NONE:
		return backend.KindNone

	// Absolute data, and the LO12 family completing an ADRP: each names an
	// absolute address, just twelve bits of it at a time.
	case elf.R_AARCH64_ABS64, elf.R_AARCH64_ABS32, elf.R_AARCH64_ABS16,
		elf.R_AARCH64_ADD_ABS_LO12_NC,
		elf.R_AARCH64_LDST8_ABS_LO12_NC, elf.R_AARCH64_LDST16_ABS_LO12_NC,
		elf.R_AARCH64_LDST32_ABS_LO12_NC, elf.R_AARCH64_LDST64_ABS_LO12_NC,
		elf.R_AARCH64_LDST128_ABS_LO12_NC:
		return backend.KindAbs

	case elf.R_AARCH64_PREL64, elf.R_AARCH64_PREL32, elf.R_AARCH64_PREL16,
		elf.R_AARCH64_ADR_PREL_LO21, elf.R_AARCH64_LD_PREL_LO19,
		elf.R_AARCH64_ADR_PREL_PG_HI21, elf.R_AARCH64_ADR_PREL_PG_HI21_NC,
		elf.R_AARCH64_TSTBR14, elf.R_AARCH64_CONDBR19:
		return backend.KindPC

	// CALL26 and JUMP26 are BL and B: the only branches wide enough to reach
	// an external symbol, and so the only ones a PLT entry can be inserted
	// for. TSTBR14 and CONDBR19 above never target anything but a local
	// label — no compiler emits them against a symbol that could need a PLT
	// stub — so they stay ordinary PC-relative fields.
	case elf.R_AARCH64_CALL26, elf.R_AARCH64_JUMP26:
		return backend.KindPltPC

	case elf.R_AARCH64_ADR_GOT_PAGE, elf.R_AARCH64_LD64_GOT_LO12_NC,
		elf.R_AARCH64_GOT_LD_PREL19:
		return backend.KindGotPC

	case elf.R_AARCH64_TLSGD_ADR_PAGE21, elf.R_AARCH64_TLSGD_ADD_LO12_NC,
		elf.R_AARCH64_TLSGD_ADR_PREL21:
		return backend.KindTlsGd

	case elf.R_AARCH64_TLSLD_ADR_PAGE21, elf.R_AARCH64_TLSLD_ADR_PREL21:
		return backend.KindTlsLd

	case elf.R_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21,
		elf.R_AARCH64_TLSIE_LD64_GOTTPREL_LO12_NC,
		elf.R_AARCH64_TLSIE_LD_GOTTPREL_PREL19:
		return backend.KindTlsIe

	case elf.R_AARCH64_TLSLE_ADD_TPREL_HI12,
		elf.R_AARCH64_TLSLE_ADD_TPREL_LO12,
		elf.R_AARCH64_TLSLE_ADD_TPREL_LO12_NC:
		return backend.KindTlsLe

	case elf.R_AARCH64_TLSDESC_ADR_PAGE21, elf.R_AARCH64_TLSDESC_LD64_LO12_NC,
		elf.R_AARCH64_TLSDESC_ADD_LO12_NC, elf.R_AARCH64_TLSDESC_CALL:
		return backend.KindTlsDesc

		// The remaining types — COPY, GLOB_DAT, JUMP_SLOT, RELATIVE, IRELATIVE,
		// the TLS_DTPMOD64/DTPREL64/TPREL64 trio, TLSDESC — are written by the
		// linker for the dynamic loader and never appear in an input object.
		// Reaching one here means the input is malformed, so it is left unknown
		// rather than given a meaning.
	}
	return backend.KindUnknown
}

// RelAddend always reports failure, because there is nothing to recover.
//
// AArch64 uses RELA exclusively: every addend is explicit in the relocation
// entry. This exists to satisfy the interface, and returning false is the
// honest answer rather than reading bytes that mean something else.
func (Backend) RelAddend(content []byte, off uint64, typ uint32) (int64, bool) {
	return 0, false
}

// DynType maps a dynamic relocation's meaning to this psABI's number.
func (Backend) DynType(k backend.DynKind) (uint32, bool) {
	switch k {
	case backend.DynNone:
		return uint32(elf.R_AARCH64_NONE), true
	case backend.DynAbsolute:
		return uint32(elf.R_AARCH64_ABS64), true
	case backend.DynRelative:
		return uint32(elf.R_AARCH64_RELATIVE), true
	case backend.DynGlobDat:
		return uint32(elf.R_AARCH64_GLOB_DAT), true
	case backend.DynJumpSlot:
		return uint32(elf.R_AARCH64_JUMP_SLOT), true
	case backend.DynCopy:
		return uint32(elf.R_AARCH64_COPY), true
	case backend.DynIRelative:
		return uint32(elf.R_AARCH64_IRELATIVE), true
	case backend.DynDtpMod:
		return uint32(elf.R_AARCH64_TLS_DTPMOD64), true
	case backend.DynDtpOff:
		return uint32(elf.R_AARCH64_TLS_DTPREL64), true
	case backend.DynTpOff:
		return uint32(elf.R_AARCH64_TLS_TPREL64), true
	}
	return 0, false
}

// ifunc reports whether a symbol is a GNU indirect function, which always
// goes through a PLT entry even when it is local, because the address a
// reference wants is what the resolver returns rather than the resolver
// itself.
func ifunc(s *image.Sym) bool { return s != nil && s.Type == elf.STT_GNU_IFUNC }

// TpOff implements backend.TlsOffsetter.
//
// AArch64 uses TLS variant I: the thread pointer names the start of a thread
// control block whose size is max(16, the TLS segment's own alignment) — not
// a flat 16 bytes, since a block that itself needs coarser alignment than 16
// pushes the header out to match, per the AAELF64 TLS chapter — and the
// executable's static TLS block is placed immediately after it, so the
// offset is positive: the opposite sign from x86-64's variant II.
func (Backend) TpOff(tlsAddr, tlsSize, tlsAlign, symAddr uint64) int64 {
	tcbSize := tlsAlign
	if tcbSize < 16 {
		tcbSize = 16
	}
	return int64(symAddr) - int64(tlsAddr) + int64(tcbSize)
}
