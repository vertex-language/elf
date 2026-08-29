// Package riscv64 is the linker backend for the RISC-V RV64 architecture.
//
// Blank-import it to make RISC-V64 links possible:
//
//	import _ "github.com/vertex-language/elf/riscv64"
//
// The backend implements backend.Backend, backend.Dynamic, backend.Thunker,
// and backend.TlsOffsetter. It deliberately implements no backend.Relaxer:
//
//   - Thunker covers JAL, whose ±1MiB field a large enough function body can
//     outgrow, by redirecting it to a trampoline built the same way this
//     package's own PLT entries are — an AUIPC/JALR pair, reaching anywhere
//     in the ±2GiB CALL_PLT itself already spans. BRANCH is deliberately left
//     alone: extending a ±4KiB conditional test needs inverting it around an
//     unconditional jump, not a redirect, so it reports in range
//     unconditionally and an actual overflow fails loudly in Apply instead.
//
//   - No Relaxer. The RISC-V psABI's central relaxation — shrinking a
//     CALL_PLT's AUIPC/JALR pair to a single JAL once the target turns out to
//     be near, or an AUIPC/ADDI PC-relative pair to nothing once a symbol
//     turns out to sit at a known offset from x0 — is exactly what every
//     R_RISCV_RELAX hint in an input object is asking for, and none of it is
//     implemented: every RELAX hint is classified and then ignored (see
//     Classify), and every CALL_PLT stays the full two-instruction sequence
//     however close its target lands.
//
// Scope. Absolute data, AUIPC-based PC-relative addressing (including its GOT
// form) and the HI20/LO12 pairing that recovers a LO12 relocation's true
// target, PC-relative calls with PLT support, branches, JAL, and local-exec
// TLS are implemented. Initial-exec and general-dynamic TLS are classified
// but not applied to a call site — the LO12 pairing logic recognises a
// TLS-flavored HI20 and reports ErrUnsupportedReloc rather than guessing at a
// value — though initial-exec's GOT slot content is generated correctly by
// link/dynamic.go via TpOff below when the reference resolves locally; only
// the case an external module owns the TLS block falls back to a dynamic
// TPREL relocation, same as x86_64 and arm64.
//
// The PLT this backend emits has no lazy-binding header: every entry loads
// its own .got.plt slot and jumps through it unconditionally, on the
// assumption the slot is already resolved. A link that uses this backend's
// PLT support must force eager binding (Options.BindNow); calling one before
// the loader has processed its JUMP_SLOT relocation reads a null pointer. A
// correct lazy PLT0 needs several more instructions computing a PLT index
// from a return-address delta, described in the psABI's dynamic linking
// chapter, and getting one of those constants wrong produces a resolver that
// crashes on the first call a real lazy-binding test would have to exercise
// — which nothing in this repository can do, so it is not attempted.
package riscv64

import (
	"github.com/vertex-language/elf"
	"github.com/vertex-language/elf/backend"
)

func init() { backend.Register(Backend{}) }

// Backend implements the linker's per-architecture interface for RISC-V64. It
// holds no state: everything a link needs lives in *image.Image and *Reqs.
type Backend struct{}

// Arch identifies this backend.
func (Backend) Arch() elf.Arch { return elf.ArchRISCV64 }

// Classify maps a relocation type to its architecture-independent meaning.
func (Backend) Classify(typ uint32) backend.Kind {
	switch elf.RelocRISCV(typ) {
	case elf.R_RISCV_NONE:
		return backend.KindNone

	case elf.R_RISCV_32, elf.R_RISCV_64,
		elf.R_RISCV_HI20, elf.R_RISCV_LO12_I, elf.R_RISCV_LO12_S:
		return backend.KindAbs

	case elf.R_RISCV_BRANCH, elf.R_RISCV_JAL, elf.R_RISCV_CALL,
		elf.R_RISCV_PCREL_HI20, elf.R_RISCV_PCREL_LO12_I, elf.R_RISCV_PCREL_LO12_S:
		return backend.KindPC

	// CALL_PLT is the only branch form that can name an external symbol; a
	// plain CALL, BRANCH, or JAL never does. PCREL_HI20 stays KindPC even
	// though it can point at a GOT-eligible symbol's own address (rather than
	// its GOT slot) — GOT_HI20 is the type that means "through the GOT", not
	// this one.
	case elf.R_RISCV_CALL_PLT:
		return backend.KindPltPC

	case elf.R_RISCV_GOT_HI20:
		return backend.KindGotPC

	case elf.R_RISCV_TLS_GOT_HI20:
		return backend.KindTlsIe
	case elf.R_RISCV_TLS_GD_HI20:
		return backend.KindTlsGd

	case elf.R_RISCV_TPREL_HI20, elf.R_RISCV_TPREL_LO12_I, elf.R_RISCV_TPREL_LO12_S,
		elf.R_RISCV_TPREL_ADD:
		return backend.KindTlsLe

	case elf.R_RISCV_RELAX:
		return backend.KindRelax

		// The remaining types — RELATIVE, COPY, JUMP_SLOT, the TLS_DTPMOD32/64,
		// TLS_DTPREL32/64, and TLS_TPREL32/64 sextet — are written by the linker
		// for the dynamic loader and never appear in an input object.
	}
	return backend.KindUnknown
}

// RelAddend always reports failure, because there is nothing to recover.
//
// RISC-V uses RELA exclusively: every addend is explicit in the relocation
// entry.
func (Backend) RelAddend(content []byte, off uint64, typ uint32) (int64, bool) {
	return 0, false
}

// DynType maps a dynamic relocation's meaning to this psABI's number.
func (Backend) DynType(k backend.DynKind) (uint32, bool) {
	switch k {
	case backend.DynNone:
		return uint32(elf.R_RISCV_NONE), true
	case backend.DynRelative:
		return uint32(elf.R_RISCV_RELATIVE), true
	case backend.DynAbsolute, backend.DynGlobDat:
		// The psABI defines no separate GLOB_DAT: a preemptible symbol's GOT
		// slot gets the same "add the 64-bit symbol value" relocation an
		// input object would use for an ordinary absolute reference.
		return uint32(elf.R_RISCV_64), true
	case backend.DynJumpSlot:
		return uint32(elf.R_RISCV_JUMP_SLOT), true
	case backend.DynCopy:
		return uint32(elf.R_RISCV_COPY), true
	case backend.DynDtpMod:
		return uint32(elf.R_RISCV_TLS_DTPMOD64), true
	case backend.DynDtpOff:
		return uint32(elf.R_RISCV_TLS_DTPREL64), true
	case backend.DynTpOff:
		return uint32(elf.R_RISCV_TLS_TPREL64), true
	}
	// DynIRelative has no reserved number in the psABI; ifuncs are not
	// supported by this backend.
	return 0, false
}

// TpOff implements backend.TlsOffsetter.
//
// RISC-V uses TLS variant I like AArch64, but with TLS_TP_OFFSET defined as
// zero in the psABI: the thread pointer names the start of the static TLS
// block directly, with no reserved header ahead of it.
func (Backend) TpOff(tlsAddr, tlsSize, tlsAlign, symAddr uint64) int64 {
	return int64(symAddr) - int64(tlsAddr)
}
