package elf

import "strconv"

// RelocRISCV is a relocation type for ArchRISCV32 and ArchRISCV64.
//
// The numbers are the RISC-V psABI's own ("ELF Specification for RISC-V",
// riscv-non-isa/riscv-elf-psabi-doc). RISC-V is RELA throughout, like every
// other 64-bit architecture this module targets.
type RelocRISCV uint32

const (
	R_RISCV_NONE RelocRISCV = 0

	// Absolute data, at both widths this module's two RISC-V architectures
	// use, and split into a 20-bit high part and a 12-bit low part the way
	// LUI/AUIPC and their following instruction always split an immediate.
	R_RISCV_32     RelocRISCV = 1
	R_RISCV_64     RelocRISCV = 2
	R_RISCV_HI20   RelocRISCV = 26
	R_RISCV_LO12_I RelocRISCV = 27
	R_RISCV_LO12_S RelocRISCV = 28

	// The ordinary control-flow fields: a branch's field, and JAL's — both
	// always local, since neither ever needs a PLT entry.
	R_RISCV_BRANCH RelocRISCV = 16
	R_RISCV_JAL    RelocRISCV = 17

	// CALL and CALL_PLT are a matched pair of instructions — an AUIPC
	// immediately followed by a JALR — described by one relocation entry at
	// the AUIPC's offset. CALL_PLT additionally names a symbol that may need
	// a PLT entry; CALL never does, and current toolchains no longer emit it,
	// but a linker still has to accept it.
	R_RISCV_CALL     RelocRISCV = 18
	R_RISCV_CALL_PLT RelocRISCV = 19

	// PCREL_HI20 is the AUIPC half of a PC-relative access — to a symbol's
	// own address, its GOT entry, or its initial-exec or general-dynamic TLS
	// slot, depending on which of these four types was used. PCREL_LO12_I
	// and PCREL_LO12_S are the instruction that completes it, an I-type or
	// S-type twelve bits later — but they name a LOCAL LABEL AT THE AUIPC'S
	// OWN ADDRESS, not the real target. Recovering the real target means
	// finding the HI20 relocation at that address and reading its symbol and
	// addend instead: RISC-V is the one psABI among this module's
	// architectures where a LO12 relocation's own Sym is not the value it
	// contributes to.
	R_RISCV_GOT_HI20     RelocRISCV = 20
	R_RISCV_TLS_GOT_HI20 RelocRISCV = 21
	R_RISCV_TLS_GD_HI20  RelocRISCV = 22
	R_RISCV_PCREL_HI20   RelocRISCV = 23
	R_RISCV_PCREL_LO12_I RelocRISCV = 24
	R_RISCV_PCREL_LO12_S RelocRISCV = 25

	// Local-exec TLS: the offset from the thread pointer, high and low
	// twelve bits, plus a marker on the instruction that adds the thread
	// pointer in — TPREL_ADD rewrites no bits of its own and exists only so
	// relaxation can find that instruction.
	R_RISCV_TPREL_HI20   RelocRISCV = 29
	R_RISCV_TPREL_LO12_I RelocRISCV = 30
	R_RISCV_TPREL_LO12_S RelocRISCV = 31
	R_RISCV_TPREL_ADD    RelocRISCV = 32

	// RELAX marks that the instruction(s) at this offset are candidates for
	// linker relaxation — shrinking a CALL_PLT to a single JAL once the
	// target turns out to be near, for instance. It carries no field of its
	// own and is never applied.
	R_RISCV_RELAX RelocRISCV = 51

	// The dynamic relocations: written by the linker for the dynamic loader
	// to apply at load time, and never present in an input object.
	R_RISCV_RELATIVE     RelocRISCV = 3
	R_RISCV_COPY         RelocRISCV = 4
	R_RISCV_JUMP_SLOT    RelocRISCV = 5
	R_RISCV_TLS_DTPMOD32 RelocRISCV = 6
	R_RISCV_TLS_DTPMOD64 RelocRISCV = 7
	R_RISCV_TLS_DTPREL32 RelocRISCV = 8
	R_RISCV_TLS_DTPREL64 RelocRISCV = 9
	R_RISCV_TLS_TPREL32  RelocRISCV = 10
	R_RISCV_TLS_TPREL64  RelocRISCV = 11
)

func (r RelocRISCV) String() string {
	if n, ok := relocRISCVNames[r]; ok {
		return n
	}
	return "R_RISCV(" + strconv.FormatUint(uint64(r), 10) + ")"
}

var relocRISCVNames = map[RelocRISCV]string{
	R_RISCV_NONE: "R_RISCV_NONE",

	R_RISCV_32:     "R_RISCV_32",
	R_RISCV_64:     "R_RISCV_64",
	R_RISCV_HI20:   "R_RISCV_HI20",
	R_RISCV_LO12_I: "R_RISCV_LO12_I",
	R_RISCV_LO12_S: "R_RISCV_LO12_S",

	R_RISCV_BRANCH: "R_RISCV_BRANCH",
	R_RISCV_JAL:    "R_RISCV_JAL",

	R_RISCV_CALL:     "R_RISCV_CALL",
	R_RISCV_CALL_PLT: "R_RISCV_CALL_PLT",

	R_RISCV_GOT_HI20:     "R_RISCV_GOT_HI20",
	R_RISCV_TLS_GOT_HI20: "R_RISCV_TLS_GOT_HI20",
	R_RISCV_TLS_GD_HI20:  "R_RISCV_TLS_GD_HI20",
	R_RISCV_PCREL_HI20:   "R_RISCV_PCREL_HI20",
	R_RISCV_PCREL_LO12_I: "R_RISCV_PCREL_LO12_I",
	R_RISCV_PCREL_LO12_S: "R_RISCV_PCREL_LO12_S",

	R_RISCV_TPREL_HI20:   "R_RISCV_TPREL_HI20",
	R_RISCV_TPREL_LO12_I: "R_RISCV_TPREL_LO12_I",
	R_RISCV_TPREL_LO12_S: "R_RISCV_TPREL_LO12_S",
	R_RISCV_TPREL_ADD:    "R_RISCV_TPREL_ADD",

	R_RISCV_RELAX: "R_RISCV_RELAX",

	R_RISCV_RELATIVE:     "R_RISCV_RELATIVE",
	R_RISCV_COPY:         "R_RISCV_COPY",
	R_RISCV_JUMP_SLOT:    "R_RISCV_JUMP_SLOT",
	R_RISCV_TLS_DTPMOD32: "R_RISCV_TLS_DTPMOD32",
	R_RISCV_TLS_DTPMOD64: "R_RISCV_TLS_DTPMOD64",
	R_RISCV_TLS_DTPREL32: "R_RISCV_TLS_DTPREL32",
	R_RISCV_TLS_DTPREL64: "R_RISCV_TLS_DTPREL64",
	R_RISCV_TLS_TPREL32:  "R_RISCV_TLS_TPREL32",
	R_RISCV_TLS_TPREL64:  "R_RISCV_TLS_TPREL64",
}
