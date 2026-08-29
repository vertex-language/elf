package elf

import "strconv"

// RelocI386 is a relocation type for ArchI386.
//
// The numbers are the Intel386 psABI supplement's own. Unlike every other
// architecture this module targets, i386 uses REL exclusively: an addend is
// never explicit in the relocation entry, only implicit in the section
// contents at the relocation's offset — and recovering it is simpler here
// than on ARM or RISC-V, since an i386 instruction's displacement or
// immediate is always a plain byte-aligned field, never bits scattered
// through an opcode.
type RelocI386 uint32

const (
	R_386_NONE RelocI386 = 0

	// Absolute data and PC-relative data, at every width the encoding
	// supports — i386 code addresses data with 8-, 16-, and 32-bit
	// displacements depending on the addressing mode chosen, unlike the
	// 64-bit architectures this module targets, which only ever need the
	// last of those in practice.
	R_386_32   RelocI386 = 1
	R_386_PC32 RelocI386 = 2
	R_386_16   RelocI386 = 20
	R_386_PC16 RelocI386 = 21
	R_386_8    RelocI386 = 22
	R_386_PC8  RelocI386 = 23

	// The GOT pair: an offset into the table, and the table's own
	// PC-relative address. GOT32X is the relaxable form current binutils and
	// LLVM emit by default in place of plain GOT32, the same role
	// R_X86_64_GOTPCRELX plays for the 64-bit psABI; this backend treats it
	// identically to GOT32; no relaxation is implemented for it.
	R_386_GOT32  RelocI386 = 3
	R_386_GOT32X RelocI386 = 43

	// PLT32 marks a 32-bit PC-relative branch that may need a procedure
	// linkage entry, the same role R_X86_64_PLT32 plays on the 64-bit psABI.
	R_386_PLT32 RelocI386 = 4

	// GOTOFF and GOTPC: a symbol's address relative to the GOT base, and the
	// GOT base's own address relative to the place — how PIC i386 code reads
	// its own data without a GOT slot, once %ebx already holds the table's
	// address.
	R_386_GOTOFF RelocI386 = 9
	R_386_GOTPC  RelocI386 = 10

	R_386_SIZE32 RelocI386 = 38

	// TLS. The classic forms (14-19) predate the 32-bit-immediate forms
	// (32-34) the modern GD/LDM/LE sequences below reuse for their
	// instruction-encoded offsets; a real toolchain may emit either
	// depending on age. Both sets are classified; this backend applies
	// neither GD nor LDM, and the local-exec pair's own sign convention is
	// not implemented — see the riscv64-style caveat in package i386.
	R_386_TLS_TPOFF  RelocI386 = 14
	R_386_TLS_IE     RelocI386 = 15
	R_386_TLS_GOTIE  RelocI386 = 16
	R_386_TLS_LE     RelocI386 = 17
	R_386_TLS_GD     RelocI386 = 18
	R_386_TLS_LDM    RelocI386 = 19
	R_386_TLS_LDO_32 RelocI386 = 32
	R_386_TLS_IE_32  RelocI386 = 33
	R_386_TLS_LE_32  RelocI386 = 34

	// The dynamic relocations: written by the linker for the dynamic loader
	// to apply at load time, and never present in an input object.
	R_386_COPY         RelocI386 = 5
	R_386_GLOB_DAT     RelocI386 = 6
	R_386_JMP_SLOT     RelocI386 = 7
	R_386_RELATIVE     RelocI386 = 8
	R_386_TLS_DTPMOD32 RelocI386 = 35
	R_386_TLS_DTPOFF32 RelocI386 = 36
	R_386_TLS_TPOFF32  RelocI386 = 37
	R_386_IRELATIVE    RelocI386 = 42
)

func (r RelocI386) String() string {
	if n, ok := relocI386Names[r]; ok {
		return n
	}
	return "R_386(" + strconv.FormatUint(uint64(r), 10) + ")"
}

var relocI386Names = map[RelocI386]string{
	R_386_NONE: "R_386_NONE",

	R_386_32:   "R_386_32",
	R_386_PC32: "R_386_PC32",
	R_386_16:   "R_386_16",
	R_386_PC16: "R_386_PC16",
	R_386_8:    "R_386_8",
	R_386_PC8:  "R_386_PC8",

	R_386_GOT32:  "R_386_GOT32",
	R_386_GOT32X: "R_386_GOT32X",
	R_386_PLT32:  "R_386_PLT32",

	R_386_GOTOFF: "R_386_GOTOFF",
	R_386_GOTPC:  "R_386_GOTPC",

	R_386_SIZE32: "R_386_SIZE32",

	R_386_TLS_TPOFF:  "R_386_TLS_TPOFF",
	R_386_TLS_IE:     "R_386_TLS_IE",
	R_386_TLS_GOTIE:  "R_386_TLS_GOTIE",
	R_386_TLS_LE:     "R_386_TLS_LE",
	R_386_TLS_GD:     "R_386_TLS_GD",
	R_386_TLS_LDM:    "R_386_TLS_LDM",
	R_386_TLS_LDO_32: "R_386_TLS_LDO_32",
	R_386_TLS_IE_32:  "R_386_TLS_IE_32",
	R_386_TLS_LE_32:  "R_386_TLS_LE_32",

	R_386_COPY:         "R_386_COPY",
	R_386_GLOB_DAT:     "R_386_GLOB_DAT",
	R_386_JMP_SLOT:     "R_386_JMP_SLOT",
	R_386_RELATIVE:     "R_386_RELATIVE",
	R_386_TLS_DTPMOD32: "R_386_TLS_DTPMOD32",
	R_386_TLS_DTPOFF32: "R_386_TLS_DTPOFF32",
	R_386_TLS_TPOFF32:  "R_386_TLS_TPOFF32",
	R_386_IRELATIVE:    "R_386_IRELATIVE",
}
