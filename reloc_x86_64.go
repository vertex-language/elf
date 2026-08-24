package elf

import "strconv"

// RelocX86_64 is a relocation type for ArchAMD64.
//
// Values 0 through 15, 24 through 26, and 32 through 33 are from the AMD64
// psABI relocation table. The TLS and relaxation-hint types above 33 come from
// later psABI revisions and from binutils.
type RelocX86_64 uint32

const (
	R_X86_64_NONE            RelocX86_64 = 0
	R_X86_64_64              RelocX86_64 = 1  // S + A, word64
	R_X86_64_PC32            RelocX86_64 = 2  // S + A - P, word32
	R_X86_64_GOT32           RelocX86_64 = 3  // G + A
	R_X86_64_PLT32           RelocX86_64 = 4  // L + A - P
	R_X86_64_COPY            RelocX86_64 = 5
	R_X86_64_GLOB_DAT        RelocX86_64 = 6  // S
	R_X86_64_JUMP_SLOT       RelocX86_64 = 7  // S
	R_X86_64_RELATIVE        RelocX86_64 = 8  // B + A
	R_X86_64_GOTPCREL        RelocX86_64 = 9  // G + GOT + A - P
	R_X86_64_32              RelocX86_64 = 10 // S + A, zero-extend check
	R_X86_64_32S             RelocX86_64 = 11 // S + A, sign-extend check
	R_X86_64_16              RelocX86_64 = 12
	R_X86_64_PC16            RelocX86_64 = 13
	R_X86_64_8               RelocX86_64 = 14
	R_X86_64_PC8             RelocX86_64 = 15
	R_X86_64_DTPMOD64        RelocX86_64 = 16
	R_X86_64_DTPOFF64        RelocX86_64 = 17
	R_X86_64_TPOFF64         RelocX86_64 = 18
	R_X86_64_TLSGD           RelocX86_64 = 19
	R_X86_64_TLSLD           RelocX86_64 = 20
	R_X86_64_DTPOFF32        RelocX86_64 = 21
	R_X86_64_GOTTPOFF        RelocX86_64 = 22
	R_X86_64_TPOFF32         RelocX86_64 = 23
	R_X86_64_PC64            RelocX86_64 = 24 // S + A - P, word64
	R_X86_64_GOTOFF64        RelocX86_64 = 25 // S + A - GOT
	R_X86_64_GOTPC32         RelocX86_64 = 26 // GOT + A - P
	R_X86_64_GOT64           RelocX86_64 = 27
	R_X86_64_GOTPCREL64      RelocX86_64 = 28
	R_X86_64_GOTPC64         RelocX86_64 = 29
	R_X86_64_GOTPLT64        RelocX86_64 = 30 // deprecated
	R_X86_64_PLTOFF64        RelocX86_64 = 31
	R_X86_64_SIZE32          RelocX86_64 = 32 // Z + A
	R_X86_64_SIZE64          RelocX86_64 = 33 // Z + A
	R_X86_64_GOTPC32_TLSDESC RelocX86_64 = 34
	R_X86_64_TLSDESC_CALL    RelocX86_64 = 35
	R_X86_64_TLSDESC         RelocX86_64 = 36
	R_X86_64_IRELATIVE       RelocX86_64 = 37
	R_X86_64_RELATIVE64      RelocX86_64 = 38
	R_X86_64_PC32_BND        RelocX86_64 = 39 // deprecated (MPX)
	R_X86_64_PLT32_BND       RelocX86_64 = 40 // deprecated (MPX)
	R_X86_64_GOTPCRELX       RelocX86_64 = 41
	R_X86_64_REX_GOTPCRELX   RelocX86_64 = 42

	// Recent additions for APX and the large code model. Verify against the
	// current psABI before the x86_64 backend relies on these numbers.
	R_X86_64_CODE_4_GOTPCRELX       RelocX86_64 = 43
	R_X86_64_CODE_4_GOTTPOFF        RelocX86_64 = 44
	R_X86_64_CODE_4_GOTPC32_TLSDESC RelocX86_64 = 45
	R_X86_64_CODE_5_GOTPCRELX       RelocX86_64 = 46
	R_X86_64_CODE_5_GOTTPOFF        RelocX86_64 = 47
	R_X86_64_CODE_5_GOTPC32_TLSDESC RelocX86_64 = 48
	R_X86_64_CODE_6_GOTPCRELX       RelocX86_64 = 49
	R_X86_64_CODE_6_GOTTPOFF        RelocX86_64 = 50
	R_X86_64_CODE_6_GOTPC32_TLSDESC RelocX86_64 = 51
)

func (r RelocX86_64) String() string {
	if s, ok := relocX86_64Names[r]; ok {
		return s
	}
	return "R_X86_64(" + strconv.FormatUint(uint64(r), 10) + ")"
}

var relocX86_64Names = map[RelocX86_64]string{
	R_X86_64_NONE: "R_X86_64_NONE", R_X86_64_64: "R_X86_64_64",
	R_X86_64_PC32: "R_X86_64_PC32", R_X86_64_GOT32: "R_X86_64_GOT32",
	R_X86_64_PLT32: "R_X86_64_PLT32", R_X86_64_COPY: "R_X86_64_COPY",
	R_X86_64_GLOB_DAT: "R_X86_64_GLOB_DAT", R_X86_64_JUMP_SLOT: "R_X86_64_JUMP_SLOT",
	R_X86_64_RELATIVE: "R_X86_64_RELATIVE", R_X86_64_GOTPCREL: "R_X86_64_GOTPCREL",
	R_X86_64_32: "R_X86_64_32", R_X86_64_32S: "R_X86_64_32S",
	R_X86_64_16: "R_X86_64_16", R_X86_64_PC16: "R_X86_64_PC16",
	R_X86_64_8: "R_X86_64_8", R_X86_64_PC8: "R_X86_64_PC8",
	R_X86_64_DTPMOD64: "R_X86_64_DTPMOD64", R_X86_64_DTPOFF64: "R_X86_64_DTPOFF64",
	R_X86_64_TPOFF64: "R_X86_64_TPOFF64", R_X86_64_TLSGD: "R_X86_64_TLSGD",
	R_X86_64_TLSLD: "R_X86_64_TLSLD", R_X86_64_DTPOFF32: "R_X86_64_DTPOFF32",
	R_X86_64_GOTTPOFF: "R_X86_64_GOTTPOFF", R_X86_64_TPOFF32: "R_X86_64_TPOFF32",
	R_X86_64_PC64: "R_X86_64_PC64", R_X86_64_GOTOFF64: "R_X86_64_GOTOFF64",
	R_X86_64_GOTPC32: "R_X86_64_GOTPC32", R_X86_64_GOT64: "R_X86_64_GOT64",
	R_X86_64_GOTPCREL64: "R_X86_64_GOTPCREL64", R_X86_64_GOTPC64: "R_X86_64_GOTPC64",
	R_X86_64_GOTPLT64: "R_X86_64_GOTPLT64", R_X86_64_PLTOFF64: "R_X86_64_PLTOFF64",
	R_X86_64_SIZE32: "R_X86_64_SIZE32", R_X86_64_SIZE64: "R_X86_64_SIZE64",
	R_X86_64_GOTPC32_TLSDESC: "R_X86_64_GOTPC32_TLSDESC",
	R_X86_64_TLSDESC_CALL:    "R_X86_64_TLSDESC_CALL",
	R_X86_64_TLSDESC:         "R_X86_64_TLSDESC",
	R_X86_64_IRELATIVE:       "R_X86_64_IRELATIVE",
	R_X86_64_RELATIVE64:      "R_X86_64_RELATIVE64",
	R_X86_64_PC32_BND:        "R_X86_64_PC32_BND",
	R_X86_64_PLT32_BND:       "R_X86_64_PLT32_BND",
	R_X86_64_GOTPCRELX:       "R_X86_64_GOTPCRELX",
	R_X86_64_REX_GOTPCRELX:   "R_X86_64_REX_GOTPCRELX",

	R_X86_64_CODE_4_GOTPCRELX:       "R_X86_64_CODE_4_GOTPCRELX",
	R_X86_64_CODE_4_GOTTPOFF:        "R_X86_64_CODE_4_GOTTPOFF",
	R_X86_64_CODE_4_GOTPC32_TLSDESC: "R_X86_64_CODE_4_GOTPC32_TLSDESC",
	R_X86_64_CODE_5_GOTPCRELX:       "R_X86_64_CODE_5_GOTPCRELX",
	R_X86_64_CODE_5_GOTTPOFF:        "R_X86_64_CODE_5_GOTTPOFF",
	R_X86_64_CODE_5_GOTPC32_TLSDESC: "R_X86_64_CODE_5_GOTPC32_TLSDESC",
	R_X86_64_CODE_6_GOTPCRELX:       "R_X86_64_CODE_6_GOTPCRELX",
	R_X86_64_CODE_6_GOTTPOFF:        "R_X86_64_CODE_6_GOTTPOFF",
	R_X86_64_CODE_6_GOTPC32_TLSDESC: "R_X86_64_CODE_6_GOTPC32_TLSDESC",
}