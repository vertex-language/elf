package elf

import "strconv"

// RelocAArch64 is a relocation type for ArchARM64.
//
// The numbers are the AArch64 ELF psABI's own ("ELF for the Arm 64-bit
// Architecture (AArch64)", ARM-software/abi-aa). AArch64 is a RELA
// architecture throughout: every relocation entry carries its own addend,
// and there is no REL encoding to fall back to.
type RelocAArch64 uint32

const (
	R_AARCH64_NONE RelocAArch64 = 0

	// Static data relocations: a plain pointer or PC-relative offset, of the
	// given width, with no instruction-encoding knowledge involved.
	R_AARCH64_ABS64  RelocAArch64 = 257
	R_AARCH64_ABS32  RelocAArch64 = 258
	R_AARCH64_ABS16  RelocAArch64 = 259
	R_AARCH64_PREL64 RelocAArch64 = 260
	R_AARCH64_PREL32 RelocAArch64 = 261
	R_AARCH64_PREL16 RelocAArch64 = 262

	// LD_PREL_LO19 and GOT_LD_PREL19 are LDR-literal forms: a ±1MiB
	// PC-relative load of a value, or of a GOT entry, with no ADRP/ADD pair
	// involved.
	R_AARCH64_LD_PREL_LO19  RelocAArch64 = 273
	R_AARCH64_GOT_LD_PREL19 RelocAArch64 = 309

	// ADR and ADRP: a byte-precise 21-bit PC-relative field, and a 21-bit
	// field naming a 4KiB page. The _NC form is bit-for-bit identical to
	// ADR_PREL_PG_HI21; it is only distinguished so the large code model can
	// pair it with an addend adjustment without implying the ordinary one's
	// overflow check.
	R_AARCH64_ADR_PREL_LO21       RelocAArch64 = 274
	R_AARCH64_ADR_PREL_PG_HI21    RelocAArch64 = 275
	R_AARCH64_ADR_PREL_PG_HI21_NC RelocAArch64 = 276

	// The Lo12 family completing an ADRP: an ADD's twelve-bit page offset,
	// and a load or store's, scaled by the access width the LDST number in
	// the name states. NC ("no check") is every one of these: unlike the
	// data relocations above, none of this family can overflow in a way
	// worth refusing, since the field is exactly the bits ADRP left out.
	R_AARCH64_ADD_ABS_LO12_NC     RelocAArch64 = 277
	R_AARCH64_LDST8_ABS_LO12_NC   RelocAArch64 = 278
	R_AARCH64_LDST16_ABS_LO12_NC  RelocAArch64 = 284
	R_AARCH64_LDST32_ABS_LO12_NC  RelocAArch64 = 285
	R_AARCH64_LDST64_ABS_LO12_NC  RelocAArch64 = 286
	R_AARCH64_LDST128_ABS_LO12_NC RelocAArch64 = 299

	// The branch and test fields.
	R_AARCH64_TSTBR14  RelocAArch64 = 279
	R_AARCH64_CONDBR19 RelocAArch64 = 280
	R_AARCH64_JUMP26   RelocAArch64 = 282
	R_AARCH64_CALL26   RelocAArch64 = 283

	// The GOT pair: ADRP to the page holding a symbol's GOT entry, then a
	// 64-bit load of the entry itself.
	R_AARCH64_ADR_GOT_PAGE     RelocAArch64 = 311
	R_AARCH64_LD64_GOT_LO12_NC RelocAArch64 = 312

	// General-dynamic TLS: an ADRP/ADD pair addressing the argument to
	// __tls_get_addr, or the byte-precise ADR form for a descriptor close
	// enough not to need a page split.
	R_AARCH64_TLSGD_ADR_PREL21  RelocAArch64 = 512
	R_AARCH64_TLSGD_ADR_PAGE21  RelocAArch64 = 513
	R_AARCH64_TLSGD_ADD_LO12_NC RelocAArch64 = 514

	// Local-dynamic TLS: the same ADR/ADRP shape as general-dynamic, naming
	// the module's TLS descriptor rather than one symbol's.
	R_AARCH64_TLSLD_ADR_PREL21 RelocAArch64 = 517
	R_AARCH64_TLSLD_ADR_PAGE21 RelocAArch64 = 518

	// Initial-exec TLS: the same ADRP/LDR shape as an ordinary GOT access,
	// naming the GOT entry that holds the offset from the thread pointer.
	R_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21   RelocAArch64 = 541
	R_AARCH64_TLSIE_LD64_GOTTPREL_LO12_NC RelocAArch64 = 542
	R_AARCH64_TLSIE_LD_GOTTPREL_PREL19    RelocAArch64 = 543

	// Local-exec TLS: the offset from the thread pointer is a link-time
	// constant, so no GOT indirection — just its high and low twelve bits.
	// LO12 without _NC exists for the rare case a toolchain wants the
	// overflow checked instead of accepting whatever ADD_TPREL_HI12 left.
	R_AARCH64_TLSLE_ADD_TPREL_HI12    RelocAArch64 = 549
	R_AARCH64_TLSLE_ADD_TPREL_LO12    RelocAArch64 = 550
	R_AARCH64_TLSLE_ADD_TPREL_LO12_NC RelocAArch64 = 551

	// TLSDESC: the descriptor-based model. ADR_PAGE21/LD64_LO12_NC/
	// ADD_LO12_NC address the descriptor the same way an ordinary GOT access
	// would; CALL marks the indirect call site itself and carries no field
	// of its own to rewrite.
	R_AARCH64_TLSDESC_ADR_PAGE21   RelocAArch64 = 562
	R_AARCH64_TLSDESC_LD64_LO12_NC RelocAArch64 = 563
	R_AARCH64_TLSDESC_ADD_LO12_NC  RelocAArch64 = 564
	R_AARCH64_TLSDESC_CALL         RelocAArch64 = 569

	// The dynamic relocations: written by the linker for the dynamic loader
	// to apply at load time, and never present in an input object.
	R_AARCH64_COPY         RelocAArch64 = 1024
	R_AARCH64_GLOB_DAT     RelocAArch64 = 1025
	R_AARCH64_JUMP_SLOT    RelocAArch64 = 1026
	R_AARCH64_RELATIVE     RelocAArch64 = 1027
	R_AARCH64_TLS_DTPMOD64 RelocAArch64 = 1028
	R_AARCH64_TLS_DTPREL64 RelocAArch64 = 1029
	R_AARCH64_TLS_TPREL64  RelocAArch64 = 1030
	R_AARCH64_TLSDESC      RelocAArch64 = 1031
	R_AARCH64_IRELATIVE    RelocAArch64 = 1032
)

func (r RelocAArch64) String() string {
	if n, ok := relocAArch64Names[r]; ok {
		return n
	}
	return "R_AARCH64(" + strconv.FormatUint(uint64(r), 10) + ")"
}

var relocAArch64Names = map[RelocAArch64]string{
	R_AARCH64_NONE: "R_AARCH64_NONE",

	R_AARCH64_ABS64:  "R_AARCH64_ABS64",
	R_AARCH64_ABS32:  "R_AARCH64_ABS32",
	R_AARCH64_ABS16:  "R_AARCH64_ABS16",
	R_AARCH64_PREL64: "R_AARCH64_PREL64",
	R_AARCH64_PREL32: "R_AARCH64_PREL32",
	R_AARCH64_PREL16: "R_AARCH64_PREL16",

	R_AARCH64_LD_PREL_LO19:  "R_AARCH64_LD_PREL_LO19",
	R_AARCH64_GOT_LD_PREL19: "R_AARCH64_GOT_LD_PREL19",

	R_AARCH64_ADR_PREL_LO21:       "R_AARCH64_ADR_PREL_LO21",
	R_AARCH64_ADR_PREL_PG_HI21:    "R_AARCH64_ADR_PREL_PG_HI21",
	R_AARCH64_ADR_PREL_PG_HI21_NC: "R_AARCH64_ADR_PREL_PG_HI21_NC",

	R_AARCH64_ADD_ABS_LO12_NC:     "R_AARCH64_ADD_ABS_LO12_NC",
	R_AARCH64_LDST8_ABS_LO12_NC:   "R_AARCH64_LDST8_ABS_LO12_NC",
	R_AARCH64_LDST16_ABS_LO12_NC:  "R_AARCH64_LDST16_ABS_LO12_NC",
	R_AARCH64_LDST32_ABS_LO12_NC:  "R_AARCH64_LDST32_ABS_LO12_NC",
	R_AARCH64_LDST64_ABS_LO12_NC:  "R_AARCH64_LDST64_ABS_LO12_NC",
	R_AARCH64_LDST128_ABS_LO12_NC: "R_AARCH64_LDST128_ABS_LO12_NC",

	R_AARCH64_TSTBR14:  "R_AARCH64_TSTBR14",
	R_AARCH64_CONDBR19: "R_AARCH64_CONDBR19",
	R_AARCH64_JUMP26:   "R_AARCH64_JUMP26",
	R_AARCH64_CALL26:   "R_AARCH64_CALL26",

	R_AARCH64_ADR_GOT_PAGE:     "R_AARCH64_ADR_GOT_PAGE",
	R_AARCH64_LD64_GOT_LO12_NC: "R_AARCH64_LD64_GOT_LO12_NC",

	R_AARCH64_TLSGD_ADR_PREL21:  "R_AARCH64_TLSGD_ADR_PREL21",
	R_AARCH64_TLSGD_ADR_PAGE21:  "R_AARCH64_TLSGD_ADR_PAGE21",
	R_AARCH64_TLSGD_ADD_LO12_NC: "R_AARCH64_TLSGD_ADD_LO12_NC",

	R_AARCH64_TLSLD_ADR_PREL21: "R_AARCH64_TLSLD_ADR_PREL21",
	R_AARCH64_TLSLD_ADR_PAGE21: "R_AARCH64_TLSLD_ADR_PAGE21",

	R_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21:   "R_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21",
	R_AARCH64_TLSIE_LD64_GOTTPREL_LO12_NC: "R_AARCH64_TLSIE_LD64_GOTTPREL_LO12_NC",
	R_AARCH64_TLSIE_LD_GOTTPREL_PREL19:    "R_AARCH64_TLSIE_LD_GOTTPREL_PREL19",

	R_AARCH64_TLSLE_ADD_TPREL_HI12:    "R_AARCH64_TLSLE_ADD_TPREL_HI12",
	R_AARCH64_TLSLE_ADD_TPREL_LO12:    "R_AARCH64_TLSLE_ADD_TPREL_LO12",
	R_AARCH64_TLSLE_ADD_TPREL_LO12_NC: "R_AARCH64_TLSLE_ADD_TPREL_LO12_NC",

	R_AARCH64_TLSDESC_ADR_PAGE21:   "R_AARCH64_TLSDESC_ADR_PAGE21",
	R_AARCH64_TLSDESC_LD64_LO12_NC: "R_AARCH64_TLSDESC_LD64_LO12_NC",
	R_AARCH64_TLSDESC_ADD_LO12_NC:  "R_AARCH64_TLSDESC_ADD_LO12_NC",
	R_AARCH64_TLSDESC_CALL:         "R_AARCH64_TLSDESC_CALL",

	R_AARCH64_COPY:         "R_AARCH64_COPY",
	R_AARCH64_GLOB_DAT:     "R_AARCH64_GLOB_DAT",
	R_AARCH64_JUMP_SLOT:    "R_AARCH64_JUMP_SLOT",
	R_AARCH64_RELATIVE:     "R_AARCH64_RELATIVE",
	R_AARCH64_TLS_DTPMOD64: "R_AARCH64_TLS_DTPMOD64",
	R_AARCH64_TLS_DTPREL64: "R_AARCH64_TLS_DTPREL64",
	R_AARCH64_TLS_TPREL64:  "R_AARCH64_TLS_TPREL64",
	R_AARCH64_TLSDESC:      "R_AARCH64_TLSDESC",
	R_AARCH64_IRELATIVE:    "R_AARCH64_IRELATIVE",
}
