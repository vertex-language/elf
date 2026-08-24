package elf

import "strconv"

// DynTag is d_tag in a .dynamic entry. Signed, because the OS- and
// processor-specific ranges are conventionally written as negative numbers in
// some psABIs.
type DynTag int64

const (
	DT_NULL            DynTag = 0
	DT_NEEDED          DynTag = 1
	DT_PLTRELSZ        DynTag = 2
	DT_PLTGOT          DynTag = 3
	DT_HASH            DynTag = 4
	DT_STRTAB          DynTag = 5
	DT_SYMTAB          DynTag = 6
	DT_RELA            DynTag = 7
	DT_RELASZ          DynTag = 8
	DT_RELAENT         DynTag = 9
	DT_STRSZ           DynTag = 10
	DT_SYMENT          DynTag = 11
	DT_INIT            DynTag = 12
	DT_FINI            DynTag = 13
	DT_SONAME          DynTag = 14
	DT_RPATH           DynTag = 15 // deprecated in favour of DT_RUNPATH
	DT_SYMBOLIC        DynTag = 16
	DT_REL             DynTag = 17
	DT_RELSZ           DynTag = 18
	DT_RELENT          DynTag = 19
	DT_PLTREL          DynTag = 20
	DT_DEBUG           DynTag = 21
	DT_TEXTREL         DynTag = 22
	DT_JMPREL          DynTag = 23
	DT_BIND_NOW        DynTag = 24
	DT_INIT_ARRAY      DynTag = 25
	DT_FINI_ARRAY      DynTag = 26
	DT_INIT_ARRAYSZ    DynTag = 27
	DT_FINI_ARRAYSZ    DynTag = 28
	DT_RUNPATH         DynTag = 29
	DT_FLAGS           DynTag = 30
	DT_ENCODING        DynTag = 32
	DT_PREINIT_ARRAY   DynTag = 32
	DT_PREINIT_ARRAYSZ DynTag = 33
	DT_SYMTAB_SHNDX    DynTag = 34
	DT_RELRSZ          DynTag = 35
	DT_RELR            DynTag = 36
	DT_RELRENT         DynTag = 37
	DT_SYMTABSZ        DynTag = 38 // added in gABI 4.3

	DT_LOOS   DynTag = 0x6000000d
	DT_HIOS   DynTag = 0x6ffff000
	DT_LOPROC DynTag = 0x70000000
	DT_HIPROC DynTag = 0x7fffffff

	DT_GNU_HASH   DynTag = 0x6ffffef5
	DT_VERSYM     DynTag = 0x6ffffff0
	DT_RELACOUNT  DynTag = 0x6ffffff9
	DT_RELCOUNT   DynTag = 0x6ffffffa
	DT_FLAGS_1    DynTag = 0x6ffffffb
	DT_VERDEF     DynTag = 0x6ffffffc
	DT_VERDEFNUM  DynTag = 0x6ffffffd
	DT_VERNEED    DynTag = 0x6ffffffe
	DT_VERNEEDNUM DynTag = 0x6fffffff
)

func (t DynTag) String() string {
	if s, ok := dynTagNames[t]; ok {
		return s
	}
	return "DT(" + strconv.FormatInt(int64(t), 16) + ")"
}

var dynTagNames = map[DynTag]string{
	DT_NULL: "DT_NULL", DT_NEEDED: "DT_NEEDED", DT_PLTRELSZ: "DT_PLTRELSZ",
	DT_PLTGOT: "DT_PLTGOT", DT_HASH: "DT_HASH", DT_STRTAB: "DT_STRTAB",
	DT_SYMTAB: "DT_SYMTAB", DT_RELA: "DT_RELA", DT_RELASZ: "DT_RELASZ",
	DT_RELAENT: "DT_RELAENT", DT_STRSZ: "DT_STRSZ", DT_SYMENT: "DT_SYMENT",
	DT_INIT: "DT_INIT", DT_FINI: "DT_FINI", DT_SONAME: "DT_SONAME",
	DT_RPATH: "DT_RPATH", DT_SYMBOLIC: "DT_SYMBOLIC", DT_REL: "DT_REL",
	DT_RELSZ: "DT_RELSZ", DT_RELENT: "DT_RELENT", DT_PLTREL: "DT_PLTREL",
	DT_DEBUG: "DT_DEBUG", DT_TEXTREL: "DT_TEXTREL", DT_JMPREL: "DT_JMPREL",
	DT_BIND_NOW: "DT_BIND_NOW", DT_INIT_ARRAY: "DT_INIT_ARRAY",
	DT_FINI_ARRAY: "DT_FINI_ARRAY", DT_INIT_ARRAYSZ: "DT_INIT_ARRAYSZ",
	DT_FINI_ARRAYSZ: "DT_FINI_ARRAYSZ", DT_RUNPATH: "DT_RUNPATH",
	DT_FLAGS: "DT_FLAGS", DT_PREINIT_ARRAY: "DT_PREINIT_ARRAY",
	DT_PREINIT_ARRAYSZ: "DT_PREINIT_ARRAYSZ", DT_SYMTAB_SHNDX: "DT_SYMTAB_SHNDX",
	DT_RELRSZ: "DT_RELRSZ", DT_RELR: "DT_RELR", DT_RELRENT: "DT_RELRENT",
	DT_SYMTABSZ: "DT_SYMTABSZ",
	DT_GNU_HASH: "DT_GNU_HASH", DT_VERSYM: "DT_VERSYM",
	DT_RELACOUNT: "DT_RELACOUNT", DT_RELCOUNT: "DT_RELCOUNT",
	DT_FLAGS_1: "DT_FLAGS_1", DT_VERDEF: "DT_VERDEF",
	DT_VERDEFNUM: "DT_VERDEFNUM", DT_VERNEED: "DT_VERNEED",
	DT_VERNEEDNUM: "DT_VERNEEDNUM",
}

// DT_FLAGS bits.
const (
	DF_ORIGIN     = 0x01
	DF_SYMBOLIC   = 0x02
	DF_TEXTREL    = 0x04
	DF_BIND_NOW   = 0x08
	DF_STATIC_TLS = 0x10
)

// DT_FLAGS_1 bits.
const (
	DF_1_NOW        = 0x00000001
	DF_1_GLOBAL     = 0x00000002
	DF_1_GROUP      = 0x00000004
	DF_1_NODELETE   = 0x00000008
	DF_1_LOADFLTR   = 0x00000010
	DF_1_INITFIRST  = 0x00000020
	DF_1_NOOPEN     = 0x00000040
	DF_1_ORIGIN     = 0x00000080
	DF_1_DIRECT     = 0x00000100
	DF_1_INTERPOSE  = 0x00000400
	DF_1_NODEFLIB   = 0x00000800
	DF_1_NODUMP     = 0x00001000
	DF_1_CONFALT    = 0x00002000
	DF_1_NODIRECT   = 0x00020000
	DF_1_NORELOC    = 0x00400000
	DF_1_SYMINTPOSE = 0x00800000
	DF_1_GLOBAUDIT  = 0x01000000
	DF_1_SINGLETON  = 0x02000000
	DF_1_PIE        = 0x08000000
)