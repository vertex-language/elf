package elf

import "strconv"

// SHType is sh_type.
type SHType uint32

const (
	SHT_NULL          SHType = 0
	SHT_PROGBITS      SHType = 1
	SHT_SYMTAB        SHType = 2
	SHT_STRTAB        SHType = 3
	SHT_RELA          SHType = 4
	SHT_HASH          SHType = 5
	SHT_DYNAMIC       SHType = 6
	SHT_NOTE          SHType = 7
	SHT_NOBITS        SHType = 8
	SHT_REL           SHType = 9
	SHT_SHLIB         SHType = 10
	SHT_DYNSYM        SHType = 11
	SHT_INIT_ARRAY    SHType = 14
	SHT_FINI_ARRAY    SHType = 15
	SHT_PREINIT_ARRAY SHType = 16
	SHT_GROUP         SHType = 17
	SHT_SYMTAB_SHNDX  SHType = 18
	SHT_RELR          SHType = 19 // added in gABI 4.3

	SHT_LOOS   SHType = 0x60000000
	SHT_HIOS   SHType = 0x6fffffff
	SHT_LOPROC SHType = 0x70000000
	SHT_HIPROC SHType = 0x7fffffff
	SHT_LOUSER SHType = 0x80000000
	SHT_HIUSER SHType = 0xffffffff

	SHT_GNU_ATTRIBUTES SHType = 0x6ffffff5
	SHT_GNU_HASH       SHType = 0x6ffffff6
	SHT_GNU_LIBLIST    SHType = 0x6ffffff7
	SHT_GNU_verdef     SHType = 0x6ffffffd
	SHT_GNU_verneed    SHType = 0x6ffffffe
	SHT_GNU_versym     SHType = 0x6fffffff
)

func (t SHType) String() string {
	if s, ok := shTypeNames[t]; ok {
		return s
	}
	return "SHT(" + strconv.FormatUint(uint64(t), 16) + ")"
}

var shTypeNames = map[SHType]string{
	SHT_NULL: "SHT_NULL", SHT_PROGBITS: "SHT_PROGBITS",
	SHT_SYMTAB: "SHT_SYMTAB", SHT_STRTAB: "SHT_STRTAB",
	SHT_RELA: "SHT_RELA", SHT_HASH: "SHT_HASH",
	SHT_DYNAMIC: "SHT_DYNAMIC", SHT_NOTE: "SHT_NOTE",
	SHT_NOBITS: "SHT_NOBITS", SHT_REL: "SHT_REL",
	SHT_SHLIB: "SHT_SHLIB", SHT_DYNSYM: "SHT_DYNSYM",
	SHT_INIT_ARRAY: "SHT_INIT_ARRAY", SHT_FINI_ARRAY: "SHT_FINI_ARRAY",
	SHT_PREINIT_ARRAY: "SHT_PREINIT_ARRAY", SHT_GROUP: "SHT_GROUP",
	SHT_SYMTAB_SHNDX: "SHT_SYMTAB_SHNDX", SHT_RELR: "SHT_RELR",
	SHT_GNU_ATTRIBUTES: "SHT_GNU_ATTRIBUTES", SHT_GNU_HASH: "SHT_GNU_HASH",
	SHT_GNU_LIBLIST: "SHT_GNU_LIBLIST", SHT_GNU_verdef: "SHT_GNU_verdef",
	SHT_GNU_verneed: "SHT_GNU_verneed", SHT_GNU_versym: "SHT_GNU_versym",
}

// IsRelocation reports whether sections of this type hold relocation entries.
func (t SHType) IsRelocation() bool {
	return t == SHT_REL || t == SHT_RELA || t == SHT_RELR
}

// sh_flags bits.
const (
	SHF_WRITE            = 0x1
	SHF_ALLOC            = 0x2
	SHF_EXECINSTR        = 0x4
	SHF_MERGE            = 0x10
	SHF_STRINGS          = 0x20
	SHF_INFO_LINK        = 0x40
	SHF_LINK_ORDER       = 0x80
	SHF_OS_NONCONFORMING = 0x100
	SHF_GROUP            = 0x200
	SHF_TLS              = 0x400
	SHF_COMPRESSED       = 0x800

	SHF_MASKOS   = 0x0ff00000
	SHF_MASKPROC = 0xf0000000

	SHF_GNU_RETAIN = 0x200000
)

// Section group flags.
const (
	GRP_COMDAT   = 0x1
	GRP_MASKOS   = 0x0ff00000
	GRP_MASKPROC = 0xf0000000
)

// Special section indexes. Named with an Idx suffix because obj uses the bare
// names for its sentinel *Section values.
const (
	SHN_UNDEF_IDX     = 0
	SHN_LORESERVE_IDX = 0xff00
	SHN_LOPROC_IDX    = 0xff00
	SHN_HIPROC_IDX    = 0xff1f
	SHN_LOOS_IDX      = 0xff20
	SHN_HIOS_IDX      = 0xff3f
	SHN_ABS_IDX       = 0xfff1
	SHN_COMMON_IDX    = 0xfff2
	SHN_XINDEX_IDX    = 0xffff
	SHN_HIRESERVE_IDX = 0xffff
)

// MaxSections is the largest number of real sections that can be indexed
// without the SHT_SYMTAB_SHNDX escape: SHN_LORESERVE minus the null section
// and the escape entry itself.
const MaxSections = SHN_LORESERVE_IDX - 1

// ReservedIndex reports whether i falls in the reserved range, where it names
// something other than a section header table entry.
func ReservedIndex(i uint32) bool {
	return i >= SHN_LORESERVE_IDX && i <= SHN_HIRESERVE_IDX
}

// CompressionType is the ch_type field of a compression header.
type CompressionType uint32

const (
	ELFCOMPRESS_ZLIB CompressionType = 1
	ELFCOMPRESS_ZSTD CompressionType = 2 // added in gABI 4.3

	ELFCOMPRESS_LOOS   CompressionType = 0x60000000
	ELFCOMPRESS_HIOS   CompressionType = 0x6fffffff
	ELFCOMPRESS_LOPROC CompressionType = 0x70000000
	ELFCOMPRESS_HIPROC CompressionType = 0x7fffffff
)

func (c CompressionType) String() string {
	switch c {
	case ELFCOMPRESS_ZLIB:
		return "ELFCOMPRESS_ZLIB"
	case ELFCOMPRESS_ZSTD:
		return "ELFCOMPRESS_ZSTD"
	}
	return "ELFCOMPRESS(" + strconv.FormatUint(uint64(c), 16) + ")"
}