package elf

import "strconv"

// e_ident indices.
const (
	EI_MAG0       = 0
	EI_MAG1       = 1
	EI_MAG2       = 2
	EI_MAG3       = 3
	EI_CLASS      = 4
	EI_DATA       = 5
	EI_VERSION    = 6
	EI_OSABI      = 7
	EI_ABIVERSION = 8
	EI_PAD        = 9
	EI_NIDENT     = 16
)

// Magic is the four-byte signature at the start of every ELF file.
var Magic = [4]byte{0x7F, 'E', 'L', 'F'}

// File format version. Only EV_CURRENT has ever been defined.
const (
	EV_NONE    = 0
	EV_CURRENT = 1
)

// Type is e_type: what kind of object this file is.
type Type uint16

const (
	ET_NONE Type = 0
	ET_REL  Type = 1
	ET_EXEC Type = 2
	ET_DYN  Type = 3
	ET_CORE Type = 4

	ET_LOOS   Type = 0xfe00
	ET_HIOS   Type = 0xfeff
	ET_LOPROC Type = 0xff00
	ET_HIPROC Type = 0xffff
)

func (t Type) String() string {
	switch t {
	case ET_NONE:
		return "ET_NONE"
	case ET_REL:
		return "ET_REL"
	case ET_EXEC:
		return "ET_EXEC"
	case ET_DYN:
		return "ET_DYN"
	case ET_CORE:
		return "ET_CORE"
	}
	if t >= ET_LOPROC {
		return "ET_LOPROC+" + strconv.FormatUint(uint64(t-ET_LOPROC), 10)
	}
	if t >= ET_LOOS {
		return "ET_LOOS+" + strconv.FormatUint(uint64(t-ET_LOOS), 10)
	}
	return "ET(" + strconv.FormatUint(uint64(t), 10) + ")"
}

// PN_XNUM is the e_phnum escape value: the real count is in the sh_info field
// of section header zero.
const PN_XNUM = 0xffff

// OSABI is e_ident[EI_OSABI].
//
// This byte is decided at emit time by what the linker actually produced, not
// by the target triple. Most Linux binaries carry ELFOSABI_NONE; ELFOSABI_GNU
// is required only when the object uses a GNU extension such as
// STB_GNU_UNIQUE or STT_GNU_IFUNC.
type OSABI uint8

const (
	ELFOSABI_NONE       OSABI = 0
	ELFOSABI_HPUX       OSABI = 1
	ELFOSABI_NETBSD     OSABI = 2
	ELFOSABI_GNU        OSABI = 3
	ELFOSABI_LINUX      OSABI = 3 // historical alias for ELFOSABI_GNU
	ELFOSABI_SOLARIS    OSABI = 6
	ELFOSABI_AIX        OSABI = 7
	ELFOSABI_IRIX       OSABI = 8
	ELFOSABI_FREEBSD    OSABI = 9
	ELFOSABI_TRU64      OSABI = 10
	ELFOSABI_MODESTO    OSABI = 11
	ELFOSABI_OPENBSD    OSABI = 12
	ELFOSABI_OPENVMS    OSABI = 13
	ELFOSABI_NSK        OSABI = 14
	ELFOSABI_AROS       OSABI = 15
	ELFOSABI_FENIXOS    OSABI = 16
	ELFOSABI_CLOUDABI   OSABI = 17
	ELFOSABI_OPENVOS    OSABI = 18
	ELFOSABI_ARM_AEABI  OSABI = 64
	ELFOSABI_ARM        OSABI = 97
	ELFOSABI_STANDALONE OSABI = 255
)

// OSABIArchStart is the first value reserved for architecture-specific use.
const OSABIArchStart OSABI = 64

// IsArchSpecific reports whether o is in the architecture-reserved range, where
// the same numeric value means different things on different machines.
func (o OSABI) IsArchSpecific() bool { return o >= OSABIArchStart }

func (o OSABI) String() string {
	switch o {
	case ELFOSABI_NONE:
		return "none"
	case ELFOSABI_HPUX:
		return "hpux"
	case ELFOSABI_NETBSD:
		return "netbsd"
	case ELFOSABI_GNU:
		return "gnu"
	case ELFOSABI_SOLARIS:
		return "solaris"
	case ELFOSABI_AIX:
		return "aix"
	case ELFOSABI_IRIX:
		return "irix"
	case ELFOSABI_FREEBSD:
		return "freebsd"
	case ELFOSABI_TRU64:
		return "tru64"
	case ELFOSABI_MODESTO:
		return "modesto"
	case ELFOSABI_OPENBSD:
		return "openbsd"
	case ELFOSABI_OPENVMS:
		return "openvms"
	case ELFOSABI_NSK:
		return "nsk"
	case ELFOSABI_AROS:
		return "aros"
	case ELFOSABI_FENIXOS:
		return "fenixos"
	case ELFOSABI_CLOUDABI:
		return "cloudabi"
	case ELFOSABI_OPENVOS:
		return "openvos"
	case ELFOSABI_STANDALONE:
		return "standalone"
	}
	if o.IsArchSpecific() {
		return "arch-specific(" + strconv.FormatUint(uint64(o), 10) + ")"
	}
	return "unknown(" + strconv.FormatUint(uint64(o), 10) + ")"
}