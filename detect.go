package elf

// Byte counts the detection functions require. Is needs only the magic;
// KindOf reads e_type, which ends at byte 18.
const (
	MagicSize  = 4
	KindPrefix = 18
)

// Is reports whether head begins with the ELF magic. It needs MagicSize bytes
// and never errors: a short or non-ELF buffer is simply false.
func Is(head []byte) bool {
	return len(head) >= MagicSize &&
		head[0] == Magic[0] && head[1] == Magic[1] &&
		head[2] == Magic[2] && head[3] == Magic[3]
}

// Kind is a coarse classification of an ELF file, enough to route it without
// parsing it.
type Kind uint8

const (
	KindNone Kind = iota
	KindRel
	KindExec
	KindDyn
	KindCore
)

func (k Kind) String() string {
	switch k {
	case KindRel:
		return "rel"
	case KindExec:
		return "exec"
	case KindDyn:
		return "dyn"
	case KindCore:
		return "core"
	}
	return "none"
}

// KindOf classifies an ELF file from its first KindPrefix bytes.
//
// The magic is verified before EI_DATA is trusted, so a buffer of arbitrary
// bytes cannot produce a confident answer. An unrecognised e_type returns
// KindNone with a nil error: the file is ELF, just not a kind this module
// handles.
func KindOf(head []byte) (Kind, error) {
	if !Is(head) {
		if len(head) < MagicSize {
			return KindNone, ErrShortHeader
		}
		return KindNone, ErrNotELF
	}
	if len(head) < KindPrefix {
		return KindNone, ErrShortHeader
	}

	var v uint16
	switch Data(head[EI_DATA]) {
	case ELFDATA2LSB:
		v = uint16(head[16]) | uint16(head[17])<<8
	case ELFDATA2MSB:
		v = uint16(head[16])<<8 | uint16(head[17])
	default:
		return KindNone, ErrUnsupportedData
	}

	switch Type(v) {
	case ET_REL:
		return KindRel, nil
	case ET_EXEC:
		return KindExec, nil
	case ET_DYN:
		return KindDyn, nil
	case ET_CORE:
		return KindCore, nil
	}
	return KindNone, nil
}