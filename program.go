package elf

import "strconv"

// ProgType is p_type.
type ProgType uint32

const (
	PT_NULL    ProgType = 0
	PT_LOAD    ProgType = 1
	PT_DYNAMIC ProgType = 2
	PT_INTERP  ProgType = 3
	PT_NOTE    ProgType = 4
	PT_SHLIB   ProgType = 5
	PT_PHDR    ProgType = 6
	PT_TLS     ProgType = 7

	PT_LOOS   ProgType = 0x60000000
	PT_HIOS   ProgType = 0x6fffffff
	PT_LOPROC ProgType = 0x70000000
	PT_HIPROC ProgType = 0x7fffffff

	PT_GNU_EH_FRAME ProgType = 0x6474e550
	PT_GNU_STACK    ProgType = 0x6474e551
	PT_GNU_RELRO    ProgType = 0x6474e552
	PT_GNU_PROPERTY ProgType = 0x6474e553
)

func (t ProgType) String() string {
	if s, ok := progTypeNames[t]; ok {
		return s
	}
	return "PT(" + strconv.FormatUint(uint64(t), 16) + ")"
}

var progTypeNames = map[ProgType]string{
	PT_NULL: "PT_NULL", PT_LOAD: "PT_LOAD", PT_DYNAMIC: "PT_DYNAMIC",
	PT_INTERP: "PT_INTERP", PT_NOTE: "PT_NOTE", PT_SHLIB: "PT_SHLIB",
	PT_PHDR: "PT_PHDR", PT_TLS: "PT_TLS",
	PT_GNU_EH_FRAME: "PT_GNU_EH_FRAME", PT_GNU_STACK: "PT_GNU_STACK",
	PT_GNU_RELRO: "PT_GNU_RELRO", PT_GNU_PROPERTY: "PT_GNU_PROPERTY",
}

// p_flags bits. A different space from SHF_*, despite describing the same
// permissions; image.SegFlags keeps them apart in the output model.
const (
	PF_X        = 0x1
	PF_W        = 0x2
	PF_R        = 0x4
	PF_MASKOS   = 0x0ff00000
	PF_MASKPROC = 0xf0000000
)

// GNUStack selects what .note.GNU-stack the object writer emits. Omitting the
// section entirely makes the kernel assume an executable stack, so the
// non-executable default is the safe one.
type GNUStack uint8

const (
	StackNonExec GNUStack = iota
	StackExec
	StackOmit
)

func (s GNUStack) String() string {
	switch s {
	case StackExec:
		return "exec"
	case StackOmit:
		return "omit"
	}
	return "nonexec"
}

// Note types that carry linker-relevant content.
const (
	NT_GNU_ABI_TAG         = 1
	NT_GNU_BUILD_ID        = 3
	NT_GNU_PROPERTY_TYPE_0 = 5
)