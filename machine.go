package elf

import "strconv"

// Machine is e_machine.
//
// e_machine is the on-disk identity. It is not sufficient to describe a target
// on its own: EM_MIPS, EM_RISCV, and EM_LOONGARCH each cover both a 32- and a
// 64-bit architecture, distinguished only by EI_CLASS. Use ArchOf to resolve
// the pair, and never Machine alone.
type Machine uint16

const (
	EM_NONE         Machine = 0
	EM_SPARC        Machine = 2
	EM_386          Machine = 3
	EM_68K          Machine = 4
	EM_88K          Machine = 5
	EM_860          Machine = 7
	EM_MIPS         Machine = 8
	EM_S370         Machine = 9
	EM_MIPS_RS3_LE  Machine = 10
	EM_PARISC       Machine = 15
	EM_SPARC32PLUS  Machine = 18
	EM_PPC          Machine = 20
	EM_PPC64        Machine = 21
	EM_S390         Machine = 22
	EM_ARM          Machine = 40
	EM_ALPHA        Machine = 41
	EM_SH           Machine = 42
	EM_SPARCV9      Machine = 43
	EM_IA_64        Machine = 50
	EM_X86_64       Machine = 62
	EM_AVR          Machine = 83
	EM_M32R         Machine = 88
	EM_XTENSA       Machine = 94
	EM_MICROBLAZE   Machine = 189
	EM_QDSP6        Machine = 164 // Hexagon
	EM_AARCH64      Machine = 183
	EM_ARC_COMPACT2 Machine = 195
	EM_AMDGPU       Machine = 224
	EM_RISCV        Machine = 243
	EM_BPF          Machine = 247
	EM_VE           Machine = 251
	EM_CSKY         Machine = 252
	EM_LOONGARCH    Machine = 258
)

func (m Machine) String() string {
	if s, ok := machineNames[m]; ok {
		return s
	}
	return "EM(" + strconv.FormatUint(uint64(m), 10) + ")"
}

var machineNames = map[Machine]string{
	EM_NONE: "EM_NONE", EM_SPARC: "EM_SPARC", EM_386: "EM_386",
	EM_68K: "EM_68K", EM_88K: "EM_88K", EM_860: "EM_860",
	EM_MIPS: "EM_MIPS", EM_S370: "EM_S370", EM_MIPS_RS3_LE: "EM_MIPS_RS3_LE",
	EM_PARISC: "EM_PARISC", EM_SPARC32PLUS: "EM_SPARC32PLUS",
	EM_PPC: "EM_PPC", EM_PPC64: "EM_PPC64", EM_S390: "EM_S390",
	EM_ARM: "EM_ARM", EM_ALPHA: "EM_ALPHA", EM_SH: "EM_SH",
	EM_SPARCV9: "EM_SPARCV9", EM_IA_64: "EM_IA_64", EM_X86_64: "EM_X86_64",
	EM_AVR: "EM_AVR", EM_M32R: "EM_M32R", EM_XTENSA: "EM_XTENSA",
	EM_MICROBLAZE: "EM_MICROBLAZE", EM_QDSP6: "EM_QDSP6",
	EM_AARCH64: "EM_AARCH64", EM_ARC_COMPACT2: "EM_ARC_COMPACT2",
	EM_AMDGPU: "EM_AMDGPU", EM_RISCV: "EM_RISCV", EM_BPF: "EM_BPF",
	EM_VE: "EM_VE", EM_CSKY: "EM_CSKY", EM_LOONGARCH: "EM_LOONGARCH",
}

// UsesREL reports whether this machine's psABI uses SHT_REL with implicit
// addends rather than SHT_RELA. Machines not listed use RELA.
func (m Machine) UsesREL() bool {
	switch m {
	case EM_386, EM_ARM, EM_MIPS, EM_MIPS_RS3_LE:
		return true
	}
	return false
}

// Arch is a resolved architecture: machine plus width, with the ambiguity of
// e_machine removed. It is the identity backends register against and the one
// Target carries.
type Arch uint16

const (
	ArchUnknown Arch = iota

	ArchI386
	ArchAMD64

	ArchARM
	ArchARM64

	ArchRISCV32
	ArchRISCV64

	ArchMIPS
	ArchMIPS64

	ArchPPC
	ArchPPC64

	ArchS390X

	ArchLoongArch32
	ArchLoongArch64

	ArchSPARC
	ArchSPARC64

	ArchSH
	ArchIA64
	ArchAlpha
	ArchM68K
	ArchM32R
	ArchXtensa
	ArchAVR
	ArchHexagon
	ArchARC
	ArchCSKY
	ArchBPF
	ArchVE
	ArchAMDGPU
)

func (a Arch) String() string {
	if s, ok := archNames[a]; ok {
		return s
	}
	return "unknown"
}

var archNames = map[Arch]string{
	ArchI386: "i386", ArchAMD64: "x86-64",
	ArchARM: "arm", ArchARM64: "arm64",
	ArchRISCV32: "riscv32", ArchRISCV64: "riscv64",
	ArchMIPS: "mips", ArchMIPS64: "mips64",
	ArchPPC: "ppc", ArchPPC64: "ppc64",
	ArchS390X:       "s390x",
	ArchLoongArch32: "loongarch32", ArchLoongArch64: "loongarch64",
	ArchSPARC: "sparc", ArchSPARC64: "sparc64",
	ArchSH: "sh", ArchIA64: "ia64", ArchAlpha: "alpha",
	ArchM68K: "m68k", ArchM32R: "m32r", ArchXtensa: "xtensa",
	ArchAVR: "avr", ArchHexagon: "hexagon", ArchARC: "arc",
	ArchCSKY: "csky", ArchBPF: "bpf", ArchVE: "ve", ArchAMDGPU: "amdgpu",
}

// Class returns the width an Arch implies. Every Arch is either 32- or 64-bit
// by construction; ArchUnknown returns ELFCLASSNONE.
func (a Arch) Class() Class {
	switch a {
	case ArchAMD64, ArchARM64, ArchRISCV64, ArchMIPS64, ArchPPC64,
		ArchS390X, ArchLoongArch64, ArchSPARC64, ArchIA64, ArchAlpha,
		ArchBPF, ArchVE, ArchAMDGPU:
		return ELFCLASS64
	case ArchI386, ArchARM, ArchRISCV32, ArchMIPS, ArchPPC,
		ArchLoongArch32, ArchSPARC, ArchSH, ArchM68K, ArchM32R,
		ArchXtensa, ArchAVR, ArchHexagon, ArchARC, ArchCSKY:
		return ELFCLASS32
	}
	return ELFCLASSNONE
}

// ArchOf resolves an e_machine and an EI_CLASS to an Arch.
//
// The class argument is not optional garnish. For EM_MIPS, EM_RISCV, and
// EM_LOONGARCH the same e_machine covers two architectures, and reading it
// without the class silently produces the 64-bit answer for 32-bit objects.
// This is the only Machine-to-Arch conversion in the module, so no caller has
// to patch up the result afterward.
func ArchOf(m Machine, c Class) Arch {
	wide := c.Wide()
	switch m {
	case EM_386:
		return ArchI386
	case EM_X86_64:
		return ArchAMD64
	case EM_ARM:
		return ArchARM
	case EM_AARCH64:
		return ArchARM64
	case EM_RISCV:
		if wide {
			return ArchRISCV64
		}
		return ArchRISCV32
	case EM_MIPS, EM_MIPS_RS3_LE:
		if wide {
			return ArchMIPS64
		}
		return ArchMIPS
	case EM_LOONGARCH:
		if wide {
			return ArchLoongArch64
		}
		return ArchLoongArch32
	case EM_PPC:
		return ArchPPC
	case EM_PPC64:
		return ArchPPC64
	case EM_S390:
		// EM_S390 with ELFCLASS32 is 31-bit s390, which this module does not
		// support; only s390x is recognised.
		if wide {
			return ArchS390X
		}
		return ArchUnknown
	case EM_SPARC, EM_SPARC32PLUS:
		return ArchSPARC
	case EM_SPARCV9:
		return ArchSPARC64
	case EM_SH:
		return ArchSH
	case EM_IA_64:
		return ArchIA64
	case EM_ALPHA:
		return ArchAlpha
	case EM_68K:
		return ArchM68K
	case EM_M32R:
		return ArchM32R
	case EM_XTENSA:
		return ArchXtensa
	case EM_AVR:
		return ArchAVR
	case EM_QDSP6:
		return ArchHexagon
	case EM_ARC_COMPACT2:
		return ArchARC
	case EM_CSKY:
		return ArchCSKY
	case EM_BPF:
		return ArchBPF
	case EM_VE:
		return ArchVE
	case EM_AMDGPU:
		return ArchAMDGPU
	}
	return ArchUnknown
}

// Machine returns the e_machine value to write for this Arch.
func (a Arch) Machine() Machine {
	switch a {
	case ArchI386:
		return EM_386
	case ArchAMD64:
		return EM_X86_64
	case ArchARM:
		return EM_ARM
	case ArchARM64:
		return EM_AARCH64
	case ArchRISCV32, ArchRISCV64:
		return EM_RISCV
	case ArchMIPS, ArchMIPS64:
		return EM_MIPS
	case ArchPPC:
		return EM_PPC
	case ArchPPC64:
		return EM_PPC64
	case ArchS390X:
		return EM_S390
	case ArchLoongArch32, ArchLoongArch64:
		return EM_LOONGARCH
	case ArchSPARC:
		return EM_SPARC
	case ArchSPARC64:
		return EM_SPARCV9
	case ArchSH:
		return EM_SH
	case ArchIA64:
		return EM_IA_64
	case ArchAlpha:
		return EM_ALPHA
	case ArchM68K:
		return EM_68K
	case ArchM32R:
		return EM_M32R
	case ArchXtensa:
		return EM_XTENSA
	case ArchAVR:
		return EM_AVR
	case ArchHexagon:
		return EM_QDSP6
	case ArchARC:
		return EM_ARC_COMPACT2
	case ArchCSKY:
		return EM_CSKY
	case ArchBPF:
		return EM_BPF
	case ArchVE:
		return EM_VE
	case ArchAMDGPU:
		return EM_AMDGPU
	}
	return EM_NONE
}