package elf

import "strings"

// OS is the operating system a target runs on. It is not e_ident[EI_OSABI];
// see Target.OSABI for the relationship.
type OS uint8

const (
	OSNone OS = iota
	OSLinux
	OSFreeBSD
	OSNetBSD
	OSOpenBSD
	OSSolaris
	OSHaiku
	OSFuchsia
	OSNone_ // placeholder to keep the block extendable without renumbering
)

func (o OS) String() string {
	switch o {
	case OSLinux:
		return "linux"
	case OSFreeBSD:
		return "freebsd"
	case OSNetBSD:
		return "netbsd"
	case OSOpenBSD:
		return "openbsd"
	case OSSolaris:
		return "solaris"
	case OSHaiku:
		return "haiku"
	case OSFuchsia:
		return "fuchsia"
	}
	return "none"
}

// ABI is the C library and calling-convention environment: the last component
// of a target triple.
type ABI uint8

const (
	ABINone ABI = iota
	ABIELF               // bare metal, as in riscv64-unknown-elf
	ABIGNU               // glibc
	ABIGNUEabi           // arm, soft float
	ABIGNUEabiHF         // arm, hard float
	ABIMusl
	ABIMuslEabi
	ABIMuslEabiHF
	ABIAndroid
	ABIAndroidEabi
)

func (a ABI) String() string {
	switch a {
	case ABIELF:
		return "elf"
	case ABIGNU:
		return "gnu"
	case ABIGNUEabi:
		return "gnueabi"
	case ABIGNUEabiHF:
		return "gnueabihf"
	case ABIMusl:
		return "musl"
	case ABIMuslEabi:
		return "musleabi"
	case ABIMuslEabiHF:
		return "musleabihf"
	case ABIAndroid:
		return "android"
	case ABIAndroidEabi:
		return "androideabi"
	}
	return "none"
}

// HardFloat reports whether this ABI passes floating-point arguments in FP
// registers, which on ARM decides EF_ARM_ABI_FLOAT_HARD.
func (a ABI) HardFloat() bool {
	return a == ABIGNUEabiHF || a == ABIMuslEabiHF
}

// Target is everything the module needs to know about what it is producing or
// consuming, independent of any one file.
//
// Arch and Class together determine e_machine, and are checked against each
// other by Valid: there is no way to hold a 64-bit Arch with ELFCLASS32.
type Target struct {
	Arch   Arch
	Class  Class
	Endian Endian
	OS     OS
	ABI    ABI

	// Flags is e_flags. Architecture-specific; see the EF_* constants. Set
	// from the triple by ParseTarget, and adjustable afterward.
	Flags uint32
}

// Machine returns the e_machine value for this target.
func (t Target) Machine() Machine { return t.Arch.Machine() }

// Data returns the e_ident[EI_DATA] value for this target.
func (t Target) Data() Data { return t.Endian.Data() }

// Wide reports whether this target uses 64-bit addresses and offsets.
func (t Target) Wide() bool { return t.Class.Wide() }

// OSABI returns the e_ident[EI_OSABI] byte to write for a target that used no
// GNU extensions.
//
// The triple does not decide this. Nearly every Linux object, glibc or musl,
// carries ELFOSABI_NONE; ELFOSABI_GNU is required only once the object
// actually contains STB_GNU_UNIQUE or STT_GNU_IFUNC, which is a fact about
// emitted content rather than about the target. The emitter passes usedGNU
// accordingly.
func (t Target) OSABI(usedGNU bool) OSABI {
	if usedGNU {
		return ELFOSABI_GNU
	}
	switch t.OS {
	case OSFreeBSD:
		return ELFOSABI_FREEBSD
	case OSNetBSD:
		return ELFOSABI_NETBSD
	case OSOpenBSD:
		return ELFOSABI_OPENBSD
	case OSSolaris:
		return ELFOSABI_SOLARIS
	}
	return ELFOSABI_NONE
}

// Valid reports whether the target is internally consistent and nameable.
func (t Target) Valid() bool {
	if t.Arch == ArchUnknown || t.Endian == EndianUnknown || !t.Class.Valid() {
		return false
	}
	// The x32 ABI (ArchAMD64 with ELFCLASS32) is deliberately unsupported;
	// allowing it here would make every width decision downstream ambiguous.
	return t.Class == t.Arch.Class()
}

// String renders the target as arch/os-abi/endian/bits.
func (t Target) String() string {
	env := t.OS.String()
	if t.ABI != ABINone {
		env += "-" + t.ABI.String()
	}
	bits := "0"
	switch t.Class {
	case ELFCLASS32:
		bits = "32"
	case ELFCLASS64:
		bits = "64"
	}
	return t.Arch.String() + "/" + env + "/" + t.Endian.String() + "/" + bits
}

// ParseTarget parses a target triple.
//
// Triples in the wild have two, three, or four components and an optional
// vendor that carries no information ("x86_64-linux-gnu",
// "x86_64-unknown-linux-gnu", "arm-linux-gnueabihf", "riscv64-unknown-elf").
// Rather than assume a position for each field, the first component is taken
// as the architecture and every remaining component is classified by lookup;
// anything unrecognised is treated as a vendor and ignored.
func ParseTarget(triple string) (Target, error) {
	parts := strings.Split(triple, "-")
	if len(parts) == 0 || parts[0] == "" {
		return Target{}, ErrInvalidTarget
	}

	arch, class, endian := parseArchToken(parts[0])
	if arch == ArchUnknown {
		return Target{}, ErrInvalidTarget
	}

	t := Target{Arch: arch, Class: class, Endian: endian}
	for _, p := range parts[1:] {
		if os, ok := osTokens[p]; ok {
			t.OS = os
			continue
		}
		if abi, ok := abiTokens[p]; ok {
			t.ABI = abi
			continue
		}
		// Vendor or an unknown component. Ignored deliberately: rejecting
		// unknown vendors would break triples this module has no opinion on.
	}

	t.Flags = defaultFlags(t)

	if !t.Valid() {
		return Target{}, ErrInvalidTarget
	}
	return t, nil
}

var osTokens = map[string]OS{
	"linux":   OSLinux,
	"freebsd": OSFreeBSD,
	"netbsd":  OSNetBSD,
	"openbsd": OSOpenBSD,
	"solaris": OSSolaris,
	"haiku":   OSHaiku,
	"fuchsia": OSFuchsia,
	"none":    OSNone,
}

var abiTokens = map[string]ABI{
	"elf":         ABIELF,
	"eabi":        ABIELF,
	"gnu":         ABIGNU,
	"gnueabi":     ABIGNUEabi,
	"gnueabihf":   ABIGNUEabiHF,
	"musl":        ABIMusl,
	"musleabi":    ABIMuslEabi,
	"musleabihf":  ABIMuslEabiHF,
	"android":     ABIAndroid,
	"androideabi": ABIAndroidEabi,
}

// parseArchToken maps the first triple component to an architecture, a width,
// and a byte order. Byte order comes from the token because several
// architectures are bi-endian and encode the choice in the name.
func parseArchToken(tok string) (Arch, Class, Endian) {
	switch tok {
	case "x86_64", "amd64":
		return ArchAMD64, ELFCLASS64, EndianLittle
	case "i386", "i486", "i586", "i686", "x86":
		return ArchI386, ELFCLASS32, EndianLittle
	case "aarch64", "arm64":
		return ArchARM64, ELFCLASS64, EndianLittle
	case "aarch64_be":
		return ArchARM64, ELFCLASS64, EndianBig
	case "arm", "armv7", "armv7l", "armel", "armhf":
		return ArchARM, ELFCLASS32, EndianLittle
	case "armeb":
		return ArchARM, ELFCLASS32, EndianBig
	case "riscv64":
		return ArchRISCV64, ELFCLASS64, EndianLittle
	case "riscv32":
		return ArchRISCV32, ELFCLASS32, EndianLittle
	case "mips":
		return ArchMIPS, ELFCLASS32, EndianBig
	case "mipsel":
		return ArchMIPS, ELFCLASS32, EndianLittle
	case "mips64":
		return ArchMIPS64, ELFCLASS64, EndianBig
	case "mips64el":
		return ArchMIPS64, ELFCLASS64, EndianLittle
	case "powerpc", "ppc":
		return ArchPPC, ELFCLASS32, EndianBig
	case "powerpcle", "ppcle":
		return ArchPPC, ELFCLASS32, EndianLittle
	case "powerpc64", "ppc64":
		return ArchPPC64, ELFCLASS64, EndianBig
	case "powerpc64le", "ppc64le":
		return ArchPPC64, ELFCLASS64, EndianLittle
	case "s390x":
		return ArchS390X, ELFCLASS64, EndianBig
	case "loongarch64":
		return ArchLoongArch64, ELFCLASS64, EndianLittle
	case "loongarch32":
		return ArchLoongArch32, ELFCLASS32, EndianLittle
	case "sparc":
		return ArchSPARC, ELFCLASS32, EndianBig
	case "sparc64", "sparcv9":
		return ArchSPARC64, ELFCLASS64, EndianBig
	case "sh", "sh4":
		return ArchSH, ELFCLASS32, EndianLittle
	case "ia64":
		return ArchIA64, ELFCLASS64, EndianLittle
	case "alpha":
		return ArchAlpha, ELFCLASS64, EndianLittle
	case "m68k":
		return ArchM68K, ELFCLASS32, EndianBig
	case "xtensa":
		return ArchXtensa, ELFCLASS32, EndianLittle
	case "avr":
		return ArchAVR, ELFCLASS32, EndianLittle
	case "hexagon":
		return ArchHexagon, ELFCLASS32, EndianLittle
	case "csky":
		return ArchCSKY, ELFCLASS32, EndianLittle
	case "bpf", "bpfel":
		return ArchBPF, ELFCLASS64, EndianLittle
	case "bpfeb":
		return ArchBPF, ELFCLASS64, EndianBig
	}
	return ArchUnknown, ELFCLASSNONE, EndianUnknown
}

// defaultFlags derives e_flags from the target, for the architectures where
// the triple determines them. Callers can override the result.
func defaultFlags(t Target) uint32 {
	switch t.Arch {
	case ArchARM:
		f := uint32(EF_ARM_EABI_VER5)
		if t.ABI.HardFloat() {
			f |= EF_ARM_ABI_FLOAT_HARD
		} else {
			f |= EF_ARM_ABI_FLOAT_SOFT
		}
		return f
	case ArchMIPS:
		return EF_MIPS_ABI_O32 | EF_MIPS_ARCH_32
	case ArchMIPS64:
		return EF_MIPS_ARCH_64
	}
	return 0
}

// BaseAddress is the default load address for a non-PIE executable.
func (a Arch) BaseAddress() uint64 {
	switch a {
	case ArchI386:
		return 0x08048000
	case ArchAMD64:
		return 0x400000
	case ArchARM64:
		return 0x200000
	case ArchPPC64:
		return 0x10000000
	}
	return 0x10000
}

// MaxPageSize is the largest page size the target may be run with, and the
// alignment segments must be given so the image is loadable everywhere.
func (a Arch) MaxPageSize() uint64 {
	switch a {
	case ArchARM64, ArchPPC64, ArchLoongArch64:
		return 0x10000
	}
	return 0x1000
}

// CommonPageSize is the page size the target is usually run with. Used for
// padding decisions that trade size against a guarantee, such as RELRO.
func (a Arch) CommonPageSize() uint64 { return 0x1000 }