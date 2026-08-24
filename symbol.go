package elf

import "strconv"

// SymBind is the high nibble of st_info.
type SymBind uint8

const (
	STB_LOCAL  SymBind = 0
	STB_GLOBAL SymBind = 1
	STB_WEAK   SymBind = 2

	STB_LOOS   SymBind = 10
	STB_HIOS   SymBind = 12
	STB_LOPROC SymBind = 13
	STB_HIPROC SymBind = 15

	STB_GNU_UNIQUE SymBind = 10
)

func (b SymBind) String() string {
	switch b {
	case STB_LOCAL:
		return "STB_LOCAL"
	case STB_GLOBAL:
		return "STB_GLOBAL"
	case STB_WEAK:
		return "STB_WEAK"
	case STB_GNU_UNIQUE:
		return "STB_GNU_UNIQUE"
	}
	return "STB(" + strconv.FormatUint(uint64(b), 10) + ")"
}

// SymType is the low nibble of st_info.
type SymType uint8

const (
	STT_NOTYPE  SymType = 0
	STT_OBJECT  SymType = 1
	STT_FUNC    SymType = 2
	STT_SECTION SymType = 3
	STT_FILE    SymType = 4
	STT_COMMON  SymType = 5
	STT_TLS     SymType = 6

	STT_LOOS   SymType = 10
	STT_HIOS   SymType = 12
	STT_LOPROC SymType = 13
	STT_HIPROC SymType = 15

	STT_GNU_IFUNC SymType = 10
)

func (t SymType) String() string {
	switch t {
	case STT_NOTYPE:
		return "STT_NOTYPE"
	case STT_OBJECT:
		return "STT_OBJECT"
	case STT_FUNC:
		return "STT_FUNC"
	case STT_SECTION:
		return "STT_SECTION"
	case STT_FILE:
		return "STT_FILE"
	case STT_COMMON:
		return "STT_COMMON"
	case STT_TLS:
		return "STT_TLS"
	case STT_GNU_IFUNC:
		return "STT_GNU_IFUNC"
	}
	return "STT(" + strconv.FormatUint(uint64(t), 10) + ")"
}

// SymInfo packs a binding and a type into st_info.
func SymInfo(bind SymBind, typ SymType) uint8 {
	return uint8(bind)<<4 | uint8(typ)&0xf
}

// SymInfoSplit unpacks st_info into its binding and type.
func SymInfoSplit(info uint8) (SymBind, SymType) {
	return SymBind(info >> 4), SymType(info & 0xf)
}

// SymVisibility is the low three bits of st_other.
type SymVisibility uint8

const (
	STV_DEFAULT   SymVisibility = 0
	STV_INTERNAL  SymVisibility = 1
	STV_HIDDEN    SymVisibility = 2
	STV_PROTECTED SymVisibility = 3

	// Added in gABI 4.3.
	STV_EXPORTED  SymVisibility = 4
	STV_SINGLETON SymVisibility = 5
	STV_ELIMINATE SymVisibility = 6
)

// VisibilityMask is the st_other mask for the visibility field.
//
// gABI 4.3 widened this from two bits to three to make room for STV_EXPORTED
// and its neighbours. Older code masking 0x3 misreads all three new values.
// Three bits is still safe against the psABIs that use the upper bits of
// st_other for their own purposes — PPC64's local entry offset lives in bits
// 5 through 7.
const VisibilityMask = 0x7

// Visibility extracts the visibility from an st_other byte.
func Visibility(other uint8) SymVisibility { return SymVisibility(other & VisibilityMask) }

// WithVisibility returns other with its visibility field replaced, preserving
// any psABI-specific bits above it.
func WithVisibility(other uint8, v SymVisibility) uint8 {
	return other&^VisibilityMask | uint8(v)&VisibilityMask
}

func (v SymVisibility) String() string {
	switch v {
	case STV_DEFAULT:
		return "STV_DEFAULT"
	case STV_INTERNAL:
		return "STV_INTERNAL"
	case STV_HIDDEN:
		return "STV_HIDDEN"
	case STV_PROTECTED:
		return "STV_PROTECTED"
	case STV_EXPORTED:
		return "STV_EXPORTED"
	case STV_SINGLETON:
		return "STV_SINGLETON"
	case STV_ELIMINATE:
		return "STV_ELIMINATE"
	}
	return "STV(" + strconv.FormatUint(uint64(v), 10) + ")"
}

// Exported reports whether a symbol with this visibility is visible outside
// its defining component.
func (v SymVisibility) Exported() bool {
	switch v {
	case STV_DEFAULT, STV_PROTECTED, STV_EXPORTED, STV_SINGLETON:
		return true
	}
	return false
}

// Preemptible reports whether a definition with this visibility may be
// overridden by a definition of the same name in another component.
func (v SymVisibility) Preemptible() bool {
	return v == STV_DEFAULT
}

// constraint ranks visibilities from least to most constraining, per gABI
// section 5.4: STV_PROTECTED, STV_HIDDEN, STV_INTERNAL, STV_EXPORTED.
// STV_DEFAULT is below all of them; STV_SINGLETON and STV_ELIMINATE are
// psABI-reserved and are treated as no more constraining than STV_HIDDEN,
// which is what the spec says STV_ELIMINATE degrades to.
func (v SymVisibility) constraint() int {
	switch v {
	case STV_DEFAULT:
		return 0
	case STV_PROTECTED:
		return 1
	case STV_SINGLETON:
		return 1
	case STV_HIDDEN, STV_ELIMINATE:
		return 2
	case STV_INTERNAL:
		return 3
	case STV_EXPORTED:
		return 4
	}
	return 0
}

// MostConstraining returns whichever of two visibilities the linker must
// propagate when references to or definitions of one name disagree.
//
// The gABI requires this: if any reference or definition carries a non-default
// visibility, that attribute must reach the resolving symbol, and when several
// disagree the most constraining wins. Symbol resolution that ignores this
// produces objects whose references were optimised on an assumption the output
// no longer honours.
func MostConstraining(a, b SymVisibility) SymVisibility {
	if b.constraint() > a.constraint() {
		return b
	}
	return a
}

// STN_UNDEF is the undefined symbol index; entry zero of every symbol table.
const STN_UNDEF = 0