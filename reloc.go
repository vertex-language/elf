package elf

// r_info packing. The 32- and 64-bit forms differ in both field width and
// shift, so the two are never interchangeable.

// RelInfo32 packs a symbol index and type into a 32-bit r_info.
func RelInfo32(sym, typ uint32) uint32 { return sym<<8 | typ&0xff }

// RelSym32 extracts the symbol index from a 32-bit r_info.
func RelSym32(info uint32) uint32 { return info >> 8 }

// RelType32 extracts the relocation type from a 32-bit r_info.
func RelType32(info uint32) uint32 { return info & 0xff }

// RelInfo64 packs a symbol index and type into a 64-bit r_info.
func RelInfo64(sym, typ uint32) uint64 { return uint64(sym)<<32 | uint64(typ) }

// RelSym64 extracts the symbol index from a 64-bit r_info.
func RelSym64(info uint64) uint32 { return uint32(info >> 32) }

// RelType64 extracts the relocation type from a 64-bit r_info.
func RelType64(info uint64) uint32 { return uint32(info) }

// RelocFormat selects how the object writer encodes relocation sections.
type RelocFormat uint8

const (
	// RelocAuto picks REL or RELA from the target's psABI.
	RelocAuto RelocFormat = iota
	RelocREL
	RelocRELA
)

func (f RelocFormat) String() string {
	switch f {
	case RelocREL:
		return "REL"
	case RelocRELA:
		return "RELA"
	}
	return "auto"
}