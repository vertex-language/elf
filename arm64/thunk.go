package arm64

import (
	"encoding/binary"
	"fmt"

	"github.com/vertex-language/elf"
	"github.com/vertex-language/elf/backend"
)

// Thunk describes the range-extension trampoline's geometry: three
// instructions loading an absolute 64-bit address into x16 and branching to
// it, the same ADRP/ADD/BR shape a PLT entry uses once the address it needs
// is a plain symbol rather than a GOT slot.
func (Backend) Thunk() backend.ThunkShape {
	return backend.ThunkShape{Size: 12, Align: 4, Scratch: "x16"}
}

// InRange reports whether a branch of this relocation type can reach its
// target directly.
//
// Only CALL26 and JUMP26 are answered for real: they are the only types this
// package ever asks growThunks to consider a thunk for, since Classify maps
// them alone to KindPltPC — the trigger relax.go checks before calling this
// at all. Every other KindPC type Classify recognises (PREL32, ADR_PREL_LO21,
// TSTBR14, CONDBR19, and the rest) reports true unconditionally: a thunk
// cannot help a conditional branch or a data reference, whose narrower field
// would need relaxation into a different instruction sequence to extend, not
// a redirect to some other address that is generally no closer. Leaving
// those alone means an out-of-range one fails loudly in Apply's own overflow
// check, which is the correct outcome until relaxation exists.
func (Backend) InRange(typ uint32, src, dst uint64) bool {
	switch elf.RelocAArch64(typ) {
	case elf.R_AARCH64_CALL26, elf.R_AARCH64_JUMP26:
		diff := int64(dst) - int64(src)
		const lo, hi = -(1 << 27), (1 << 27) - 4 // imm26 is a word offset: ±128MiB
		return diff >= lo && diff <= hi
	}
	return true
}

// WriteThunk emits the trampoline.
//
//	adrp x16, Page(target)
//	add  x16, x16, Offset(target)
//	br   x16
func (Backend) WriteThunk(buf []byte, s *backend.Site, target uint64, addr uint64) error {
	if len(buf) < 12 {
		return fmt.Errorf("arm64: thunk needs 12 bytes, got %d", len(buf))
	}
	pages := int64(page(target)) - int64(page(addr))

	ord := binary.LittleEndian
	ord.PutUint32(buf[0:], adrp(16, int32(pages>>12)))
	ord.PutUint32(buf[4:], addImm64(16, 16, uint32(target&0xFFF)))
	ord.PutUint32(buf[8:], br(16))
	return nil
}
