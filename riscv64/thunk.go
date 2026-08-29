package riscv64

import (
	"encoding/binary"
	"fmt"

	"github.com/vertex-language/elf"
	"github.com/vertex-language/elf/backend"
)

// regT0 is the scratch register the thunk computes through and jumps from —
// caller-saved, and not used to hold a live value across a JAL/JALR the way
// t1 is by this package's own PLT entries, so a thunk never has to worry
// about clobbering one.
const regT0 = 5

// Thunk describes the range-extension trampoline's geometry: an AUIPC/JALR
// pair reaching anywhere in the same ±2GiB a CALL_PLT itself can, the same
// shape this package's PLT entries use to reach a GOT slot rather than a
// plain address.
func (Backend) Thunk() backend.ThunkShape {
	return backend.ThunkShape{Size: 8, Align: 4, Scratch: "t0"}
}

// InRange reports whether a branch of this relocation type can reach its
// target directly.
//
// Only JAL is answered for real: it is the sole type Classify maps to
// KindPltPC alongside CALL_PLT... no — Classify maps CALL_PLT alone to
// KindPltPC, and JAL to KindPC, which is what makes relax.go consider both
// for a thunk (it triggers on either Kind). CALL_PLT's own AUIPC/JALR pair
// already spans the full range this thunk does, so it is never actually out
// of range in a file small enough for this module's own address-space
// assumptions to hold, and its case here is exact rather than omitted only
// for tidiness. BRANCH is the one type this leaves unanswered on purpose: its
// ±4KiB field is for a conditional test, and reaching a trampoline that far
// away needs inverting the condition around an unconditional jump — real
// relaxation — not a redirect, so it reports in range unconditionally and an
// actual overflow fails loudly in Apply instead.
func (Backend) InRange(typ uint32, src, dst uint64) bool {
	switch elf.RelocRISCV(typ) {
	case elf.R_RISCV_JAL:
		diff := int64(dst) - int64(src)
		const lo, hi = -(1 << 20), (1 << 20) - 2 // 21-bit signed, even: ±1MiB
		return diff >= lo && diff <= hi
	case elf.R_RISCV_CALL, elf.R_RISCV_CALL_PLT:
		diff := int64(dst) - int64(src)
		const lo, hi = -(1 << 31), (1 << 31) - 1
		return diff >= lo && diff <= hi
	}
	return true
}

// WriteThunk emits the trampoline.
//
//	auipc t0, %pcrel_hi(target)
//	jalr  x0, %pcrel_lo(target)(t0)
func (Backend) WriteThunk(buf []byte, s *backend.Site, target uint64, addr uint64) error {
	if len(buf) < 8 {
		return fmt.Errorf("riscv64: thunk needs 8 bytes, got %d", len(buf))
	}
	hi20, lo12 := splitHiLo(int64(target) - int64(addr))

	ord := binary.LittleEndian
	ord.PutUint32(buf[0:], rvU(0x17, regT0, hi20))       // auipc t0, hi20
	ord.PutUint32(buf[4:], rvI(0x67, 0, 0, regT0, lo12)) // jalr x0, lo12(t0)
	return nil
}
