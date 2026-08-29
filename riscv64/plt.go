package riscv64

import (
	"encoding/binary"
	"fmt"

	"github.com/vertex-language/elf/backend"
	"github.com/vertex-language/elf/image"
)

// Got describes the global offset table's geometry.
func (Backend) Got() backend.GotShape {
	return backend.GotShape{
		EntrySize: 8,
		Align:     8,
		Reserved:  0,

		// .got.plt reserves two slots, as on AArch64: one for the link_map
		// pointer, one for the resolver address, both loader-owned — moot for
		// this backend's own PLT, which never reads them (see the package
		// doc), but kept so the layout matches what other tools reading this
		// output expect to find there.
		PltReserved: 2,

		TlsGdEntries: 2,
	}
}

// Plt describes the procedure linkage table's geometry.
//
// HeaderSize is zero: this format has no PLT0 and no lazy binding. Every
// entry loads its own .got.plt slot and jumps through it, unconditionally —
// see the package doc for why a real lazy resolver is not attempted.
func (Backend) Plt() backend.PltShape {
	return backend.PltShape{
		HeaderSize:    0,
		EntrySize:     16,
		SecEntrySize:  0,
		IPltEntrySize: 0,
		Align:         8,
		Lazy:          false,
	}
}

// Register encodings used only by the PLT sequence below: t3 (x28), the
// scratch register both instructions of an entry compute through, and t1
// (x6), which receives the return address side effect of JALR the way any
// call does but which nothing here reads back.
const (
	regT1 = 6
	regT3 = 28
)

// WritePltHeader is never called: HeaderSize is zero.
func (Backend) WritePltHeader(buf []byte, s *backend.Site) error {
	return fmt.Errorf("riscv64: this PLT format has no header")
}

// WriteGotPltHeader fills the two reserved slots, both loader-owned and
// unused by this backend's own PLT entries.
func (Backend) WriteGotPltHeader(buf []byte, s *backend.Site) error {
	if len(buf) < 16 {
		return fmt.Errorf("riscv64: .got.plt header needs 16 bytes, got %d", len(buf))
	}
	for i := range buf[:16] {
		buf[i] = 0
	}
	return nil
}

// WriteGotPlt fills the .got.plt slot belonging to a PLT entry.
//
// There is no lazy path for the initial value to support, so this writes
// zero: the entry's first real use only works once the loader has already
// applied this slot's JUMP_SLOT relocation under eager binding, at which
// point what was here before is irrelevant.
func (Backend) WriteGotPlt(buf []byte, s *backend.Site, sym *image.Sym) error {
	if len(buf) < 8 {
		return fmt.Errorf("riscv64: .got.plt slot needs 8 bytes, got %d", len(buf))
	}
	for i := range buf[:8] {
		buf[i] = 0
	}
	return nil
}

// WritePlt fills one PLT entry.
//
//	auipc t3, %pcrel_hi(gotAddr)
//	ld    t3, %pcrel_lo(gotAddr)(t3)
//	jalr  t1, t3
//	nop
func (Backend) WritePlt(buf []byte, s *backend.Site, sym *image.Sym,
	pltAddr, gotAddr uint64, index int) error {

	if len(buf) < 16 {
		return fmt.Errorf("riscv64: PLT entry needs 16 bytes, got %d", len(buf))
	}
	hi20, lo12 := splitHiLo(int64(gotAddr) - int64(pltAddr))

	ord := binary.LittleEndian
	ord.PutUint32(buf[0:], rvU(0x17, regT3, hi20))           // auipc t3, hi20
	ord.PutUint32(buf[4:], rvI(0x03, regT3, 3, regT3, lo12)) // ld t3, lo12(t3)
	ord.PutUint32(buf[8:], rvI(0x67, regT1, 0, regT3, 0))    // jalr t1, t3
	ord.PutUint32(buf[12:], 0x00000013)                      // nop (addi x0, x0, 0)
	return nil
}

// WriteSecPlt is never called: this format reports no second table.
func (Backend) WriteSecPlt(buf []byte, s *backend.Site, sym *image.Sym,
	pltAddr, gotAddr uint64, index int) error {
	return fmt.Errorf("riscv64: this PLT format has no .plt.sec")
}

// rvU encodes a U-type instruction from scratch: LUI or AUIPC, opcode
// carrying the distinction.
func rvU(opcode, rd uint32, hi20 int32) uint32 {
	return uField(hi20) | rd<<7 | opcode
}

// rvI encodes an I-type instruction from scratch: LD, JALR, or ADDI here,
// opcode and funct3 carrying the distinction.
func rvI(opcode, rd, funct3, rs1 uint32, imm12 int32) uint32 {
	return iField(imm12) | rs1<<15 | funct3<<12 | rd<<7 | opcode
}
