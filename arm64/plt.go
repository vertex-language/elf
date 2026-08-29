package arm64

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

		// .got.plt opens with two slots the dynamic loader owns: a link_map
		// pointer and the resolver's address, both filled in at load time.
		// The first slot belonging to a PLT entry is therefore index 2.
		PltReserved: 2,

		TlsGdEntries: 2,
	}
}

// Plt describes the procedure linkage table's geometry.
//
// This is the standard AAELF64 lazy-binding format: a 32-byte header (eight
// instructions) that reaches the resolver, and 16-byte entries (four
// instructions) that load their .got.plt slot and branch to it. There is no
// Intel-CET-style second table on this architecture, so SecEntrySize is
// zero and call sites target .plt directly.
func (Backend) Plt() backend.PltShape {
	return backend.PltShape{
		HeaderSize:    32,
		EntrySize:     16,
		SecEntrySize:  0,
		IPltEntrySize: 16,
		Align:         16,
		Lazy:          true,
	}
}

// The instruction sequences below follow the AAELF64 psABI's own description
// of the PLT (section 5.2, "Procedure Linkage Table for AArch64"), which is
// also what the GNU and LLVM linkers emit. They are unverified against a
// reference toolchain in this repository: nothing here has yet diffed a
// generated .plt against llvm-readobj's dump of one produced by clang. Treat
// a mismatch here as the first suspect for a binary that links cleanly and
// faults on its first library call.

// WritePltHeader fills PLT0, which loads the link_map and resolver from
// .got.plt[0] and .got.plt[1] and jumps to the resolver.
//
//	stp x16, x30, [sp, #-16]!
//	adrp x16, Page(&(.got.plt[2]))
//	ldr  x17, [x16, Offset(&(.got.plt[2]))]
//	add  x16, x16, Offset(&(.got.plt[2]))
//	br   x17
//	nop
//	nop
//	nop
func (Backend) WritePltHeader(buf []byte, s *backend.Site) error {
	if len(buf) < 32 {
		return fmt.Errorf("arm64: PLT header needs 32 bytes, got %d", len(buf))
	}
	gotplt := s.Reqs.GotPltAddr()
	plt := s.Reqs.PltAddr()
	target := gotplt + 16 // &(.got.plt[2]), the first loader-owned slot past the reserved pair

	ord := binary.LittleEndian
	ord.PutUint32(buf[0:], stpPre64(16, 30, 31, -16))
	ord.PutUint32(buf[4:], adrp(16, int32(int64(page(target))-int64(page(plt+4)))>>12))
	ord.PutUint32(buf[8:], ldrImm64(17, 16, target&0xFFF))
	ord.PutUint32(buf[12:], addImm64(16, 16, uint32(target&0xFFF)))
	ord.PutUint32(buf[16:], br(17))
	ord.PutUint32(buf[20:], nop())
	ord.PutUint32(buf[24:], nop())
	ord.PutUint32(buf[28:], nop())
	return nil
}

// WriteGotPltHeader fills the two reserved slots, which the dynamic loader
// overwrites with the link_map pointer and resolver address before the
// first lazy call runs.
func (Backend) WriteGotPltHeader(buf []byte, s *backend.Site) error {
	if len(buf) < 16 {
		return fmt.Errorf("arm64: .got.plt header needs 16 bytes, got %d", len(buf))
	}
	for i := range buf[:16] {
		buf[i] = 0
	}
	return nil
}

// WriteGotPlt fills the .got.plt slot belonging to a PLT entry.
//
// For lazy binding the slot points back at its own PLT entry's first
// instruction, so the first call falls through the entry and into the
// resolver. Under eager binding the loader overwrites it before the program
// runs and the initial value never matters.
func (Backend) WriteGotPlt(buf []byte, s *backend.Site, sym *image.Sym) error {
	if len(buf) < 8 {
		return fmt.Errorf("arm64: .got.plt slot needs 8 bytes, got %d", len(buf))
	}
	if sym.PltIndex == image.NoIndex {
		return fmt.Errorf("arm64: %s has no PLT entry", sym)
	}
	shape := Backend{}.Plt()
	entry := s.Reqs.PltAddr() + shape.EntryOffset(int(sym.PltIndex))
	s.Order.PutUint64(buf, entry)
	return nil
}

// WritePlt fills one PLT entry, which loads its .got.plt slot and jumps
// through it.
//
//	adrp x16, Page(&(.got.plt[n]))
//	ldr  x17, [x16, Offset(&(.got.plt[n]))]
//	add  x16, x16, Offset(&(.got.plt[n]))
//	br   x17
func (Backend) WritePlt(buf []byte, s *backend.Site, sym *image.Sym,
	pltAddr, gotAddr uint64, index int) error {

	if len(buf) < 16 {
		return fmt.Errorf("arm64: PLT entry needs 16 bytes, got %d", len(buf))
	}
	ord := binary.LittleEndian
	ord.PutUint32(buf[0:], adrp(16, int32(int64(page(gotAddr))-int64(page(pltAddr)))>>12))
	ord.PutUint32(buf[4:], ldrImm64(17, 16, gotAddr&0xFFF))
	ord.PutUint32(buf[8:], addImm64(16, 16, uint32(gotAddr&0xFFF)))
	ord.PutUint32(buf[12:], br(17))
	return nil
}

// WriteSecPlt is never called: this format reports no second table.
func (Backend) WriteSecPlt(buf []byte, s *backend.Site, sym *image.Sym,
	pltAddr, gotAddr uint64, index int) error {
	return fmt.Errorf("arm64: this PLT format has no .plt.sec")
}

// Instruction encoders. Each returns one little-endian AArch64 instruction
// word; register numbers are the plain 0-31 encoding (31 doubling as SP in
// the base+offset addressing forms used here).

func stpPre64(rt1, rt2, rn uint32, imm int32) uint32 {
	imm7 := uint32(imm/8) & 0x7F
	return 0xA9800000 | (imm7 << 15) | (rt2 << 10) | (rn << 5) | rt1
}

func addImm64(rd, rn, imm12 uint32) uint32 {
	return 0x91000000 | ((imm12 & 0xFFF) << 10) | (rn << 5) | rd
}

func ldrImm64(rt, rn uint32, byteOff uint64) uint32 {
	imm12 := uint32(byteOff/8) & 0xFFF
	return 0xF9400000 | (imm12 << 10) | (rn << 5) | rt
}

func br(rn uint32) uint32 { return 0xD61F0000 | (rn << 5) }

func nop() uint32 { return 0xD503201F }

func adrp(rd uint32, imm21 int32) uint32 {
	lo := uint32(imm21) & 0x3
	hi := (uint32(imm21) >> 2) & 0x7FFFF
	return 0x90000000 | (lo << 29) | (hi << 5) | rd
}
