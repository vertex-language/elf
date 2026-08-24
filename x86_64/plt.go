package x86_64

import (
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

		// .got.plt opens with three slots the dynamic loader owns: the
		// address of _DYNAMIC, a link_map pointer the loader fills in, and
		// the resolver's address it also fills in. The first slot belonging
		// to a PLT entry is therefore index 3, and writing one at index 0
		// overwrites _DYNAMIC and the program dies before main.
		PltReserved: 3,

		TlsGdEntries: 2,
	}
}

// Plt describes the procedure linkage table's geometry.
//
// This is the legacy format: a 16-byte header that reaches the resolver, and
// 16-byte entries. The Intel CET format splits each entry between .plt and
// .plt.sec so that an endbr64 can precede the indirect jump, and is not
// implemented here — SecEntrySize of zero tells link there is no second table,
// so call sites target .plt directly.
func (Backend) Plt() backend.PltShape {
	return backend.PltShape{
		HeaderSize:    16,
		EntrySize:     16,
		SecEntrySize:  0,
		IPltEntrySize: 16,
		Align:         16,
		Lazy:          true,
	}
}

// The instruction sequences below are unverified against a reference
// toolchain. They are transcribed from the psABI and match what readelf shows
// for a lazily-bound binary, but nothing in this repository has yet diffed a
// generated .plt against llvm-readobj's dump of one produced by clang. Treat a
// mismatch here as the first suspect for a binary that links cleanly and
// faults on its first library call.

// WritePltHeader fills PLT0, which pushes the loader's bookkeeping and jumps
// to the resolver.
//
//	ff 35 xx xx xx xx    push  GOTPLT+8(%rip)
//	ff 25 xx xx xx xx    jmp   *GOTPLT+16(%rip)
//	0f 1f 40 00          nopl  0(%rax)
func (Backend) WritePltHeader(buf []byte, s *backend.Site) error {
	if len(buf) < 16 {
		return fmt.Errorf("x86_64: PLT header needs 16 bytes, got %d", len(buf))
	}
	gotplt := s.Reqs.GotPltAddr()
	plt := s.Reqs.PltAddr()

	copy(buf, []byte{
		0xff, 0x35, 0, 0, 0, 0, // push GOT+8(%rip)
		0xff, 0x25, 0, 0, 0, 0, // jmp *GOT+16(%rip)
		0x0f, 0x1f, 0x40, 0x00, // nop
	})
	// Each displacement is measured from the end of its own instruction.
	put32(buf[2:], int32(int64(gotplt+8)-int64(plt+6)))
	put32(buf[8:], int32(int64(gotplt+16)-int64(plt+12)))
	return nil
}

// WriteGotPltHeader fills the three reserved slots.
//
// Slot 0 holds _DYNAMIC; the loader writes slots 1 and 2 itself, so they start
// as zero.
func (Backend) WriteGotPltHeader(buf []byte, s *backend.Site) error {
	if len(buf) < 24 {
		return fmt.Errorf("x86_64: .got.plt header needs 24 bytes, got %d", len(buf))
	}
	for i := range buf[:24] {
		buf[i] = 0
	}
	if d := s.Img.FindSection(".dynamic"); d != nil {
		s.Order.PutUint64(buf, d.Addr)
	}
	return nil
}

// WriteGotPlt fills the .got.plt slot belonging to a PLT entry.
//
// For lazy binding the slot points back into its own PLT entry, at the push
// that follows the indirect jump, so that the first call falls through to the
// resolver. Under eager binding the loader overwrites it before the program
// runs and the initial value never matters.
func (Backend) WriteGotPlt(buf []byte, s *backend.Site, sym *image.Sym) error {
	if len(buf) < 8 {
		return fmt.Errorf("x86_64: .got.plt slot needs 8 bytes, got %d", len(buf))
	}
	if sym.PltIndex == image.NoIndex {
		return fmt.Errorf("x86_64: %s has no PLT entry", sym)
	}
	shape := Backend{}.Plt()
	entry := s.Reqs.PltAddr() + shape.EntryOffset(int(sym.PltIndex))
	s.Order.PutUint64(buf, entry+6)
	return nil
}

// WritePlt fills one PLT entry.
//
//	ff 25 xx xx xx xx    jmp   *GOT[n](%rip)
//	68 xx xx xx xx       push  $index
//	e9 xx xx xx xx       jmp   PLT0
func (Backend) WritePlt(buf []byte, s *backend.Site, sym *image.Sym,
	pltAddr, gotAddr uint64, index int) error {

	if len(buf) < 16 {
		return fmt.Errorf("x86_64: PLT entry needs 16 bytes, got %d", len(buf))
	}
	copy(buf, []byte{
		0xff, 0x25, 0, 0, 0, 0, // jmp *GOT[n](%rip)
		0x68, 0, 0, 0, 0, // push $index
		0xe9, 0, 0, 0, 0, // jmp PLT0
	})
	put32(buf[2:], int32(int64(gotAddr)-int64(pltAddr+6)))
	put32(buf[7:], int32(index))
	put32(buf[12:], int32(int64(s.Reqs.PltAddr())-int64(pltAddr+16)))
	return nil
}

// WriteSecPlt is never called: this format reports no second table.
func (Backend) WriteSecPlt(buf []byte, s *backend.Site, sym *image.Sym,
	pltAddr, gotAddr uint64, index int) error {
	return fmt.Errorf("x86_64: this PLT format has no .plt.sec")
}

// put32 stores a little-endian signed displacement. The PLT is always
// little-endian because AMD64 is.
func put32(b []byte, v int32) {
	u := uint32(v)
	b[0] = byte(u)
	b[1] = byte(u >> 8)
	b[2] = byte(u >> 16)
	b[3] = byte(u >> 24)
}