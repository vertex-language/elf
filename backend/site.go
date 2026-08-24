package backend

import (
	"encoding/binary"
	"fmt"

	"github.com/vertex-language/elf"
	"github.com/vertex-language/elf/image"
)

// RangeError is a value that does not fit the field it was being written into:
// a branch too far to encode, an address too large for a 32-bit slot.
//
// It is the most common real link failure on large binaries, so it carries
// enough to act on — which relocation, in which chunk, at what offset, holding
// what value.
type RangeError struct {
	Chunk  *image.Chunk
	Off    uint64
	Type   uint32
	Sym    string
	Value  int64
	Bits   uint
	Signed bool
}

func (e *RangeError) Error() string {
	kind := "unsigned"
	if e.Signed {
		kind = "signed"
	}
	where := "<unplaced>"
	if e.Chunk != nil {
		where = e.Chunk.String()
	}
	name := e.Sym
	if name == "" {
		name = "<no symbol>"
	}
	return fmt.Sprintf("relocation type %d against %s at %s+%#x: %d does not fit a %d-bit %s field",
		e.Type, name, where, e.Off, e.Value, e.Bits, kind)
}

// Site is the place a relocation is applied: one chunk's output bytes, plus
// everything a backend needs to compute a value.
//
// link builds one Site per chunk and reuses it across that chunk's
// relocations, so a backend must not retain it past the Apply call it was
// handed to.
type Site struct {
	// Img is the output being written.
	Img *image.Image

	// Chunk is the contribution these bytes came from, for diagnostics.
	Chunk *image.Chunk

	// Data is the chunk's region of the output buffer. Writes go here and
	// land in the file directly; there is no copy-back step.
	Data []byte

	// Addr is the run-time address of Data[0].
	Addr uint64

	// Class and Order are the output's width and byte order.
	Class elf.Class
	Order binary.ByteOrder

	// Reqs is what the scan pass decided, for backends that need the GOT
	// base or a slot's address while applying.
	Reqs *Reqs
}

// Wide reports whether the output uses 64-bit addresses.
func (s *Site) Wide() bool { return s.Class.Wide() }

// P returns the run-time address of the relocation site.
func (s *Site) P(off uint64) uint64 { return s.Addr + off }

// Slice returns n writable bytes at off within the chunk.
func (s *Site) Slice(off, n uint64) ([]byte, error) {
	total := uint64(len(s.Data))
	if off > total || n > total-off {
		return nil, fmt.Errorf("backend: %d bytes at %#x in %s, which is %d bytes: %w",
			n, off, s.Chunk, total, image.ErrOutOfBounds)
	}
	return s.Data[off : off+n], nil
}

// Read helpers. Each returns an error rather than panicking, because the
// offset came from a relocation record in an input file.

func (s *Site) U8(off uint64) (uint8, error) {
	b, err := s.Slice(off, 1)
	if err != nil {
		return 0, err
	}
	return b[0], nil
}

func (s *Site) U16(off uint64) (uint16, error) {
	b, err := s.Slice(off, 2)
	if err != nil {
		return 0, err
	}
	return s.Order.Uint16(b), nil
}

func (s *Site) U32(off uint64) (uint32, error) {
	b, err := s.Slice(off, 4)
	if err != nil {
		return 0, err
	}
	return s.Order.Uint32(b), nil
}

func (s *Site) U64(off uint64) (uint64, error) {
	b, err := s.Slice(off, 8)
	if err != nil {
		return 0, err
	}
	return s.Order.Uint64(b), nil
}

// Write helpers.

func (s *Site) PutU8(off uint64, v uint8) error {
	b, err := s.Slice(off, 1)
	if err != nil {
		return err
	}
	b[0] = v
	return nil
}

func (s *Site) PutU16(off uint64, v uint16) error {
	b, err := s.Slice(off, 2)
	if err != nil {
		return err
	}
	s.Order.PutUint16(b, v)
	return nil
}

func (s *Site) PutU32(off uint64, v uint32) error {
	b, err := s.Slice(off, 4)
	if err != nil {
		return err
	}
	s.Order.PutUint32(b, v)
	return nil
}

func (s *Site) PutU64(off uint64, v uint64) error {
	b, err := s.Slice(off, 8)
	if err != nil {
		return err
	}
	s.Order.PutUint64(b, v)
	return nil
}

// PutWord writes a class-width value: 8 bytes for a 64-bit output, 4 for a
// 32-bit one.
func (s *Site) PutWord(off uint64, v uint64) error {
	if s.Wide() {
		return s.PutU64(off, v)
	}
	return s.PutU32(off, uint32(v))
}

// PutBytes copies b into the chunk at off.
func (s *Site) PutBytes(off uint64, b []byte) error {
	dst, err := s.Slice(off, uint64(len(b)))
	if err != nil {
		return err
	}
	copy(dst, b)
	return nil
}

// Mask32 replaces the bits of the 32-bit word at off that are set in mask,
// leaving the rest alone. This is the instruction-field write: a RISC branch
// displacement is scattered across an opcode that must survive intact.
func (s *Site) Mask32(off uint64, mask, v uint32) error {
	cur, err := s.U32(off)
	if err != nil {
		return err
	}
	return s.PutU32(off, cur&^mask|v&mask)
}

// CheckSigned reports a RangeError when v does not fit a signed field of the
// given width. A width of 64 always fits.
func (s *Site) CheckSigned(off uint64, r image.Reloc, v int64, bits uint) error {
	if bits >= 64 {
		return nil
	}
	lo := int64(-1) << (bits - 1)
	hi := int64(1)<<(bits-1) - 1
	if v < lo || v > hi {
		return s.rangeErr(off, r, v, bits, true)
	}
	return nil
}

// CheckUnsigned reports a RangeError when v does not fit an unsigned field of
// the given width.
func (s *Site) CheckUnsigned(off uint64, r image.Reloc, v uint64, bits uint) error {
	if bits >= 64 {
		return nil
	}
	if v > uint64(1)<<bits-1 {
		return s.rangeErr(off, r, int64(v), bits, false)
	}
	return nil
}

func (s *Site) rangeErr(off uint64, r image.Reloc, v int64, bits uint, signed bool) error {
	name := ""
	if r.Sym != nil {
		name = r.Sym.Name
	}
	return &RangeError{
		Chunk: s.Chunk, Off: off, Type: r.Type,
		Sym: name, Value: v, Bits: bits, Signed: signed,
	}
}

// SymAddr returns the relocation's symbol address, or an error naming the
// chunk and offset when the relocation resolved to nothing.
//
// A weak undefined symbol is not an error: it resolves to zero by design, and
// code that references one is written to test for it.
func (s *Site) SymAddr(off uint64, r image.Reloc) (uint64, error) {
	if r.Sym == nil {
		return 0, fmt.Errorf("backend: relocation type %d at %s+%#x names no symbol",
			r.Type, s.Chunk, off)
	}
	if !r.Sym.Defined() {
		if r.Sym.Weak() {
			return 0, nil
		}
		return 0, fmt.Errorf("backend: relocation type %d at %s+%#x against undefined symbol %s",
			r.Type, s.Chunk, off, r.Sym.Name)
	}
	return r.Sym.Addr(), nil
}