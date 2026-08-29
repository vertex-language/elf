package riscv64

import (
	"fmt"

	"github.com/vertex-language/elf"
	"github.com/vertex-language/elf/backend"
	"github.com/vertex-language/elf/image"
)

// Apply writes one relocation into the output.
//
// The psABI's notation is used throughout: S is the symbol's address, A the
// addend, P the place, G the symbol's GOT slot offset, GOT the table's base,
// L the PLT entry's address.
func (b Backend) Apply(s *backend.Site, r image.Reloc) error {
	typ := elf.RelocRISCV(r.Type)
	if typ == elf.R_RISCV_NONE {
		return nil
	}

	off := r.Offset
	p := s.P(off)
	a := r.Addend

	switch typ {
	case elf.R_RISCV_32:
		sym, err := s.SymAddr(off, r)
		if err != nil {
			return err
		}
		v := int64(sym) + a
		if err := s.CheckUnsigned(off, r, uint64(v), 32); err != nil {
			return err
		}
		return s.PutU32(off, uint32(v))

	case elf.R_RISCV_64:
		sym, err := s.SymAddr(off, r)
		if err != nil {
			return err
		}
		return s.PutU64(off, uint64(int64(sym)+a))

	case elf.R_RISCV_HI20:
		sym, err := s.SymAddr(off, r)
		if err != nil {
			return err
		}
		hi20, _ := splitHiLo(int64(sym) + a)
		return s.Mask32(off, uMask, uField(hi20))

	case elf.R_RISCV_LO12_I:
		sym, err := s.SymAddr(off, r)
		if err != nil {
			return err
		}
		_, lo12 := splitHiLo(int64(sym) + a)
		return s.Mask32(off, iMask, iField(lo12))

	case elf.R_RISCV_LO12_S:
		sym, err := s.SymAddr(off, r)
		if err != nil {
			return err
		}
		_, lo12 := splitHiLo(int64(sym) + a)
		return s.Mask32(off, sMask, sField(lo12))

	case elf.R_RISCV_BRANCH:
		sym, err := s.SymAddr(off, r)
		if err != nil {
			return err
		}
		v := int64(sym) + a - int64(p)
		if err := s.CheckSigned(off, r, v, 13); err != nil {
			return err
		}
		return s.Mask32(off, bMask, bField(v))

	case elf.R_RISCV_JAL:
		sym, err := s.SymAddr(off, r)
		if err != nil {
			return err
		}
		v := int64(sym) + a - int64(p)
		if err := s.CheckSigned(off, r, v, 21); err != nil {
			return err
		}
		return s.Mask32(off, jMask, jField(v))

	case elf.R_RISCV_CALL, elf.R_RISCV_CALL_PLT:
		target := uint64(0)
		if typ == elf.R_RISCV_CALL_PLT && r.Sym != nil && r.Sym.PltIndex != image.NoIndex {
			var err error
			target, err = s.Reqs.PltEntryAddr(r.Sym)
			if err != nil {
				return err
			}
		} else {
			sym, err := s.SymAddr(off, r)
			if err != nil {
				return err
			}
			target = sym
		}
		v := int64(target) + a - int64(p)
		if err := s.CheckSigned(off, r, v, 32); err != nil {
			return err
		}
		hi20, lo12 := splitHiLo(v)
		if err := s.Mask32(off, uMask, uField(hi20)); err != nil {
			return err
		}
		return s.Mask32(off+4, iMask, iField(lo12))

	case elf.R_RISCV_PCREL_HI20:
		sym, err := s.SymAddr(off, r)
		if err != nil {
			return err
		}
		hi20, _ := splitHiLo(int64(sym) + a - int64(p))
		return s.Mask32(off, uMask, uField(hi20))

	case elf.R_RISCV_GOT_HI20, elf.R_RISCV_TLS_GOT_HI20:
		// Both AUIPC a GOT slot's address relative to P; only what the
		// loaded slot holds differs — a symbol's address for one, its
		// initial-exec thread-pointer offset for the other — and that
		// difference is entirely link/dynamic.go's concern when it fills the
		// slot, not this instruction's.
		slot, err := s.Reqs.GotSlotAddr(r.Sym)
		if err != nil {
			return fmt.Errorf("riscv64: %s+%#x: %w", s.Chunk, off, err)
		}
		hi20, _ := splitHiLo(int64(slot) + a - int64(p))
		return s.Mask32(off, uMask, uField(hi20))

	case elf.R_RISCV_PCREL_LO12_I:
		lo12, err := b.pairedLo12(s, r)
		if err != nil {
			return err
		}
		return s.Mask32(off, iMask, iField(lo12))

	case elf.R_RISCV_PCREL_LO12_S:
		lo12, err := b.pairedLo12(s, r)
		if err != nil {
			return err
		}
		return s.Mask32(off, sMask, sField(lo12))

	case elf.R_RISCV_TPREL_HI20:
		sym, err := s.SymAddr(off, r)
		if err != nil {
			return err
		}
		v, err := tpOff(s, sym)
		if err != nil {
			return err
		}
		hi20, _ := splitHiLo(v + a)
		return s.Mask32(off, uMask, uField(hi20))

	case elf.R_RISCV_TPREL_LO12_I:
		sym, err := s.SymAddr(off, r)
		if err != nil {
			return err
		}
		v, err := tpOff(s, sym)
		if err != nil {
			return err
		}
		_, lo12 := splitHiLo(v + a)
		return s.Mask32(off, iMask, iField(lo12))

	case elf.R_RISCV_TPREL_LO12_S:
		sym, err := s.SymAddr(off, r)
		if err != nil {
			return err
		}
		v, err := tpOff(s, sym)
		if err != nil {
			return err
		}
		_, lo12 := splitHiLo(v + a)
		return s.Mask32(off, sMask, sField(lo12))

	case elf.R_RISCV_TPREL_ADD:
		// Marks the instruction that adds the thread pointer in, for
		// relaxation to find. It names no field of its own.
		return nil
	}

	return fmt.Errorf("riscv64: %s+%#x: %v: %w", s.Chunk, off, typ,
		backend.ErrUnsupportedReloc)
}

// pairedLo12 recovers the low twelve bits a PCREL_LO12_I or PCREL_LO12_S
// relocation contributes.
//
// Its own Sym names a local label at the paired HI20 instruction's address,
// not the real target — the RISC-V psABI's one departure from every other
// architecture this module supports, where a LO12-family relocation always
// names the same symbol its HI21 or HI20 counterpart does. Finding the real
// value means locating that HI20 relocation, by offset, among this chunk's
// own relocations, and recomputing the same value it computed.
func (b Backend) pairedLo12(s *backend.Site, r image.Reloc) (int32, error) {
	if r.Sym == nil {
		return 0, fmt.Errorf("riscv64: %s+%#x: PCREL_LO12 names no label", s.Chunk, r.Offset)
	}
	hiAddr := r.Sym.Addr() + uint64(r.Addend)
	if hiAddr < s.Chunk.Addr() {
		return 0, fmt.Errorf("riscv64: %s+%#x: PCREL_LO12's label at %#x is before this chunk",
			s.Chunk, r.Offset, hiAddr)
	}
	hiOff := hiAddr - s.Chunk.Addr()

	relocs, err := s.Chunk.Relocs()
	if err != nil {
		return 0, err
	}
	for _, hr := range relocs {
		if hr.Offset != hiOff {
			continue
		}
		switch elf.RelocRISCV(hr.Type) {
		case elf.R_RISCV_PCREL_HI20:
			sym, err := s.SymAddr(hiOff, hr)
			if err != nil {
				return 0, err
			}
			_, lo12 := splitHiLo(int64(sym) + hr.Addend - int64(s.P(hiOff)))
			return lo12, nil

		case elf.R_RISCV_GOT_HI20, elf.R_RISCV_TLS_GOT_HI20:
			slot, err := s.Reqs.GotSlotAddr(hr.Sym)
			if err != nil {
				return 0, fmt.Errorf("riscv64: %s+%#x: %w", s.Chunk, r.Offset, err)
			}
			_, lo12 := splitHiLo(int64(slot) + hr.Addend - int64(s.P(hiOff)))
			return lo12, nil

		case elf.R_RISCV_TLS_GD_HI20:
			return 0, fmt.Errorf("riscv64: %s+%#x: %v: %w",
				s.Chunk, r.Offset, elf.RelocRISCV(hr.Type), backend.ErrUnsupportedReloc)
		}
	}
	return 0, fmt.Errorf("riscv64: %s+%#x: no HI20 relocation paired with this LO12 at %#x",
		s.Chunk, r.Offset, hiAddr)
}

// Field masks: the bits an immediate occupies, leaving opcode, funct3, rd,
// rs1, and rs2 alone. B-type and S-type share one layout — the same four
// bit ranges hold a different scramble of the immediate in each — and J-type
// shares U-type's, both occupying every bit above the low 12.
const (
	uMask = 0xFFFFF000
	iMask = 0xFFF00000
	sMask = 0xFE000F80
	bMask = 0xFE000F80
	jMask = 0xFFFFF000
)

// splitHiLo divides a 32-bit-range value into the 20-bit high part a
// LUI or AUIPC carries and the 12-bit signed low part the following
// instruction adds, the same synthesis every RISC-V assembler uses to build
// an arbitrary 32-bit immediate from the two: round to the nearest multiple
// of 4096 whose low 12 bits, sign-extended, still add up to the original
// value.
func splitHiLo(value int64) (hi20, lo12 int32) {
	hi20 = int32((value + 0x800) >> 12)
	lo12 = int32(value - int64(hi20)<<12)
	return hi20, lo12
}

// uField places a 20-bit value at a U-type instruction's imm[31:12].
func uField(hi20 int32) uint32 { return uint32(hi20) << 12 }

// iField places a signed 12-bit value at an I-type instruction's imm[11:0].
func iField(lo12 int32) uint32 { return (uint32(lo12) & 0xFFF) << 20 }

// sField places a signed 12-bit value across an S-type instruction's split
// imm[11:5]/imm[4:0].
func sField(lo12 int32) uint32 {
	v := uint32(lo12) & 0xFFF
	return (v>>5)<<25 | (v&0x1F)<<7
}

// bField places a signed, even, 13-bit branch displacement across a B-type
// instruction's imm[12|10:5|4:1|11].
func bField(v int64) uint32 {
	u := uint32(v)
	return (u>>12&1)<<31 | (u>>5&0x3F)<<25 | (u>>1&0xF)<<8 | (u>>11&1)<<7
}

// jField places a signed, even, 21-bit jump displacement across a J-type
// instruction's imm[20|10:1|11|19:12].
func jField(v int64) uint32 {
	u := uint32(v)
	return (u>>20&1)<<31 | (u>>1&0x3FF)<<21 | (u>>11&1)<<20 | (u>>12&0xFF)<<12
}

// tpOff converts an address in the TLS block to an offset from the thread
// pointer, failing when there is no TLS block to measure from.
func tpOff(s *backend.Site, sym uint64) (int64, error) {
	if s.Reqs.TlsSize == 0 {
		return 0, fmt.Errorf("riscv64: %s: thread-local reference in an output with no TLS block",
			s.Chunk)
	}
	return Backend{}.TpOff(s.Reqs.TlsAddr, s.Reqs.TlsSize, s.Reqs.TlsAlign, sym), nil
}
