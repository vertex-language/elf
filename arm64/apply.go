package arm64

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
	typ := elf.RelocAArch64(r.Type)
	if typ == elf.R_AARCH64_NONE {
		return nil
	}

	off := r.Offset
	p := s.P(off)
	a := r.Addend

	// A CALL26/JUMP26 to a symbol with no definition in this link is not an
	// error: it is the ordinary shape of a call into a shared library, and
	// PltEntryAddr below supplies the address SymAddr has none for. Every
	// other relocation type still requires a real value.
	var sym uint64
	var err error
	if r.Sym == nil || r.Sym.PltIndex == image.NoIndex {
		sym, err = s.SymAddr(off, r)
		if err != nil {
			return err
		}
	}

	switch typ {
	case elf.R_AARCH64_ABS64:
		return s.PutU64(off, uint64(int64(sym)+a))

	case elf.R_AARCH64_ABS32:
		v := int64(sym) + a
		if err := s.CheckUnsigned(off, r, uint64(v), 32); err != nil {
			return err
		}
		return s.PutU32(off, uint32(v))

	case elf.R_AARCH64_ABS16:
		v := int64(sym) + a
		if err := s.CheckUnsigned(off, r, uint64(v), 16); err != nil {
			return err
		}
		return s.PutU16(off, uint16(v))

	case elf.R_AARCH64_PREL64:
		return s.PutU64(off, uint64(int64(sym)+a-int64(p)))

	case elf.R_AARCH64_PREL32:
		v := int64(sym) + a - int64(p)
		if err := s.CheckSigned(off, r, v, 32); err != nil {
			return err
		}
		return s.PutU32(off, uint32(int32(v)))

	case elf.R_AARCH64_PREL16:
		v := int64(sym) + a - int64(p)
		if err := s.CheckSigned(off, r, v, 16); err != nil {
			return err
		}
		return s.PutU16(off, uint16(int16(v)))

	case elf.R_AARCH64_ADR_PREL_LO21:
		v := int64(sym) + a - int64(p)
		if err := s.CheckSigned(off, r, v, 21); err != nil {
			return err
		}
		return writeAdr(s, off, int32(v))

	case elf.R_AARCH64_ADR_PREL_PG_HI21, elf.R_AARCH64_ADR_PREL_PG_HI21_NC:
		pages := int64(page(uint64(int64(sym)+a))) - int64(page(p))
		v := pages >> 12
		if typ == elf.R_AARCH64_ADR_PREL_PG_HI21 {
			if err := s.CheckSigned(off, r, v, 21); err != nil {
				return err
			}
		}
		return writeAdrp(s, off, int32(v))

	case elf.R_AARCH64_ADD_ABS_LO12_NC:
		return writeLo12(s, off, uint64(int64(sym)+a), 0)

	case elf.R_AARCH64_LDST8_ABS_LO12_NC:
		return writeLo12(s, off, uint64(int64(sym)+a), 0)
	case elf.R_AARCH64_LDST16_ABS_LO12_NC:
		return writeLo12(s, off, uint64(int64(sym)+a), 1)
	case elf.R_AARCH64_LDST32_ABS_LO12_NC:
		return writeLo12(s, off, uint64(int64(sym)+a), 2)
	case elf.R_AARCH64_LDST64_ABS_LO12_NC:
		return writeLo12(s, off, uint64(int64(sym)+a), 3)
	case elf.R_AARCH64_LDST128_ABS_LO12_NC:
		return writeLo12(s, off, uint64(int64(sym)+a), 4)

	case elf.R_AARCH64_TSTBR14:
		v := (int64(sym) + a - int64(p)) >> 2
		if err := s.CheckSigned(off, r, v, 14); err != nil {
			return err
		}
		return s.Mask32(off, 0x0007FFE0, uint32(v)<<5)

	case elf.R_AARCH64_CONDBR19:
		v := (int64(sym) + a - int64(p)) >> 2
		if err := s.CheckSigned(off, r, v, 19); err != nil {
			return err
		}
		return s.Mask32(off, 0x00FFFFE0, uint32(v)<<5)

	case elf.R_AARCH64_CALL26, elf.R_AARCH64_JUMP26:
		target := sym
		if r.Sym != nil && r.Sym.PltIndex != image.NoIndex {
			target, err = s.Reqs.PltEntryAddr(r.Sym)
			if err != nil {
				return err
			}
		}
		v := (int64(target) + a - int64(p)) >> 2
		if err := s.CheckSigned(off, r, v, 26); err != nil {
			return err
		}
		return s.Mask32(off, 0x03FFFFFF, uint32(v)&0x03FFFFFF)

	case elf.R_AARCH64_ADR_GOT_PAGE:
		slot, err := s.Reqs.GotSlotAddr(r.Sym)
		if err != nil {
			return fmt.Errorf("arm64: %s+%#x: %w", s.Chunk, off, err)
		}
		pages := int64(page(slot)) - int64(page(p))
		return writeAdrp(s, off, int32(pages>>12))

	case elf.R_AARCH64_LD64_GOT_LO12_NC:
		slot, err := s.Reqs.GotSlotAddr(r.Sym)
		if err != nil {
			return fmt.Errorf("arm64: %s+%#x: %w", s.Chunk, off, err)
		}
		return writeLo12(s, off, slot, 3)

	case elf.R_AARCH64_GOT_LD_PREL19:
		slot, err := s.Reqs.GotSlotAddr(r.Sym)
		if err != nil {
			return fmt.Errorf("arm64: %s+%#x: %w", s.Chunk, off, err)
		}
		v := (int64(slot) - int64(p)) >> 2
		if err := s.CheckSigned(off, r, v, 19); err != nil {
			return err
		}
		return s.Mask32(off, 0x00FFFFE0, uint32(v)<<5)

	case elf.R_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21:
		slot, err := s.Reqs.GotSlotAddr(r.Sym)
		if err != nil {
			return fmt.Errorf("arm64: %s+%#x: %w", s.Chunk, off, err)
		}
		pages := int64(page(slot)) - int64(page(p))
		return writeAdrp(s, off, int32(pages>>12))

	case elf.R_AARCH64_TLSIE_LD64_GOTTPREL_LO12_NC:
		slot, err := s.Reqs.GotSlotAddr(r.Sym)
		if err != nil {
			return fmt.Errorf("arm64: %s+%#x: %w", s.Chunk, off, err)
		}
		return writeLo12(s, off, slot, 3)

	case elf.R_AARCH64_TLSLE_ADD_TPREL_HI12:
		v, err := tpOff(s, sym)
		if err != nil {
			return err
		}
		return writeLo12(s, off, uint64(v+a)>>12, 0)

	case elf.R_AARCH64_TLSLE_ADD_TPREL_LO12, elf.R_AARCH64_TLSLE_ADD_TPREL_LO12_NC:
		v, err := tpOff(s, sym)
		if err != nil {
			return err
		}
		return writeLo12(s, off, uint64(v+a), 0)
	}

	return fmt.Errorf("arm64: %s+%#x: %v: %w", s.Chunk, off, typ,
		backend.ErrUnsupportedReloc)
}

// page rounds an address down to its containing 4KiB page, the granularity
// ADRP addresses.
func page(addr uint64) uint64 { return addr &^ 0xFFF }

// writeAdr encodes a byte-precise ADR's split 21-bit immediate into the
// instruction word at off, leaving everything but the immediate and Rd
// unmodified — but ADR's own Rd is untouched too, since only the immediate
// changes between a relocated instruction and the same one before linking.
func writeAdr(s *backend.Site, off uint64, imm int32) error {
	lo := uint32(imm) & 0x3
	hi := (uint32(imm) >> 2) & 0x7FFFF
	return s.Mask32(off, 0x60FFFFE0, (lo<<29)|(hi<<5))
}

// writeAdrp encodes ADRP's split 21-bit page immediate, the same field
// layout as ADR at a different opcode.
func writeAdrp(s *backend.Site, off uint64, imm int32) error {
	lo := uint32(imm) & 0x3
	hi := (uint32(imm) >> 2) & 0x7FFFF
	return s.Mask32(off, 0x60FFFFE0, (lo<<29)|(hi<<5))
}

// writeLo12 writes a twelve-bit page offset into an ADD or LDR/STR
// immediate field, scaling it down by the access width shift: 0 for ADD and
// a byte access, 1/2/3/4 for a 2/4/8/16-byte load or store, since those
// instructions encode the offset pre-divided by their own access size.
func writeLo12(s *backend.Site, off uint64, addr uint64, shift uint) error {
	imm12 := uint32((addr&0xFFF)>>shift) & 0xFFF
	return s.Mask32(off, 0x003FFC00, imm12<<10)
}

// tpOff converts an address in the TLS block to an offset from the thread
// pointer, failing when there is no TLS block to measure from.
func tpOff(s *backend.Site, sym uint64) (int64, error) {
	if s.Reqs.TlsSize == 0 {
		return 0, fmt.Errorf("arm64: %s: thread-local reference in an output with no TLS block",
			s.Chunk)
	}
	return Backend{}.TpOff(s.Reqs.TlsAddr, s.Reqs.TlsSize, s.Reqs.TlsAlign, sym), nil
}
