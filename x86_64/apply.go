package x86_64

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
// L the PLT entry's address, Z the symbol's size.
func (b Backend) Apply(s *backend.Site, r image.Reloc) error {
	typ := elf.RelocX86_64(r.Type)
	if typ == elf.R_X86_64_NONE {
		return nil
	}

	off := r.Offset
	p := s.P(off)
	a := r.Addend

	sym, err := s.SymAddr(off, r)
	if err != nil {
		return err
	}

	switch typ {
	case elf.R_X86_64_64:
		return s.PutU64(off, uint64(int64(sym)+a))

	case elf.R_X86_64_32:
		// The value must survive a round trip through 32 bits unsigned. The
		// psABI requires the check rather than a silent truncation, because
		// a program that quietly addresses the wrong four gigabytes is worse
		// than one that fails to link.
		v := uint64(int64(sym) + a)
		if err := s.CheckUnsigned(off, r, v, 32); err != nil {
			return err
		}
		return s.PutU32(off, uint32(v))

	case elf.R_X86_64_32S:
		v := int64(sym) + a
		if err := s.CheckSigned(off, r, v, 32); err != nil {
			return err
		}
		return s.PutU32(off, uint32(int32(v)))

	case elf.R_X86_64_16:
		v := int64(sym) + a
		if err := s.CheckUnsigned(off, r, uint64(v), 16); err != nil {
			return err
		}
		return s.PutU16(off, uint16(v))

	case elf.R_X86_64_8:
		v := int64(sym) + a
		if err := s.CheckUnsigned(off, r, uint64(v), 8); err != nil {
			return err
		}
		return s.PutU8(off, uint8(v))

	case elf.R_X86_64_PC64:
		return s.PutU64(off, uint64(int64(sym)+a-int64(p)))

	case elf.R_X86_64_PC32:
		return putPC32(s, off, r, int64(sym)+a-int64(p))

	case elf.R_X86_64_PC16:
		v := int64(sym) + a - int64(p)
		if err := s.CheckSigned(off, r, v, 16); err != nil {
			return err
		}
		return s.PutU16(off, uint16(int16(v)))

	case elf.R_X86_64_PC8:
		v := int64(sym) + a - int64(p)
		if err := s.CheckSigned(off, r, v, 8); err != nil {
			return err
		}
		return s.PutU8(off, uint8(int8(v)))

	case elf.R_X86_64_PLT32, elf.R_X86_64_PLT32_BND:
		// L + A - P, where L is the PLT entry when there is one. When the
		// target is defined locally there is none, and the psABI permits
		// reducing the branch to a direct PC-relative call.
		target := sym
		if r.Sym != nil && r.Sym.PltIndex != image.NoIndex {
			target, err = s.Reqs.PltEntryAddr(r.Sym)
			if err != nil {
				return err
			}
		}
		return putPC32(s, off, r, int64(target)+a-int64(p))

	case elf.R_X86_64_GOTPCREL, elf.R_X86_64_GOTPCREL64,
		elf.R_X86_64_GOTPCRELX, elf.R_X86_64_REX_GOTPCRELX,
		elf.R_X86_64_CODE_4_GOTPCRELX, elf.R_X86_64_CODE_5_GOTPCRELX,
		elf.R_X86_64_CODE_6_GOTPCRELX:
		return applyGotPCRel(s, r, off, p, a, sym, typ)

	case elf.R_X86_64_GOT32:
		v, err := gotOffset(s, r)
		if err != nil {
			return err
		}
		return s.PutU32(off, uint32(int64(v)+a))

	case elf.R_X86_64_GOT64:
		v, err := gotOffset(s, r)
		if err != nil {
			return err
		}
		return s.PutU64(off, uint64(int64(v)+a))

	case elf.R_X86_64_GOTOFF64:
		return s.PutU64(off, uint64(int64(sym)+a-int64(s.Reqs.GotAddr())))

	case elf.R_X86_64_GOTPC32:
		return putPC32(s, off, r, int64(s.Reqs.GotAddr())+a-int64(p))

	case elf.R_X86_64_GOTPC64:
		return s.PutU64(off, uint64(int64(s.Reqs.GotAddr())+a-int64(p)))

	case elf.R_X86_64_SIZE32:
		v := int64(symSize(r)) + a
		if err := s.CheckUnsigned(off, r, uint64(v), 32); err != nil {
			return err
		}
		return s.PutU32(off, uint32(v))

	case elf.R_X86_64_SIZE64:
		return s.PutU64(off, uint64(int64(symSize(r))+a))

	case elf.R_X86_64_TPOFF32:
		// Local-exec. x86 uses TLS variant II: the static block sits below
		// the thread pointer, so an offset from it is negative.
		v, err := tpOff(s, sym)
		if err != nil {
			return err
		}
		return putPC32(s, off, r, v+a)

	case elf.R_X86_64_TPOFF64:
		v, err := tpOff(s, sym)
		if err != nil {
			return err
		}
		return s.PutU64(off, uint64(v+a))

	case elf.R_X86_64_DTPOFF32:
		return s.PutU32(off, uint32(int64(sym-s.Reqs.TlsAddr)+a))

	case elf.R_X86_64_DTPOFF64:
		return s.PutU64(off, uint64(int64(sym-s.Reqs.TlsAddr)+a))
	}

	return fmt.Errorf("x86_64: %s+%#x: %v: %w", s.Chunk, off, typ,
		backend.ErrUnsupportedReloc)
}

// putPC32 writes a 32-bit displacement, checking that it fits.
//
// Every 32-bit PC-relative form on this architecture has the same ±2 GiB
// range, and overflow is the failure real programs hit — usually from code
// reaching data across a large output, not from code reaching code.
func putPC32(s *backend.Site, off uint64, r image.Reloc, v int64) error {
	if err := s.CheckSigned(off, r, v, 32); err != nil {
		return err
	}
	return s.PutU32(off, uint32(int32(v)))
}

// applyGotPCRel handles the GOT-load family, relaxing it to a direct
// address computation when Scan decided the slot was unnecessary.
func applyGotPCRel(s *backend.Site, r image.Reloc, off, p uint64, a int64,
	sym uint64, typ elf.RelocX86_64) error {

	if canRelaxGot(s.Reqs, r) {
		if err := relaxToLea(s, off); err != nil {
			return err
		}
		// The lea computes the symbol's own address rather than its slot's,
		// so the addend that pointed at the slot is not part of the result.
		// The instruction is the same length, so P is unchanged.
		return putPC32(s, off, r, int64(sym)+a+4-int64(p))
	}

	slot, err := s.Reqs.GotSlotAddr(r.Sym)
	if err != nil {
		return fmt.Errorf("x86_64: %s+%#x: %w", s.Chunk, off, err)
	}
	if typ == elf.R_X86_64_GOTPCREL64 {
		return s.PutU64(off, uint64(int64(slot)+a-int64(p)))
	}
	return putPC32(s, off, r, int64(slot)+a-int64(p))
}

// relaxToLea rewrites a GOT load into a direct address computation.
//
// The opcode byte sits at the relocation offset minus two whatever prefix the
// instruction carries — a REX or REX2 byte precedes it and stays valid
// untouched, since lea takes the same operand encoding as mov. Only the
// register-load form is rewritten here; the indirect call and jump forms need
// a nop inserted ahead of them and are left going through the GOT.
func relaxToLea(s *backend.Site, off uint64) error {
	if off < 2 {
		return fmt.Errorf("x86_64: %s: GOT load at %#x has no room for an opcode",
			s.Chunk, off)
	}
	op, err := s.U8(off - 2)
	if err != nil {
		return err
	}
	const (
		opMov = 0x8b // mov r, r/m
		opLea = 0x8d // lea r, m
	)
	if op != opMov {
		// Not a form this rewrite understands. Scan allocated no slot on the
		// assumption that it was, so refusing here would leave the
		// relocation with nothing to point at.
		return fmt.Errorf("x86_64: %s+%#x: GOT load has opcode %#x, expected mov",
			s.Chunk, off, op)
	}
	return s.PutU8(off-2, opLea)
}

// gotOffset is G: the symbol's slot measured from the table's base.
func gotOffset(s *backend.Site, r image.Reloc) (uint64, error) {
	addr, err := s.Reqs.GotSlotAddr(r.Sym)
	if err != nil {
		return 0, err
	}
	return addr - s.Reqs.GotAddr(), nil
}

// symSize is Z.
func symSize(r image.Reloc) uint64 {
	if r.Sym == nil {
		return 0
	}
	return r.Sym.Size
}

// tpOff converts an address in the TLS block to an offset from the thread
// pointer.
//
// Variant II places the static block immediately below the thread pointer, so
// the offset is the symbol's position within the block minus the block's
// aligned size, and is therefore negative.
func tpOff(s *backend.Site, sym uint64) (int64, error) {
	if s.Reqs.TlsSize == 0 {
		return 0, fmt.Errorf("x86_64: %s: thread-local reference in an output with no TLS block",
			s.Chunk)
	}
	align := s.Reqs.TlsAlign
	if align == 0 {
		align = 1
	}
	size := (s.Reqs.TlsSize + align - 1) &^ (align - 1)
	return int64(sym) - int64(s.Reqs.TlsAddr) - int64(size), nil
}