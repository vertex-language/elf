package i386

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
	typ := elf.RelocI386(r.Type)
	if typ == elf.R_386_NONE {
		return nil
	}

	off := r.Offset
	p := s.P(off)
	a := r.Addend

	// sym (S) is fetched lazily, one case at a time, rather than once up
	// front: GOT32 reaches its value through the symbol's GOT slot, and
	// PLT32 through its PLT entry when it has one, and neither needs S
	// itself, which SymAddr refuses to supply for an undefined symbol
	// pursuing either kind of indirection precisely so that it need not be
	// defined at all.
	sym := func() (uint64, error) { return s.SymAddr(off, r) }

	switch typ {
	case elf.R_386_32:
		v, err := sym()
		if err != nil {
			return err
		}
		return s.PutU32(off, uint32(int64(v)+a))

	case elf.R_386_16:
		v, err := sym()
		if err != nil {
			return err
		}
		vv := int64(v) + a
		if err := s.CheckUnsigned(off, r, uint64(vv), 16); err != nil {
			return err
		}
		return s.PutU16(off, uint16(vv))

	case elf.R_386_8:
		v, err := sym()
		if err != nil {
			return err
		}
		vv := int64(v) + a
		if err := s.CheckUnsigned(off, r, uint64(vv), 8); err != nil {
			return err
		}
		return s.PutU8(off, uint8(vv))

	case elf.R_386_PC32:
		v, err := sym()
		if err != nil {
			return err
		}
		return s.PutU32(off, uint32(int64(v)+a-int64(p)))

	case elf.R_386_PC16:
		v, err := sym()
		if err != nil {
			return err
		}
		vv := int64(v) + a - int64(p)
		if err := s.CheckSigned(off, r, vv, 16); err != nil {
			return err
		}
		return s.PutU16(off, uint16(int16(vv)))

	case elf.R_386_PC8:
		v, err := sym()
		if err != nil {
			return err
		}
		vv := int64(v) + a - int64(p)
		if err := s.CheckSigned(off, r, vv, 8); err != nil {
			return err
		}
		return s.PutU8(off, uint8(int8(vv)))

	case elf.R_386_PLT32:
		// L + A - P, where L is the PLT entry when there is one. When the
		// target is defined locally there is none, and the psABI permits
		// reducing the branch to a direct PC-relative call.
		var target uint64
		if r.Sym != nil && r.Sym.PltIndex != image.NoIndex {
			t, err := s.Reqs.PltEntryAddr(r.Sym)
			if err != nil {
				return err
			}
			target = t
		} else {
			v, err := sym()
			if err != nil {
				return err
			}
			target = v
		}
		return s.PutU32(off, uint32(int64(target)+a-int64(p)))

	case elf.R_386_GOT32, elf.R_386_GOT32X:
		g, err := gotOffset(s, r)
		if err != nil {
			return err
		}
		return s.PutU32(off, uint32(int64(g)+a))

	case elf.R_386_GOTOFF:
		v, err := sym()
		if err != nil {
			return err
		}
		return s.PutU32(off, uint32(int64(v)+a-int64(s.Reqs.GotAddr())))

	case elf.R_386_GOTPC:
		return s.PutU32(off, uint32(int64(s.Reqs.GotAddr())+a-int64(p)))

	case elf.R_386_SIZE32:
		v := int64(symSize(r)) + a
		if err := s.CheckUnsigned(off, r, uint64(v), 32); err != nil {
			return err
		}
		return s.PutU32(off, uint32(v))

	case elf.R_386_TLS_IE:
		// GNU model initial-exec, non-PIC: the field is the GOT slot's
		// absolute address, loaded directly with no base register.
		addr, err := s.Reqs.GotSlotAddr(r.Sym)
		if err != nil {
			return fmt.Errorf("i386: %s+%#x: %w", s.Chunk, off, err)
		}
		return s.PutU32(off, uint32(int64(addr)+a))

	case elf.R_386_TLS_GOTIE:
		// GNU model initial-exec, PIC: the field is the slot's offset from
		// the GOT base %ebx holds, the same shape as an ordinary GOT32.
		g, err := gotOffset(s, r)
		if err != nil {
			return err
		}
		return s.PutU32(off, uint32(int64(g)+a))

	case elf.R_386_TLS_LE:
		// GNU model local-exec: the field already holds whatever the
		// instruction that uses it expects — an immediate a leal or movl
		// adds, or a %gs-relative displacement — because it is the same
		// negative variant-II offset either way. See TpOff and the package
		// doc for the sign convention this depends on.
		v, err := sym()
		if err != nil {
			return err
		}
		off2, err := tpOff(s, v)
		if err != nil {
			return err
		}
		return s.PutU32(off, uint32(off2+a))
	}

	return fmt.Errorf("i386: %s+%#x: %v: %w", s.Chunk, off, typ,
		backend.ErrUnsupportedReloc)
}

// tpOff converts an address in the TLS block to an offset from the thread
// pointer, failing when there is no TLS block to measure from.
func tpOff(s *backend.Site, symAddr uint64) (int64, error) {
	if s.Reqs.TlsSize == 0 {
		return 0, fmt.Errorf("i386: %s: thread-local reference in an output with no TLS block", s.Chunk)
	}
	return Backend{}.TpOff(s.Reqs.TlsAddr, s.Reqs.TlsSize, s.Reqs.TlsAlign, symAddr), nil
}

// gotOffset is G: the symbol's slot measured from the table's base.
func gotOffset(s *backend.Site, r image.Reloc) (uint64, error) {
	addr, err := s.Reqs.GotSlotAddr(r.Sym)
	if err != nil {
		return 0, fmt.Errorf("i386: %s: %w", s.Chunk, err)
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
