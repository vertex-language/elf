package obj

import (
	"fmt"

	"github.com/vertex-language/elf"
	"github.com/vertex-language/elf/internal/binio"
	"github.com/vertex-language/elf/internal/format"
)

// Note is one record from an SHT_NOTE section.
type Note struct {
	Name string
	Type uint32

	// Desc is a copy of the descriptor, safe to retain.
	Desc []byte
}

// Notes decodes the records in an SHT_NOTE section.
//
// Record padding follows the section's sh_addralign rather than a fixed four
// bytes: 64-bit Linux emits eight-byte-aligned notes, and reading them at four
// desynchronises after the first record. An sh_addralign of 0 or 1 is treated
// as 4, which is what the gABI specifies and what such sections in practice
// contain.
func (s *Section) Notes() ([]Note, error) {
	if s.Type != elf.SHT_NOTE {
		return nil, fmt.Errorf("obj: Notes on section %q, which is %v, not SHT_NOTE", s.Name, s.Type)
	}
	data, err := s.Data()
	if err != nil {
		return nil, fmt.Errorf("obj: reading %q: %w", s.Name, err)
	}

	align := 4
	if s.Addralign == 8 {
		align = 8
	}

	c := binio.NewCursorAt(data, int64(s.Offset), s.file.bo)
	var out []Note
	for c.Len() > 0 {
		var nh format.Nhdr
		nh.Decode(c, s.file.Class)
		if err := c.Err(); err != nil {
			return nil, fmt.Errorf("obj: %q: truncated note header: %w", s.Name, err)
		}
		if nh.Namesz > uint32(c.Len()) || nh.Descsz > uint32(c.Len()) {
			return nil, fmt.Errorf("obj: %q: note declares %d-byte name and %d-byte descriptor in %d remaining bytes",
				s.Name, nh.Namesz, nh.Descsz, c.Len())
		}

		name := c.Str(int(nh.Namesz))
		c.Align(align)
		desc := c.Bytes(int(nh.Descsz))
		c.Align(align)
		if err := c.Err(); err != nil {
			return nil, fmt.Errorf("obj: %q: truncated note: %w", s.Name, err)
		}

		out = append(out, Note{
			Name: name,
			Type: nh.Type,
			Desc: append([]byte(nil), desc...),
		})
	}
	return out, nil
}

// StackState reports what the object says about stack executability.
//
// present is false when the object has no .note.GNU-stack section at all,
// which the kernel and most linkers take as a request for an executable stack.
// It is worth distinguishing from an explicit non-executable declaration.
func (f *File) StackState() (present, executable bool) {
	sec := f.Section(".note.GNU-stack")
	if sec == nil {
		return false, false
	}
	return true, sec.Flags&elf.SHF_EXECINSTR != 0
}