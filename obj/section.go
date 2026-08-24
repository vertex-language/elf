package obj

import (
	"fmt"
	"io"

	"github.com/vertex-language/elf"
	"github.com/vertex-language/elf/internal/binio"
	"github.com/vertex-language/elf/internal/format"
)

// Section is one entry of a parsed object's section header table.
//
// A Section is immutable. It describes where its contents live but does not
// hold them; see Data and Open.
type Section struct {
	Name      string
	Type      elf.SHType
	Flags     uint64
	Addr      uint64
	Offset    uint64
	Size      uint64
	Link      uint32
	Info      uint32
	Addralign uint64
	Entsize   uint64

	// Index is this section's position in the section header table, which is
	// the index other structures use to refer to it.
	Index uint32

	file    *File
	nameOff uint32
}

// File returns the object this section belongs to.
func (s *Section) File() *File { return s.file }

// Alloc reports whether the section occupies memory at run time.
func (s *Section) Alloc() bool { return s.Flags&elf.SHF_ALLOC != 0 }

// Writable reports whether the section is writable at run time.
func (s *Section) Writable() bool { return s.Flags&elf.SHF_WRITE != 0 }

// Executable reports whether the section holds executable instructions.
func (s *Section) Executable() bool { return s.Flags&elf.SHF_EXECINSTR != 0 }

// TLS reports whether the section holds thread-local storage.
func (s *Section) TLS() bool { return s.Flags&elf.SHF_TLS != 0 }

// Compressed reports whether the section's contents are prefixed by a
// compression header.
func (s *Section) Compressed() bool { return s.Flags&elf.SHF_COMPRESSED != 0 }

// Data returns the section's contents exactly as they sit in the file.
//
// Data allocates a fresh slice on every call and does no decompression: a
// section flagged SHF_COMPRESSED yields its compression header followed by the
// compressed bytes. Decompression is the linker's job, because only the linker
// knows whether it wants the section at all.
//
// Callers that read the same section repeatedly should hold onto the result.
// The object reader deliberately does not cache section contents — the linker
// keeps the bytes it needs, and caching here would double peak memory on
// exactly the largest inputs.
//
// SHT_NOBITS sections occupy no file space and return an empty slice.
func (s *Section) Data() ([]byte, error) {
	if s.Type == elf.SHT_NOBITS {
		return []byte{}, nil
	}
	ext, err := s.extent()
	if err != nil {
		return nil, err
	}
	return ext.Data()
}

// Open returns a reader over the section's contents without loading them.
// SHT_NOBITS sections yield an immediately-EOF reader.
func (s *Section) Open() (io.ReadSeeker, error) {
	if s.Type == elf.SHT_NOBITS {
		return binio.EmptyExtent().Open(), nil
	}
	ext, err := s.extent()
	if err != nil {
		return nil, err
	}
	return ext.Open(), nil
}

func (s *Section) extent() (binio.Extent, error) {
	ext, err := s.file.bf.At(int64(s.Offset), int64(s.Size))
	if err != nil {
		return binio.Extent{}, fmt.Errorf("obj: section %q: %w", s.Name, err)
	}
	return ext, nil
}

// CompressionHeader decodes the header prefixing an SHF_COMPRESSED section.
// It returns nil, nil for a section that is not compressed.
func (s *Section) CompressionHeader() (*format.Chdr, error) {
	if !s.Compressed() {
		return nil, nil
	}
	want := int64(format.ChdrSize(s.file.Class))
	if s.Size < uint64(want) {
		return nil, fmt.Errorf("obj: section %q is %d bytes, too small for a %d-byte compression header",
			s.Name, s.Size, want)
	}
	ext, err := s.file.bf.At(int64(s.Offset), want)
	if err != nil {
		return nil, fmt.Errorf("obj: section %q compression header: %w", s.Name, err)
	}
	c, err := ext.Cursor(s.file.bo)
	if err != nil {
		return nil, err
	}
	var ch format.Chdr
	ch.Decode(c, s.file.Class)
	if err := c.Err(); err != nil {
		return nil, fmt.Errorf("obj: section %q compression header: %w", s.Name, err)
	}
	return &ch, nil
}

// entryCount reports how many fixed-size records of the given stride the
// section holds, rejecting a size that is not a whole multiple.
func (s *Section) entryCount(stride int, what string) (int, error) {
	if stride <= 0 {
		return 0, fmt.Errorf("obj: section %q: non-positive %s stride %d", s.Name, what, stride)
	}
	if s.Entsize != 0 && s.Entsize != uint64(stride) {
		return 0, fmt.Errorf("obj: section %q sh_entsize %d does not match the %d-byte %s of this class",
			s.Name, s.Entsize, stride, what)
	}
	if s.Size%uint64(stride) != 0 {
		return 0, fmt.Errorf("obj: section %q size %d is not a multiple of %d",
			s.Name, s.Size, stride)
	}
	return int(s.Size / uint64(stride)), nil
}

// cursor reads the section and returns a cursor over its contents.
func (s *Section) cursor() (*binio.Cursor, error) {
	data, err := s.Data()
	if err != nil {
		return nil, fmt.Errorf("obj: reading %q: %w", s.Name, err)
	}
	return binio.NewCursorAt(data, int64(s.Offset), s.file.bo), nil
}