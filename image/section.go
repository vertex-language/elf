package image

import (
	"strings"

	"github.com/vertex-language/elf"
)

// SecFlags is sh_flags. It is a distinct type from SegFlags because the two
// describe the same permissions in different, non-interchangeable bit spaces:
// SHF_EXECINSTR is 0x4 and PF_X is 0x1. A uint32 carrying either would let one
// be assigned to the other, and the result — an executable, non-readable
// segment — is the kind of bug that only shows up at exec time.
type SecFlags uint64

func (f SecFlags) Alloc() bool      { return f&elf.SHF_ALLOC != 0 }
func (f SecFlags) Write() bool      { return f&elf.SHF_WRITE != 0 }
func (f SecFlags) Exec() bool       { return f&elf.SHF_EXECINSTR != 0 }
func (f SecFlags) TLS() bool        { return f&elf.SHF_TLS != 0 }
func (f SecFlags) Merge() bool      { return f&elf.SHF_MERGE != 0 }
func (f SecFlags) Strings() bool    { return f&elf.SHF_STRINGS != 0 }
func (f SecFlags) Group() bool      { return f&elf.SHF_GROUP != 0 }
func (f SecFlags) Compressed() bool { return f&elf.SHF_COMPRESSED != 0 }

// Mergeable reports whether the section's contents may be split into fragments
// and deduplicated. SHF_MERGE alone means fixed-size entries of sh_entsize;
// with SHF_STRINGS it means NUL-terminated strings.
func (f SecFlags) Mergeable() bool { return f.Merge() }

// Seg maps section permissions onto segment permissions. Everything allocated
// is readable; the other two bits carry across.
func (f SecFlags) Seg() SegFlags {
	s := SegFlags(elf.PF_R)
	if f.Write() {
		s |= elf.PF_W
	}
	if f.Exec() {
		s |= elf.PF_X
	}
	return s
}

func (f SecFlags) String() string {
	var b strings.Builder
	for _, bit := range []struct {
		mask SecFlags
		name string
	}{
		{elf.SHF_WRITE, "W"}, {elf.SHF_ALLOC, "A"}, {elf.SHF_EXECINSTR, "X"},
		{elf.SHF_MERGE, "M"}, {elf.SHF_STRINGS, "S"}, {elf.SHF_INFO_LINK, "I"},
		{elf.SHF_LINK_ORDER, "L"}, {elf.SHF_GROUP, "G"}, {elf.SHF_TLS, "T"},
		{elf.SHF_COMPRESSED, "C"},
	} {
		if f&bit.mask != 0 {
			b.WriteString(bit.name)
		}
	}
	if b.Len() == 0 {
		return "-"
	}
	return b.String()
}

// SegFlags is p_flags.
type SegFlags uint32

func (f SegFlags) Read() bool  { return f&elf.PF_R != 0 }
func (f SegFlags) Write() bool { return f&elf.PF_W != 0 }
func (f SegFlags) Exec() bool  { return f&elf.PF_X != 0 }

func (f SegFlags) String() string {
	b := []byte("---")
	if f.Read() {
		b[0] = 'R'
	}
	if f.Write() {
		b[1] = 'W'
	}
	if f.Exec() {
		b[2] = 'E'
	}
	return string(b)
}

// secKey identifies an output section. See Image.Section for why all three
// fields are part of the identity.
type secKey struct {
	name  string
	typ   elf.SHType
	flags SecFlags
}

// OutputSection is one section of the linked file.
//
// It holds the chunks placed in it, not their bytes: contents are copied into
// the Image's buffer once, at commit, from each chunk's own source.
type OutputSection struct {
	Name  string
	Type  elf.SHType
	Flags SecFlags

	// Addr, Off, and Size are assigned by layout and reassigned on every
	// iteration of the relax fixpoint. Nothing may cache them across an
	// iteration.
	Addr uint64
	Off  uint64
	Size uint64

	// Align is the maximum alignment of the chunks placed here, never less
	// than 1.
	Align uint64

	// Entsize is sh_entsize, for sections of fixed-size records.
	Entsize uint64

	// Link and Info are the raw header fields. LinkTo and InfoTo take
	// precedence when set, so that a reference to another section survives
	// the reordering that assigns indexes.
	Link   uint32
	Info   uint32
	LinkTo *OutputSection
	InfoTo *OutputSection

	// Index is this section's position in the output section header table,
	// assigned by emit. Zero until then, which is the null section's index,
	// so nothing may read it early.
	Index uint32

	// Rank orders sections within the output. Assigned by link/order.go from
	// its name-pattern table; equal ranks keep input order.
	Rank int

	// Seg is the segment covering this section, or nil for a non-allocated
	// section.
	Seg *Segment

	// Chunks are the contributions placed here, in final order.
	Chunks []*Chunk
}

// HasBits reports whether the section occupies file space. SHT_NOBITS sections
// have a size and an address but no contents.
func (s *OutputSection) HasBits() bool { return s.Type != elf.SHT_NOBITS }

// Alloc reports whether the section occupies memory at run time.
func (s *OutputSection) Alloc() bool { return s.Flags.Alloc() }

// TLS reports whether the section holds thread-local storage.
func (s *OutputSection) TLS() bool { return s.Flags.TLS() }

// End returns the address one past the section's last byte.
func (s *OutputSection) End() uint64 { return s.Addr + s.Size }

// Bound returns the address of one end of the section.
func (s *OutputSection) Bound(at Anchor) uint64 {
	if at == AnchorEnd {
		return s.End()
	}
	return s.Addr
}

// Add places a chunk in this section and raises the section's alignment to
// cover it. Offsets are assigned later, by layout.
//
// It also adopts the chunk's Entsize when the chunk has one and the section
// does not yet: sh_entsize is a fact about the section, but every chunk that
// is going to define it — a synthetic .symtab or .dynsym, an input .rela.text
// — carries it on itself, and a section left at zero produces a symbol or
// relocation table that tools such as readelf refuse to parse.
func (s *OutputSection) Add(ch *Chunk) {
	ch.Out = s
	if ch.Align > s.Align {
		s.Align = ch.Align
	}
	if ch.Entsize != 0 && s.Entsize == 0 {
		s.Entsize = ch.Entsize
	}
	s.Chunks = append(s.Chunks, ch)
}

func (s *OutputSection) String() string { return s.Name }

// Segment is one program header.
//
// Flags is SegFlags, not SecFlags: see the comment on SecFlags for why the two
// are separate types.
type Segment struct {
	Type  elf.ProgType
	Flags SegFlags

	Off    uint64
	Vaddr  uint64
	Paddr  uint64
	Filesz uint64
	Memsz  uint64
	Align  uint64

	// Sections are the output sections this segment covers, in address order.
	// PT_PHDR, PT_INTERP, and the GNU segments may cover none.
	Sections []*OutputSection
}

// NewSegment returns a segment of the given type and permissions.
func NewSegment(typ elf.ProgType, flags SegFlags, align uint64) *Segment {
	if align == 0 {
		align = 1
	}
	return &Segment{Type: typ, Flags: flags, Align: align}
}

// Add appends a section to the segment.
func (p *Segment) Add(s *OutputSection) {
	s.Seg = p
	p.Sections = append(p.Sections, s)
}

// Cover recomputes the segment's extent from the sections it holds.
//
// Filesz and Memsz differ whenever the segment ends in SHT_NOBITS: .bss
// occupies memory the file does not contain, which is the entire reason the
// two fields exist. Trailing NOBITS sections therefore extend Memsz only.
func (p *Segment) Cover() {
	if len(p.Sections) == 0 {
		p.Filesz, p.Memsz = 0, 0
		return
	}
	first := p.Sections[0]
	p.Off = first.Off
	p.Vaddr = first.Addr
	p.Paddr = first.Addr

	var fileEnd, memEnd uint64
	for _, s := range p.Sections {
		if end := s.Addr + s.Size; end > memEnd {
			memEnd = end
		}
		if s.HasBits() {
			if end := s.Off + s.Size; end > fileEnd {
				fileEnd = end
			}
		}
	}
	if fileEnd > p.Off {
		p.Filesz = fileEnd - p.Off
	} else {
		p.Filesz = 0
	}
	p.Memsz = memEnd - p.Vaddr
}