package obj

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"

	"github.com/vertex-language/elf"
	"github.com/vertex-language/elf/internal/binio"
	"github.com/vertex-language/elf/internal/format"
)

// File is a parsed relocatable object.
//
// Parsing reads the ELF header, the section header table, and the section name
// string table. Section contents, symbol tables, and relocations are decoded
// on demand.
type File struct {
	Class      elf.Class
	Data       elf.Data
	Type       elf.Type
	Machine    elf.Machine
	OSABI      elf.OSABI
	ABIVersion uint8
	Flags      uint32

	// Sections is the section header table, index 0 (SHT_NULL) included, so
	// that a Section's position in this slice is its ELF section index.
	Sections []*Section

	bf     *binio.File
	bo     binary.ByteOrder
	closer io.Closer

	shstrndx int
	symtab   *Section
	dynsym   *Section

	// syms caches decoded symbol tables by their section. The cache exists
	// for pointer identity, not speed: the linker keys on *Symbol, so two
	// calls asking about the same table must hand back the same objects.
	syms map[*Section][]*Symbol

	// relocsFor maps a section index to the relocation sections targeting it,
	// built once at parse time. Without it, relocating every section is
	// quadratic in the section count.
	relocsFor map[uint32][]*Section
}

// NewFile parses the object in r. r must report its own size; see
// binio.SizeOf.
func NewFile(r io.ReaderAt) (*File, error) {
	bf, err := binio.Open(r)
	if err != nil {
		return nil, err
	}
	return newFile(bf, nil)
}

// Open parses the object in the named file. The caller must Close the result.
func Open(name string) (*File, error) {
	fh, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	bf, err := binio.Open(fh)
	if err != nil {
		fh.Close()
		return nil, err
	}
	f, err := newFile(bf, fh)
	if err != nil {
		fh.Close()
		return nil, err
	}
	return f, nil
}

// Close releases the underlying file, if this File opened one. Closing a File
// built by NewFile is a no-op.
func (f *File) Close() error {
	if f.closer != nil {
		return f.closer.Close()
	}
	return nil
}

func newFile(bf *binio.File, closer io.Closer) (*File, error) {
	head, err := bf.Head(elf.EI_NIDENT)
	if err != nil {
		return nil, err
	}
	id, err := format.DecodeIdent(head)
	if err != nil {
		return nil, err
	}

	f := &File{
		Class:      id.Class,
		Data:       id.Data,
		OSABI:      id.OSABI,
		ABIVersion: id.ABIVersion,
		bf:         bf,
		bo:         id.ByteOrder(),
		closer:     closer,
		syms:       make(map[*Section][]*Symbol),
		relocsFor:  make(map[uint32][]*Section),
	}

	ehExt, err := bf.At(0, int64(format.EhdrSize(f.Class)))
	if err != nil {
		return nil, fmt.Errorf("obj: reading ELF header: %w", err)
	}
	c, err := ehExt.Cursor(f.bo)
	if err != nil {
		return nil, err
	}
	var eh format.Ehdr
	eh.Decode(c)
	if err := c.Err(); err != nil {
		return nil, fmt.Errorf("obj: parsing ELF header: %w", err)
	}

	f.Type = eh.Type
	f.Machine = eh.Machine
	f.Flags = eh.Flags

	if eh.Type != elf.ET_REL {
		return nil, fmt.Errorf("obj: %v: %w", eh.Type, ErrNotRelocatable)
	}

	if err := f.parseSections(&eh); err != nil {
		return nil, err
	}
	return f, nil
}

// parseSections decodes the section header table, resolves section names, and
// builds the symbol-table and relocation indexes.
func (f *File) parseSections(eh *format.Ehdr) error {
	if eh.Shoff == 0 {
		// An ET_REL object with no section header table carries nothing the
		// linker can use, but it is not malformed.
		return nil
	}

	shdrSize := int64(format.ShdrSize(f.Class))
	if eh.Shentsize != 0 && int64(eh.Shentsize) != shdrSize {
		return fmt.Errorf("obj: e_shentsize %d does not match %v (want %d)",
			eh.Shentsize, f.Class, shdrSize)
	}

	first, err := f.readShdr(eh.Shoff)
	if err != nil {
		return err
	}

	// e_shnum of zero is the escape for a table too large for the field: the
	// real count lives in sh_size of section header zero. Likewise
	// e_shstrndx of SHN_XINDEX escapes into that header's sh_link.
	count := uint64(eh.Shnum)
	if eh.Shnum == 0 {
		count = first.Size
	}
	if count == 0 {
		return nil
	}
	shstrndx := uint64(eh.Shstrndx)
	if eh.Shstrndx == elf.SHN_XINDEX_IDX {
		shstrndx = uint64(first.Link)
	}

	// Reject a declared count that cannot physically fit before allocating
	// against it.
	if fit := uint64(f.bf.Size()) / uint64(shdrSize); count > fit {
		return fmt.Errorf("obj: section header count %d exceeds the %d that fit in a %d-byte file",
			count, fit, f.bf.Size())
	}

	f.Sections = make([]*Section, 0, count)
	for i := uint64(0); i < count; i++ {
		raw := first
		if i != 0 {
			raw, err = f.readShdr(eh.Shoff + i*uint64(shdrSize))
			if err != nil {
				return err
			}
		}
		f.Sections = append(f.Sections, &Section{
			Type:      raw.Type,
			Flags:     raw.Flags,
			Addr:      raw.Addr,
			Offset:    raw.Off,
			Size:      raw.Size,
			Link:      raw.Link,
			Info:      raw.Info,
			Addralign: raw.Addralign,
			Entsize:   raw.Entsize,
			Index:     uint32(i),
			file:      f,
			nameOff:   raw.Name,
		})
	}

	if shstrndx != 0 && shstrndx < uint64(len(f.Sections)) {
		f.shstrndx = int(shstrndx)
		blob, err := f.Sections[f.shstrndx].Data()
		if err != nil {
			return fmt.Errorf("obj: reading section name string table: %w", err)
		}
		for _, sec := range f.Sections {
			sec.Name = stringAt(blob, sec.nameOff)
		}
	}

	for _, sec := range f.Sections {
		switch {
		case sec.Type == elf.SHT_SYMTAB && f.symtab == nil:
			f.symtab = sec
		case sec.Type == elf.SHT_DYNSYM && f.dynsym == nil:
			f.dynsym = sec
		case sec.Type == elf.SHT_REL || sec.Type == elf.SHT_RELA:
			// sh_info names the section these relocations apply to.
			f.relocsFor[sec.Info] = append(f.relocsFor[sec.Info], sec)
		}
	}
	return nil
}

func (f *File) readShdr(off uint64) (format.Shdr, error) {
	ext, err := f.bf.At(int64(off), int64(format.ShdrSize(f.Class)))
	if err != nil {
		return format.Shdr{}, fmt.Errorf("obj: reading section header at %#x: %w", off, err)
	}
	c, err := ext.Cursor(f.bo)
	if err != nil {
		return format.Shdr{}, err
	}
	var sh format.Shdr
	sh.Decode(c, f.Class)
	if err := c.Err(); err != nil {
		return format.Shdr{}, fmt.Errorf("obj: decoding section header at %#x: %w", off, err)
	}
	return sh, nil
}

// Section returns the first section with the given name, or nil.
//
// Section names are not unique — COMDAT groups routinely produce several
// .text.foo sections in one object — so this is a convenience for the cases
// where uniqueness is known. Use Sections or SectionsNamed when it is not.
func (f *File) Section(name string) *Section {
	for _, s := range f.Sections {
		if s.Name == name {
			return s
		}
	}
	return nil
}

// SectionsNamed returns every section with the given name, in table order.
func (f *File) SectionsNamed(name string) []*Section {
	var out []*Section
	for _, s := range f.Sections {
		if s.Name == name {
			out = append(out, s)
		}
	}
	return out
}

// SectionAt returns the section at index i, or nil if i is out of range or
// falls in the reserved range.
func (f *File) SectionAt(i uint32) *Section {
	if elf.ReservedIndex(i) || uint64(i) >= uint64(len(f.Sections)) {
		return nil
	}
	return f.Sections[i]
}

// Symtab returns the SHT_SYMTAB section, or nil.
func (f *File) Symtab() *Section { return f.symtab }

// Dynsym returns the SHT_DYNSYM section, or nil.
func (f *File) Dynsym() *Section { return f.dynsym }

// ByteOrder returns the byte order this object is encoded in.
func (f *File) ByteOrder() binary.ByteOrder { return f.bo }

// Target describes the object's architecture.
//
// OS is inferred from e_ident[EI_OSABI], which most Linux objects leave as
// ELFOSABI_NONE regardless of what they were built for, so a returned OSNone
// means "unstated", not "bare metal". ABI is never recoverable from an object
// and is always ABINone; e_flags is carried through verbatim, and for ARM and
// MIPS it is the real evidence of the ABI variant.
func (f *File) Target() elf.Target {
	t := elf.Target{
		Arch:   elf.ArchOf(f.Machine, f.Class),
		Class:  f.Class,
		Endian: f.Data.Endian(),
		Flags:  f.Flags,
	}
	switch f.OSABI {
	case elf.ELFOSABI_FREEBSD:
		t.OS = elf.OSFreeBSD
	case elf.ELFOSABI_NETBSD:
		t.OS = elf.OSNetBSD
	case elf.ELFOSABI_OPENBSD:
		t.OS = elf.OSOpenBSD
	case elf.ELFOSABI_SOLARIS:
		t.OS = elf.OSSolaris
	case elf.ELFOSABI_GNU:
		t.OS = elf.OSLinux
	}
	return t
}