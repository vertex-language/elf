package format

import (
	"encoding/binary"

	"github.com/vertex-language/elf"
	"github.com/vertex-language/elf/internal/binio"
)

// Ident is e_ident: the first sixteen bytes, which are byte-order independent
// and must be read before anything else in the file can be interpreted.
type Ident struct {
	Class      elf.Class
	Data       elf.Data
	Version    uint8
	OSABI      elf.OSABI
	ABIVersion uint8
}

// DecodeIdent reads e_ident from the first elf.EI_NIDENT bytes of b.
//
// This is the bootstrap: it validates the magic and yields the class and byte
// order that every later decode in the file depends on. It takes a byte slice
// rather than a cursor because a cursor cannot be constructed until its result
// is known.
func DecodeIdent(b []byte) (Ident, error) {
	if len(b) < elf.EI_NIDENT {
		return Ident{}, elf.ErrShortHeader
	}
	if !elf.Is(b) {
		return Ident{}, elf.ErrNotELF
	}
	id := Ident{
		Class:      elf.Class(b[elf.EI_CLASS]),
		Data:       elf.Data(b[elf.EI_DATA]),
		Version:    b[elf.EI_VERSION],
		OSABI:      elf.OSABI(b[elf.EI_OSABI]),
		ABIVersion: b[elf.EI_ABIVERSION],
	}
	if !id.Class.Valid() {
		return id, elf.ErrUnsupportedClass
	}
	if id.Data.Endian() == elf.EndianUnknown {
		return id, elf.ErrUnsupportedData
	}
	return id, nil
}

// ByteOrder returns the binary.ByteOrder this identity selects. Only valid
// after DecodeIdent has returned a nil error.
func (id Ident) ByteOrder() binary.ByteOrder {
	if id.Data == elf.ELFDATA2MSB {
		return binary.BigEndian
	}
	return binary.LittleEndian
}

// Encode writes e_ident into the first elf.EI_NIDENT bytes of b, zeroing the
// padding. It panics if b is too short, which is an emitter bug.
func (id Ident) Encode(b []byte) {
	if len(b) < elf.EI_NIDENT {
		panic("format: Ident.Encode into a buffer shorter than EI_NIDENT")
	}
	b[elf.EI_MAG0] = elf.Magic[0]
	b[elf.EI_MAG1] = elf.Magic[1]
	b[elf.EI_MAG2] = elf.Magic[2]
	b[elf.EI_MAG3] = elf.Magic[3]
	b[elf.EI_CLASS] = byte(id.Class)
	b[elf.EI_DATA] = byte(id.Data)
	b[elf.EI_VERSION] = id.Version
	b[elf.EI_OSABI] = byte(id.OSABI)
	b[elf.EI_ABIVERSION] = id.ABIVersion
	for i := elf.EI_PAD; i < elf.EI_NIDENT; i++ {
		b[i] = 0
	}
}

// Ehdr is the ELF header.
type Ehdr struct {
	Ident     Ident
	Type      elf.Type
	Machine   elf.Machine
	Version   uint32
	Entry     uint64
	Phoff     uint64
	Shoff     uint64
	Flags     uint32
	Ehsize    uint16
	Phentsize uint16
	Phnum     uint16
	Shentsize uint16
	Shnum     uint16
	Shstrndx  uint16
}

// Decode reads an ELF header, e_ident included, from the start of c.
//
// The cursor must already carry the byte order named by the file's e_ident,
// which means the caller has run DecodeIdent on the first sixteen bytes
// already. ParseEhdr does that sequencing; prefer it unless the cursor is
// already in hand.
//
// Unlike the other Decode methods this takes no class: the header carries its
// own, in the ident it begins with.
func (h *Ehdr) Decode(c *binio.Cursor) {
	raw := c.Bytes(elf.EI_NIDENT)
	if raw == nil {
		return
	}
	id, err := DecodeIdent(raw)
	if err != nil {
		c.Fail(err)
		return
	}
	h.Ident = id
	wide := id.Class.Wide()

	h.Type = elf.Type(c.U16())
	h.Machine = elf.Machine(c.U16())
	h.Version = c.U32()
	h.Entry = c.UWord(wide)
	h.Phoff = c.UWord(wide)
	h.Shoff = c.UWord(wide)
	h.Flags = c.U32()
	h.Ehsize = c.U16()
	h.Phentsize = c.U16()
	h.Phnum = c.U16()
	h.Shentsize = c.U16()
	h.Shnum = c.U16()
	h.Shstrndx = c.U16()
}

// ParseEhdr decodes an ELF header from a byte slice, discovering the byte
// order from e_ident on the way.
func ParseEhdr(b []byte) (Ehdr, error) {
	id, err := DecodeIdent(b)
	if err != nil {
		return Ehdr{}, err
	}
	c := binio.NewCursor(b, id.ByteOrder())
	var h Ehdr
	h.Decode(c)
	if err := c.Err(); err != nil {
		return Ehdr{}, err
	}
	return h, nil
}

// Encode writes the ELF header. Ehsize, Phentsize, and Shentsize are taken
// from the class rather than from the struct, so they cannot disagree with the
// structures actually written; the fields exist to carry what was read.
func (h *Ehdr) Encode(b *binio.Buf) {
	cl := h.Ident.Class
	wide := cl.Wide()

	var ident [elf.EI_NIDENT]byte
	h.Ident.Encode(ident[:])
	b.Write(ident[:])

	b.U16(uint16(h.Type))
	b.U16(uint16(h.Machine))
	b.U32(h.Version)
	b.UWord(wide, h.Entry)
	b.UWord(wide, h.Phoff)
	b.UWord(wide, h.Shoff)
	b.U32(h.Flags)
	b.U16(uint16(EhdrSize(cl)))
	b.U16(uint16(PhdrSize(cl)))
	b.U16(h.Phnum)
	b.U16(uint16(ShdrSize(cl)))
	b.U16(h.Shnum)
	b.U16(h.Shstrndx)
}