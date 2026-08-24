package elf

// Class is e_ident[EI_CLASS]: the width of the object's address and offset
// fields. It is this module's single representation of 32-vs-64.
type Class uint8

const (
	ELFCLASSNONE Class = 0
	ELFCLASS32   Class = 1
	ELFCLASS64   Class = 2
)

func (c Class) String() string {
	switch c {
	case ELFCLASS32:
		return "ELFCLASS32"
	case ELFCLASS64:
		return "ELFCLASS64"
	}
	return "ELFCLASSNONE"
}

// Wide reports whether addresses and offsets are 64 bits.
//
// Total by construction: ELFCLASSNONE reports false rather than panicking,
// because this is reachable from parsing a hostile file. Callers that must
// reject an unknown class check Valid first.
func (c Class) Wide() bool { return c == ELFCLASS64 }

// Valid reports whether c is a class this module can decode.
func (c Class) Valid() bool { return c == ELFCLASS32 || c == ELFCLASS64 }

// Bits returns 32 or 64, or 0 for ELFCLASSNONE. It exists for formatting and
// arithmetic; it is not a field anywhere.
func (c Class) Bits() int {
	switch c {
	case ELFCLASS32:
		return 32
	case ELFCLASS64:
		return 64
	}
	return 0
}

// Data is e_ident[EI_DATA]: the byte order of the object's multi-byte fields.
type Data uint8

const (
	ELFDATANONE Data = 0
	ELFDATA2LSB Data = 1
	ELFDATA2MSB Data = 2
)

func (d Data) String() string {
	switch d {
	case ELFDATA2LSB:
		return "ELFDATA2LSB"
	case ELFDATA2MSB:
		return "ELFDATA2MSB"
	}
	return "ELFDATANONE"
}

// Endian names a byte order without reference to the ELF encoding of it, so
// that Target can carry one without carrying an e_ident byte.
type Endian uint8

const (
	EndianUnknown Endian = iota
	EndianLittle
	EndianBig
)

func (e Endian) String() string {
	switch e {
	case EndianLittle:
		return "little"
	case EndianBig:
		return "big"
	}
	return "unknown"
}

// Endian converts the EI_DATA encoding to an Endian.
func (d Data) Endian() Endian {
	switch d {
	case ELFDATA2LSB:
		return EndianLittle
	case ELFDATA2MSB:
		return EndianBig
	}
	return EndianUnknown
}

// Data converts an Endian back to its EI_DATA encoding.
func (e Endian) Data() Data {
	switch e {
	case EndianLittle:
		return ELFDATA2LSB
	case EndianBig:
		return ELFDATA2MSB
	}
	return ELFDATANONE
}