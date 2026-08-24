package elf

import "errors"

var (
	// ErrNotELF reports a file whose first four bytes are not the ELF magic.
	ErrNotELF = errors.New("elf: not an ELF file")

	// ErrShortHeader reports a buffer too short for the detection function
	// that was called. See MagicSize and KindPrefix.
	ErrShortHeader = errors.New("elf: header prefix is too short to classify")

	// ErrInvalidTarget reports a triple that named no known architecture, or
	// a Target whose fields contradict each other.
	ErrInvalidTarget = errors.New("elf: invalid target")

	// ErrUnsupportedClass reports an e_ident[EI_CLASS] that is neither
	// ELFCLASS32 nor ELFCLASS64.
	ErrUnsupportedClass = errors.New("elf: unsupported EI_CLASS")

	// ErrUnsupportedData reports an e_ident[EI_DATA] that is neither
	// ELFDATA2LSB nor ELFDATA2MSB.
	ErrUnsupportedData = errors.New("elf: unsupported EI_DATA")
)

// Errors for conditions this package cannot observe live with the package that
// can: obj.ErrNotRelocatable, ar.ErrNotArchive, backend.ErrNoBackend, and the
// link.*Error types.