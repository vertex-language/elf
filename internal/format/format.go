// Package format defines every ELF on-disk structure exactly once.
//
// This is the module's single source of truth for the wire format. obj reads
// and writes through it, link/emit writes through it, and link's shared-object
// reader reads through it. No other package hand-indexes header bytes or
// re-derives a structure size — if a literal 52 or 64 appears outside this
// package, that is a bug.
//
// Every structure follows the same shape:
//
//	func (s *T) Decode(c *binio.Cursor, cl elf.Class)
//	func (s *T) Encode(b *binio.Buf, cl elf.Class)
//	func TSize(cl elf.Class) int
//
// Decode returns nothing. Errors latch into the cursor, so a decoder can read
// sixty thousand symbols and check binio.Cursor.Err once at the end rather
// than branching after every field. A failed cursor leaves the destination
// struct in an unspecified state; callers must not read it before checking.
//
// The structures mirror the file. They hold raw bytes where the file holds raw
// bytes — Sym.Info is the packed st_info, not a decoded binding and type —
// and offer accessors for the interpretation. Keeping decode free of
// interpretation means a round trip is byte-exact even for objects using
// psABI-specific bits this module does not understand.
package format

import (
	"errors"

	"github.com/vertex-language/elf"
	"github.com/vertex-language/elf/internal/binio"
)

// ErrClass reports a decode or encode attempted with a class that is neither
// ELFCLASS32 nor ELFCLASS64.
var ErrClass = errors.New("format: structure width requires ELFCLASS32 or ELFCLASS64")

// checkClass latches ErrClass on an unusable class and reports whether the
// caller may proceed.
func checkClass(c *binio.Cursor, cl elf.Class) bool {
	if !cl.Valid() {
		c.Fail(ErrClass)
		return false
	}
	return true
}

// Structure sizes. Zero for ELFCLASSNONE.

func EhdrSize(cl elf.Class) int {
	switch cl {
	case elf.ELFCLASS32:
		return 52
	case elf.ELFCLASS64:
		return 64
	}
	return 0
}

func PhdrSize(cl elf.Class) int {
	switch cl {
	case elf.ELFCLASS32:
		return 32
	case elf.ELFCLASS64:
		return 56
	}
	return 0
}

func ShdrSize(cl elf.Class) int {
	switch cl {
	case elf.ELFCLASS32:
		return 40
	case elf.ELFCLASS64:
		return 64
	}
	return 0
}

func SymSize(cl elf.Class) int {
	switch cl {
	case elf.ELFCLASS32:
		return 16
	case elf.ELFCLASS64:
		return 24
	}
	return 0
}

func RelSize(cl elf.Class) int {
	switch cl {
	case elf.ELFCLASS32:
		return 8
	case elf.ELFCLASS64:
		return 16
	}
	return 0
}

func RelaSize(cl elf.Class) int {
	switch cl {
	case elf.ELFCLASS32:
		return 12
	case elf.ELFCLASS64:
		return 24
	}
	return 0
}

func RelrSize(cl elf.Class) int {
	switch cl {
	case elf.ELFCLASS32:
		return 4
	case elf.ELFCLASS64:
		return 8
	}
	return 0
}

func DynSize(cl elf.Class) int {
	switch cl {
	case elf.ELFCLASS32:
		return 8
	case elf.ELFCLASS64:
		return 16
	}
	return 0
}

func ChdrSize(cl elf.Class) int {
	switch cl {
	case elf.ELFCLASS32:
		return 12
	case elf.ELFCLASS64:
		return 24
	}
	return 0
}

// The note header and the symbol versioning structures use the same layout in
// both classes, so their sizes take no argument.
const (
	NhdrSize    = 12
	VerdefSize  = 20
	VerdauxSize = 8
	VerneedSize = 16
	VernauxSize = 16
)

// HeaderRegion is the size of the ELF header plus nsegs program headers: the
// prefix of the file that must be reserved before any section can be placed.
func HeaderRegion(cl elf.Class, nsegs int) uint64 {
	return uint64(EhdrSize(cl)) + uint64(nsegs)*uint64(PhdrSize(cl))
}