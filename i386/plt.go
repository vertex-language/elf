package i386

import (
	"fmt"

	"github.com/vertex-language/elf/backend"
	"github.com/vertex-language/elf/image"
)

// Got describes the global offset table's geometry.
//
// This is real, correct geometry — not a placeholder — because ordinary
// GOT-relative addressing (GOTOFF, GOTPC, GOT32) needs it and works today;
// see the package doc for what does not.
func (Backend) Got() backend.GotShape {
	return backend.GotShape{
		EntrySize:    4,
		Align:        4,
		Reserved:     0,
		PltReserved:  3,
		TlsGdEntries: 2,
	}
}

// Plt describes the procedure linkage table's geometry i386 dynamic linking
// uses. Reported for accuracy — it is what a correct implementation's tables
// would be sized as — even though nothing here can fill them yet; see the
// package doc for why.
func (Backend) Plt() backend.PltShape {
	return backend.PltShape{
		HeaderSize:    16,
		EntrySize:     16,
		SecEntrySize:  0,
		IPltEntrySize: 16,
		Align:         4,
		Lazy:          true,
	}
}

// errNoDynamic is returned by every method below: this backend can compute
// the GOT and PLT geometry, which is all ordinary GOT-relative addressing
// needs, but cannot fill in the loader-facing tables, because doing that
// correctly means emitting REL rather than RELA dynamic relocations, which
// link/dynamic.go does not support yet. See the package doc.
var errNoDynamic = fmt.Errorf("i386: dynamic linking (PLT/.got.plt content) is not implemented yet: " +
	"i386 needs REL-format dynamic relocations, which link/dynamic.go does not emit")

func (Backend) WritePltHeader(buf []byte, s *backend.Site) error    { return errNoDynamic }
func (Backend) WriteGotPltHeader(buf []byte, s *backend.Site) error { return errNoDynamic }
func (Backend) WriteGotPlt(buf []byte, s *backend.Site, sym *image.Sym) error {
	return errNoDynamic
}
func (Backend) WritePlt(buf []byte, s *backend.Site, sym *image.Sym,
	pltAddr, gotAddr uint64, index int) error {
	return errNoDynamic
}
func (Backend) WriteSecPlt(buf []byte, s *backend.Site, sym *image.Sym,
	pltAddr, gotAddr uint64, index int) error {
	return errNoDynamic
}
