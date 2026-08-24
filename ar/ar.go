// Package ar reads and writes Unix archives in the SysV/GNU variant, which is
// what ELF toolchains produce.
//
// Three special members structure a SysV archive. A member named "/" is the
// symbol index and, if present, comes first. A member named "//" is the string
// table holding member names too long for the 16-byte name field; it follows
// the index, or comes first when there is no index. A member named "/SYM64/"
// replaces "/" when the archive is large enough that 32-bit offsets no longer
// reach.
//
// GNU thin archives are supported. A thin archive carries headers and an index
// but no member contents: each member names a file on disk. Reading one gives
// you names and offsets; the bytes are the caller's to fetch.
//
// The BSD variant is not supported. It is detected and rejected rather than
// misparsed: BSD stores long names after the header and counts them in
// ar_size, so reading a BSD archive as SysV yields members whose contents are
// silently shifted by the length of their own name.
package ar

import "errors"

const (
	// Magic begins a normal archive.
	Magic = "!<arch>\n"

	// MagicThin begins a GNU thin archive.
	MagicThin = "!<thin>\n"

	// MagicSize is the length of either magic string.
	MagicSize = 8

	// HeaderSize is the fixed size of a member header.
	HeaderSize = 60
)

// headerTerm is ar_fmag, the two bytes closing every member header: a
// backtick and a linefeed.
//
// FreeBSD's ar(5) states these as 0x96 and 0x0A. That is a typo for 0x60;
// glibc's ar.h defines ARFMAG as a backtick followed by a newline, and that is
// what archives in the wild contain.
const headerTerm = "`\n"

// Special member names.
const (
	nameSymbolIndex   = "/"
	nameSymbolIndex64 = "/SYM64/"
	nameStringTable   = "//"
	nameBSDSymbolDef  = "__.SYMDEF"
)

// longNameTerm ends each entry in the "//" string table. Entries are packed
// with no padding between them.
const longNameTerm = "/\n"

// maxSizeField is the largest value the 10-byte decimal ar_size field holds.
const maxSizeField = 9999999999

var (
	// ErrNotArchive reports a file that begins with neither archive magic.
	ErrNotArchive = errors.New("ar: not an ar archive")

	// ErrBadHeader reports a malformed member header: a missing terminator,
	// a non-numeric field, or a nonsensical size.
	ErrBadHeader = errors.New("ar: malformed member header")

	// ErrBSDArchive reports a BSD-variant archive, which this package
	// declines to read rather than misparse.
	ErrBSDArchive = errors.New("ar: BSD-variant archive; only the SysV/GNU variant is supported")

	// ErrThinMember reports an attempt to read the contents of a thin
	// archive member, which live in a separate file.
	ErrThinMember = errors.New("ar: thin archive member has no contents in the archive")

	// ErrBadIndex reports a malformed symbol index.
	ErrBadIndex = errors.New("ar: malformed symbol index")
)

// IndexEntry maps a symbol name to the member defining it.
type IndexEntry struct {
	Name string

	// HeaderOffset is the archive file offset of the defining member's
	// header, not of its data. This is what the format stores and what a
	// linker seeks to.
	HeaderOffset int64
}