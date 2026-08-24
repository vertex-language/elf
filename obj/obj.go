// Package obj reads and writes ELF relocatable objects (ET_REL).
//
// Reading and writing are separate type families. A parsed *File and its
// *Section values are immutable; construction happens through *Writer and
// *SectionBuilder, which share no types with the read side. Nothing here has a
// field whose meaning depends on which of the two worlds it came from.
//
// A *File is not safe for concurrent use: Symbols caches its result so that
// symbol pointer identity is stable across calls, and that cache is written on
// first access.
//
// Reading is bounded throughout. A malformed or hostile object produces an
// error, never a panic; bounds failures unwrap to internal/binio.ErrTruncated.
package obj

import "errors"

var (
	// ErrNotRelocatable reports an ELF file whose e_type is not ET_REL.
	// Executables and shared objects are the linker's business, not the
	// object reader's.
	ErrNotRelocatable = errors.New("obj: not a relocatable (ET_REL) object")

	// ErrNoSymbolTable reports a lookup that needed a symbol table in a file
	// that has none.
	ErrNoSymbolTable = errors.New("obj: file has no symbol table")
)