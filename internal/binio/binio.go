// Package binio provides bounded, byte-order-aware readers and writers for
// binary file formats.
//
// The package knows nothing about ELF. It deals in offsets, widths, and byte
// order, and it never panics on the contents of the data it is given — every
// out-of-range access latches an error that unwraps to ErrTruncated. Panics are
// reserved for API misuse by the caller (a nil binary.ByteOrder, a patch outside
// the buffer) and are documented on the method that panics.
//
// Width is expressed here as a plain bool ("wide"), not as an ELF class. binio
// sits below the format layer and has no vocabulary for ELF; internal/format
// converts elf.Class to a bool once, at its own boundary.
package binio

import (
	"errors"
	"fmt"
)

// maxInt is the largest value an int can hold on this platform. Used to reject
// lengths that cannot address a Go slice before they are converted.
const maxInt = int(^uint(0) >> 1)

var (
	// ErrTruncated reports that a read ran past the end of the available data.
	// BoundsError and CountError both unwrap to it.
	ErrTruncated = errors.New("binio: data ends before the structure does")

	// ErrOverflow reports that an encoded value does not fit the Go type it was
	// being decoded into. LEBError unwraps to it.
	ErrOverflow = errors.New("binio: encoded value does not fit its type")

	// ErrUnknownSize reports that the length of an io.ReaderAt could not be
	// determined. See SizeOf.
	ErrUnknownSize = errors.New("binio: cannot determine the length of the reader")

	// ErrTooLarge reports a length that exceeds the maximum Go slice size.
	ErrTooLarge = errors.New("binio: length exceeds the maximum slice size")
)

// BoundsError is a read that ran off the end of the data.
type BoundsError struct {
	Op   string // the operation that failed: "u32", "cstring", "sub", …
	Off  int64  // absolute position where the read started
	Need int64  // bytes the operation wanted
	Have int64  // bytes actually remaining
}

func (e *BoundsError) Error() string {
	return fmt.Sprintf("binio: %s at offset %#x needs %d bytes, %d remain",
		e.Op, e.Off, e.Need, e.Have)
}

func (e *BoundsError) Unwrap() error { return ErrTruncated }

// CountError is a declared table whose entries cannot fit in the data. It is
// separate from BoundsError so that "this header claims 4 billion symbols" is
// distinguishable from "this read is three bytes short".
type CountError struct {
	Off    int64
	Count  uint64
	Stride int
	Have   int64
}

func (e *CountError) Error() string {
	return fmt.Sprintf("binio: table of %d entries of %d bytes at offset %#x exceeds the %d bytes available",
		e.Count, e.Stride, e.Off, e.Have)
}

func (e *CountError) Unwrap() error { return ErrTruncated }

// LEBError is a LEB128 value too large for its 64-bit destination.
type LEBError struct {
	Op  string // "uleb" or "sleb"
	Off int64  // absolute position of the first byte of the value
}

func (e *LEBError) Error() string {
	return fmt.Sprintf("binio: %s at offset %#x does not fit in 64 bits", e.Op, e.Off)
}

func (e *LEBError) Unwrap() error { return ErrOverflow }