package binio

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
)

// File is a bounded view of an io.ReaderAt of known size. It hands out Extents,
// which are checked sub-ranges; nothing above this layer computes a file offset
// without going through one.
type File struct {
	r    io.ReaderAt
	size int64
}

// NewFile returns a File over r. It panics if size is negative.
func NewFile(r io.ReaderAt, size int64) *File {
	if size < 0 {
		panic("binio: negative file size")
	}
	return &File{r: r, size: size}
}

// Open returns a File over r, determining its size with SizeOf.
func Open(r io.ReaderAt) (*File, error) {
	n, err := SizeOf(r)
	if err != nil {
		return nil, err
	}
	return NewFile(r, n), nil
}

// SizeOf reports the length of r, via a Size method (bytes.Reader,
// io.SectionReader) or a Stat method (os.File). Non-regular files report
// ErrUnknownSize: a pipe has no length to bound reads against.
func SizeOf(r io.ReaderAt) (int64, error) {
	switch v := r.(type) {
	case interface{ Size() int64 }:
		n := v.Size()
		if n < 0 {
			return 0, ErrUnknownSize
		}
		return n, nil
	case interface {
		Stat() (fs.FileInfo, error)
	}:
		fi, err := v.Stat()
		if err != nil {
			return 0, err
		}
		if !fi.Mode().IsRegular() {
			return 0, ErrUnknownSize
		}
		n := fi.Size()
		if n < 0 {
			return 0, ErrUnknownSize
		}
		return n, nil
	}
	return 0, ErrUnknownSize
}

// Size returns the file's length.
func (f *File) Size() int64 { return f.size }

// ReaderAt returns the underlying reader.
func (f *File) ReaderAt() io.ReaderAt { return f.r }

// At returns an Extent covering n bytes at off, or a BoundsError.
func (f *File) At(off, n int64) (Extent, error) {
	if off < 0 || n < 0 || off > f.size || n > f.size-off {
		have := int64(0)
		if off >= 0 && off <= f.size {
			have = f.size - off
		}
		return Extent{}, &BoundsError{Op: "extent", Off: off, Need: n, Have: have}
	}
	return Extent{r: f.r, off: off, n: n}, nil
}

// Head reads up to n bytes from the start of the file, returning fewer if the
// file is shorter. It is for magic-number sniffing, where a short file is an
// answer rather than an error.
func (f *File) Head(n int64) ([]byte, error) {
	if n < 0 {
		n = 0
	}
	if n > f.size {
		n = f.size
	}
	e, err := f.At(0, n)
	if err != nil {
		return nil, err
	}
	return e.Data()
}

// Extent is a checked byte range within a File. Constructing one proves it is
// in bounds; reading it can still fail on I/O.
type Extent struct {
	r   io.ReaderAt
	off int64
	n   int64
}

// EmptyExtent returns a zero-length Extent. Data returns an empty slice and
// Open returns an immediately-EOF reader, so callers with nothing to read
// (SHT_NOBITS sections, thin archive members) can return one instead of
// inventing a private empty io.ReaderAt.
func EmptyExtent() Extent { return Extent{} }

// Off returns the extent's offset within the file.
func (e Extent) Off() int64 { return e.off }

// Len returns the extent's length.
func (e Extent) Len() int64 { return e.n }

// Sub returns a sub-range of e, or a BoundsError.
func (e Extent) Sub(off, n int64) (Extent, error) {
	if off < 0 || n < 0 || off > e.n || n > e.n-off {
		have := int64(0)
		if off >= 0 && off <= e.n {
			have = e.n - off
		}
		return Extent{}, &BoundsError{Op: "subextent", Off: e.off + off, Need: n, Have: have}
	}
	return Extent{r: e.r, off: e.off + off, n: n}, nil
}

// Data reads the extent into a fresh slice. It allocates on every call;
// callers that read the same extent repeatedly should cache the result.
//
// A short read is reported as a BoundsError even though the extent was in
// bounds at construction: the file shrank, or the ReaderAt lied about its size.
func (e Extent) Data() ([]byte, error) {
	if e.n == 0 {
		return []byte{}, nil
	}
	if e.n > int64(maxInt) {
		return nil, fmt.Errorf("binio: extent of %d bytes at %#x: %w", e.n, e.off, ErrTooLarge)
	}
	b := make([]byte, e.n)
	n, err := e.r.ReadAt(b, e.off)
	if int64(n) == e.n {
		return b, nil
	}
	if err == nil || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return nil, &BoundsError{Op: "read", Off: e.off, Need: e.n, Have: int64(n)}
	}
	return nil, fmt.Errorf("binio: reading %d bytes at %#x: %w", e.n, e.off, err)
}

// Open returns a reader over the extent, without reading it into memory.
func (e Extent) Open() *io.SectionReader {
	if e.r == nil {
		return io.NewSectionReader(emptyReaderAt{}, 0, 0)
	}
	return io.NewSectionReader(e.r, e.off, e.n)
}

// Cursor reads the extent and returns a Cursor over it, positioned so that Pos
// reports absolute file offsets.
func (e Extent) Cursor(ord binary.ByteOrder) (*Cursor, error) {
	b, err := e.Data()
	if err != nil {
		return nil, err
	}
	return NewCursorAt(b, e.off, ord), nil
}

type emptyReaderAt struct{}

func (emptyReaderAt) ReadAt([]byte, int64) (int, error) { return 0, io.EOF }