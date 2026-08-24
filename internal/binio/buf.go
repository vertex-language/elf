package binio

import (
	"encoding/binary"
	"fmt"
	"io"
)

// Buf is an append-only, byte-order-aware output buffer with backpatching.
//
// Reserve16/32/64 write a placeholder and return a handle that can set its
// value later — the standard way to emit a length or offset that is not known
// until after the thing it describes has been written.
type Buf struct {
	b   []byte
	ord binary.ByteOrder
}

// NewBuf returns an empty Buf. It panics if ord is nil.
func NewBuf(ord binary.ByteOrder) *Buf { return NewBufSize(ord, 0) }

// NewBufSize returns an empty Buf with room for capacity bytes.
// It panics if ord is nil.
func NewBufSize(ord binary.ByteOrder, capacity int) *Buf {
	if ord == nil {
		panic("binio: nil ByteOrder")
	}
	var b []byte
	if capacity > 0 {
		b = make([]byte, 0, capacity)
	}
	return &Buf{b: b, ord: ord}
}

// Order returns the byte order values are encoded with.
func (w *Buf) Order() binary.ByteOrder { return w.ord }

// Len returns the number of bytes written.
func (w *Buf) Len() int { return len(w.b) }

// Bytes returns the buffer's contents. The result aliases the buffer and is
// invalidated by any subsequent write that reallocates.
func (w *Buf) Bytes() []byte { return w.b }

// Reset truncates the buffer, retaining its capacity.
func (w *Buf) Reset() { w.b = w.b[:0] }

// Grow ensures room for n more bytes without reallocating. It grows
// geometrically, so repeated calls stay amortized O(1) per byte.
func (w *Buf) Grow(n int) {
	if n <= 0 || cap(w.b)-len(w.b) >= n {
		return
	}
	need := len(w.b) + n
	next := 2 * cap(w.b)
	if next < need {
		next = need
	}
	nb := make([]byte, len(w.b), next)
	copy(nb, w.b)
	w.b = nb
}

func (w *Buf) U8(v uint8) { w.b = append(w.b, v) }

func (w *Buf) U16(v uint16) {
	var a [2]byte
	w.ord.PutUint16(a[:], v)
	w.b = append(w.b, a[:]...)
}

func (w *Buf) U32(v uint32) {
	var a [4]byte
	w.ord.PutUint32(a[:], v)
	w.b = append(w.b, a[:]...)
}

func (w *Buf) U64(v uint64) {
	var a [8]byte
	w.ord.PutUint64(a[:], v)
	w.b = append(w.b, a[:]...)
}

func (w *Buf) I8(v int8)   { w.U8(uint8(v)) }
func (w *Buf) I16(v int16) { w.U16(uint16(v)) }
func (w *Buf) I32(v int32) { w.U32(uint32(v)) }
func (w *Buf) I64(v int64) { w.U64(uint64(v)) }

// UWord writes 8 bytes when wide, 4 otherwise. Values that do not fit 32 bits
// are truncated; callers that need a range check must make it themselves.
func (w *Buf) UWord(wide bool, v uint64) {
	if wide {
		w.U64(v)
		return
	}
	w.U32(uint32(v))
}

// IWord writes 8 bytes when wide, 4 otherwise.
func (w *Buf) IWord(wide bool, v int64) {
	if wide {
		w.I64(v)
		return
	}
	w.I32(int32(v))
}

// Write implements io.Writer. The error is always nil.
func (w *Buf) Write(p []byte) (int, error) {
	w.b = append(w.b, p...)
	return len(p), nil
}

// WriteString implements io.StringWriter. The error is always nil.
func (w *Buf) WriteString(s string) (int, error) {
	w.b = append(w.b, s...)
	return len(s), nil
}

// WriteByte implements io.ByteWriter. The error is always nil.
func (w *Buf) WriteByte(b byte) error {
	w.b = append(w.b, b)
	return nil
}

// Zero appends n zero bytes.
func (w *Buf) Zero(n int) {
	if n <= 0 {
		return
	}
	w.Grow(n)
	for i := 0; i < n; i++ {
		w.b = append(w.b, 0)
	}
}

// Align zero-pads to the next multiple of n, measured from the start of the
// buffer.
func (w *Buf) Align(n int) {
	if n <= 1 {
		return
	}
	if r := len(w.b) % n; r != 0 {
		w.Zero(n - r)
	}
}

// WriteTo implements io.WriterTo.
func (w *Buf) WriteTo(dst io.Writer) (int64, error) {
	n, err := dst.Write(w.b)
	return int64(n), err
}

// Reserve16 appends a zero placeholder and returns a handle to fill it in.
func (w *Buf) Reserve16() Patch16 { off := len(w.b); w.U16(0); return Patch16{w, off} }

// Reserve32 appends a zero placeholder and returns a handle to fill it in.
func (w *Buf) Reserve32() Patch32 { off := len(w.b); w.U32(0); return Patch32{w, off} }

// Reserve64 appends a zero placeholder and returns a handle to fill it in.
func (w *Buf) Reserve64() Patch64 { off := len(w.b); w.U64(0); return Patch64{w, off} }

// Patch16At returns a handle to the 2 bytes already written at off.
// It panics if those bytes are outside the buffer.
func (w *Buf) Patch16At(off int) Patch16 { w.checkPatch(off, 2); return Patch16{w, off} }

// Patch32At returns a handle to the 4 bytes already written at off.
// It panics if those bytes are outside the buffer.
func (w *Buf) Patch32At(off int) Patch32 { w.checkPatch(off, 4); return Patch32{w, off} }

// Patch64At returns a handle to the 8 bytes already written at off.
// It panics if those bytes are outside the buffer.
func (w *Buf) Patch64At(off int) Patch64 { w.checkPatch(off, 8); return Patch64{w, off} }

// checkPatch panics: patching outside the buffer is a bug in the emitter, not
// bad input. Nothing reachable from parsing a file calls it.
func (w *Buf) checkPatch(off, n int) {
	if off < 0 || off > len(w.b)-n {
		panic(fmt.Sprintf("binio: %d-byte patch at %d outside a %d-byte buffer", n, off, len(w.b)))
	}
}

// Patch16 is a handle to two bytes in a Buf.
type Patch16 struct {
	b   *Buf
	off int
}

func (p Patch16) Off() int    { return p.off }
func (p Patch16) Valid() bool { return p.b != nil }

// Set overwrites the reserved bytes. It panics on a zero Patch16.
func (p Patch16) Set(v uint16) {
	if p.b == nil {
		panic("binio: Set on a zero Patch16")
	}
	p.b.ord.PutUint16(p.b.b[p.off:p.off+2], v)
}

// Patch32 is a handle to four bytes in a Buf.
type Patch32 struct {
	b   *Buf
	off int
}

func (p Patch32) Off() int    { return p.off }
func (p Patch32) Valid() bool { return p.b != nil }

// Set overwrites the reserved bytes. It panics on a zero Patch32.
func (p Patch32) Set(v uint32) {
	if p.b == nil {
		panic("binio: Set on a zero Patch32")
	}
	p.b.ord.PutUint32(p.b.b[p.off:p.off+4], v)
}

// Patch64 is a handle to eight bytes in a Buf.
type Patch64 struct {
	b   *Buf
	off int
}

func (p Patch64) Off() int    { return p.off }
func (p Patch64) Valid() bool { return p.b != nil }

// Set overwrites the reserved bytes. It panics on a zero Patch64.
func (p Patch64) Set(v uint64) {
	if p.b == nil {
		panic("binio: Set on a zero Patch64")
	}
	p.b.ord.PutUint64(p.b.b[p.off:p.off+8], v)
}