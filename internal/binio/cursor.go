package binio

import (
	"encoding/binary"
	"fmt"
)

// Cursor is a bounded sequential reader over a byte slice.
//
// A Cursor latches the first error it encounters and becomes inert: every
// subsequent read returns a zero value without advancing. This lets a decoder
// read a whole structure field by field and check Err once at the end, rather
// than branching after every field.
//
// A Cursor does not copy. Slices returned by Bytes, Peek, and Rest alias the
// underlying data; callers that retain them past the lifetime of that data must
// copy.
type Cursor struct {
	b    []byte
	off  int   // read position, relative to b
	base int64 // absolute position of b[0] in the containing file
	ord  binary.ByteOrder
	err  error
}

// NewCursor returns a Cursor over b whose absolute positions are relative to
// the start of b. It panics if ord is nil.
func NewCursor(b []byte, ord binary.ByteOrder) *Cursor { return NewCursorAt(b, 0, ord) }

// NewCursorAt returns a Cursor over b, reporting positions as base + offset.
// base only affects error messages and Pos; it does not bound anything.
// It panics if ord is nil.
func NewCursorAt(b []byte, base int64, ord binary.ByteOrder) *Cursor {
	if ord == nil {
		panic("binio: nil ByteOrder")
	}
	return &Cursor{b: b, base: base, ord: ord}
}

// Order returns the byte order reads are decoded with.
func (c *Cursor) Order() binary.ByteOrder { return c.ord }

// Len returns the number of bytes remaining.
func (c *Cursor) Len() int { return len(c.b) - c.off }

// Off returns the read position relative to the start of the cursor's data.
func (c *Cursor) Off() int { return c.off }

// Pos returns the absolute position, base + Off.
func (c *Cursor) Pos() int64 { return c.base + int64(c.off) }

// Err returns the first error latched, or nil.
func (c *Cursor) Err() error { return c.err }

// Fail latches err if no error has been latched yet. Decoders use it to report
// semantic problems ("this index names no section") through the same channel as
// bounds problems.
func (c *Cursor) Fail(err error) {
	if c.err == nil && err != nil {
		c.err = err
	}
}

// take consumes n bytes, or latches a BoundsError and returns false.
func (c *Cursor) take(op string, n int) ([]byte, bool) {
	if c.err != nil {
		return nil, false
	}
	// Written as a subtraction so that a huge n cannot overflow into a pass.
	if n < 0 || n > len(c.b)-c.off {
		c.Fail(&BoundsError{
			Op:   op,
			Off:  c.Pos(),
			Need: int64(n),
			Have: int64(len(c.b) - c.off),
		})
		return nil, false
	}
	s := c.b[c.off : c.off+n]
	c.off += n
	return s, true
}

func (c *Cursor) U8() uint8 {
	s, ok := c.take("u8", 1)
	if !ok {
		return 0
	}
	return s[0]
}

func (c *Cursor) U16() uint16 {
	s, ok := c.take("u16", 2)
	if !ok {
		return 0
	}
	return c.ord.Uint16(s)
}

func (c *Cursor) U32() uint32 {
	s, ok := c.take("u32", 4)
	if !ok {
		return 0
	}
	return c.ord.Uint32(s)
}

func (c *Cursor) U64() uint64 {
	s, ok := c.take("u64", 8)
	if !ok {
		return 0
	}
	return c.ord.Uint64(s)
}

func (c *Cursor) I8() int8   { return int8(c.U8()) }
func (c *Cursor) I16() int16 { return int16(c.U16()) }
func (c *Cursor) I32() int32 { return int32(c.U32()) }
func (c *Cursor) I64() int64 { return int64(c.U64()) }

// UWord reads a 64-bit value when wide, a zero-extended 32-bit value otherwise.
func (c *Cursor) UWord(wide bool) uint64 {
	if wide {
		return c.U64()
	}
	return uint64(c.U32())
}

// IWord reads a 64-bit value when wide, a sign-extended 32-bit value otherwise.
func (c *Cursor) IWord(wide bool) int64 {
	if wide {
		return c.I64()
	}
	return int64(c.I32())
}

// Bytes consumes and returns n bytes. The result aliases the cursor's data.
func (c *Cursor) Bytes(n int) []byte {
	s, ok := c.take("bytes", n)
	if !ok {
		return nil
	}
	return s
}

// Rest consumes and returns everything remaining.
func (c *Cursor) Rest() []byte { return c.Bytes(c.Len()) }

// Peek returns the next n bytes without consuming them, or nil if fewer than n
// remain. Peek never latches an error: it is for lookahead, where a short read
// is an answer rather than a failure.
func (c *Cursor) Peek(n int) []byte {
	if c.err != nil || n < 0 || n > len(c.b)-c.off {
		return nil
	}
	return c.b[c.off : c.off+n]
}

// Str consumes exactly n bytes and returns them as a string with trailing NUL
// bytes removed. This is the fixed-width-field form; for a NUL-terminated
// string of unknown length, use CString.
func (c *Cursor) Str(n int) string {
	s, ok := c.take("str", n)
	if !ok {
		return ""
	}
	for len(s) > 0 && s[len(s)-1] == 0 {
		s = s[:len(s)-1]
	}
	return string(s)
}

// CString consumes bytes through the next NUL and returns them without it. An
// unterminated run to the end of the data is a BoundsError: a string table
// whose last entry is unterminated is malformed, not merely short.
func (c *Cursor) CString() string {
	if c.err != nil {
		return ""
	}
	rest := c.b[c.off:]
	for i := 0; i < len(rest); i++ {
		if rest[i] == 0 {
			s := string(rest[:i])
			c.off += i + 1
			return s
		}
	}
	c.Fail(&BoundsError{
		Op:   "cstring",
		Off:  c.Pos(),
		Need: int64(len(rest)) + 1,
		Have: int64(len(rest)),
	})
	return ""
}

// Skip advances by n bytes.
func (c *Cursor) Skip(n int) { c.take("skip", n) }

// Seek moves to an absolute offset within the cursor's data. Unlike Sub and
// Next, Seek is not relative to the current position.
func (c *Cursor) Seek(off int) {
	if c.err != nil {
		return
	}
	if off < 0 || off > len(c.b) {
		c.Fail(&BoundsError{
			Op:   "seek",
			Off:  c.base + int64(off),
			Need: 0,
			Have: int64(len(c.b)),
		})
		return
	}
	c.off = off
}

// Align advances to the next multiple of n, measured from the start of the
// cursor's data — not from the absolute file position. For a cursor over a
// section, that is section-relative alignment, which is what note records and
// most in-section tables specify.
func (c *Cursor) Align(n int) {
	if n <= 1 {
		return
	}
	if r := c.off % n; r != 0 {
		c.Skip(n - r)
	}
}

// dead returns an already-failed cursor, so that Sub/Next/Table can always
// return a usable *Cursor and callers never nil-check.
func (c *Cursor) dead(err error) *Cursor {
	return &Cursor{base: c.Pos(), ord: c.ord, err: err}
}

// Sub returns a cursor over n bytes starting off bytes ahead of the current
// position, without advancing this cursor.
//
// Sub, Next, and Skip all measure from the current position. Only Seek and
// SubAt use absolute offsets.
func (c *Cursor) Sub(off, n int) *Cursor {
	if c.err != nil {
		return c.dead(c.err)
	}
	if off < 0 {
		err := &BoundsError{Op: "sub", Off: c.Pos(), Need: int64(n), Have: int64(c.Len())}
		c.Fail(err)
		return c.dead(err)
	}
	return c.SubAt(c.off+off, n)
}

// SubAt returns a cursor over n bytes at an absolute offset within this
// cursor's data, without advancing this cursor.
func (c *Cursor) SubAt(off, n int) *Cursor {
	if c.err != nil {
		return c.dead(c.err)
	}
	if off < 0 || n < 0 || off > len(c.b) || n > len(c.b)-off {
		have := int64(0)
		if off >= 0 && off <= len(c.b) {
			have = int64(len(c.b) - off)
		}
		err := &BoundsError{Op: "sub", Off: c.base + int64(off), Need: int64(n), Have: have}
		c.Fail(err)
		return c.dead(err)
	}
	return &Cursor{b: c.b[off : off+n], base: c.base + int64(off), ord: c.ord}
}

// Next consumes n bytes and returns a cursor over them.
func (c *Cursor) Next(n int) *Cursor {
	start := c.off
	if _, ok := c.take("next", n); !ok {
		return c.dead(c.err)
	}
	return &Cursor{b: c.b[start : start+n], base: c.base + int64(start), ord: c.ord}
}

// Table consumes count entries of stride bytes and returns a cursor over them.
// The multiplication is checked before it is performed, so a header declaring
// an absurd entry count fails with a CountError naming the declared count
// rather than wrapping around into a plausible-looking small read.
func (c *Cursor) Table(count uint64, stride int) (*Cursor, error) {
	if c.err != nil {
		return c.dead(c.err), c.err
	}
	if stride <= 0 {
		err := fmt.Errorf("binio: table stride %d is not positive", stride)
		c.Fail(err)
		return c.dead(err), err
	}
	avail := int64(c.Len())
	if count > uint64(maxInt)/uint64(stride) {
		err := &CountError{Off: c.Pos(), Count: count, Stride: stride, Have: avail}
		c.Fail(err)
		return c.dead(err), err
	}
	need := int64(count) * int64(stride)
	if need > avail {
		err := &CountError{Off: c.Pos(), Count: count, Stride: stride, Have: avail}
		c.Fail(err)
		return c.dead(err), err
	}
	return c.Next(int(need)), nil
}