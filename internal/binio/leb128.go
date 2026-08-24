package binio

// LEB128, as specified by DWARF and used by CREL, .eh_frame, .gnu.version, and
// the .debug_* sections.
//
// A value is a sequence of bytes, least-significant 7-bit group first, with the
// high bit set on every byte but the last. The signed form sign-extends from
// bit 6 of the terminating byte.
//
// The decoders here accept non-canonical encodings — 0x80 0x00 is a valid, if
// wasteful, zero — because producers emit them (fixed-width padded LEBs are a
// standard backpatching trick, see ULEBPad). They reject values that do not fit
// 64 bits, with the same bounds LLVM's decodeULEB128/decodeSLEB128 use.

// ULEB reads an unsigned LEB128 value.
//
// Two failure modes, both latched: running off the end (BoundsError) and a
// value wider than 64 bits (LEBError). Trailing all-zero continuation bytes past
// bit 64 are accepted, since they carry no information.
func (c *Cursor) ULEB() uint64 {
	if c.err != nil {
		return 0
	}
	start := c.off
	var v uint64
	var shift uint
	for {
		if c.off >= len(c.b) {
			c.Fail(&BoundsError{
				Op:   "uleb",
				Off:  c.base + int64(start),
				Need: int64(c.off-start) + 1,
				Have: int64(c.off - start),
			})
			c.off = len(c.b)
			return 0
		}
		b := c.b[c.off]
		c.off++
		slice := uint64(b & 0x7f)

		// At shift 63 exactly one payload bit still fits, so the slice must be
		// 0 or 1. Past 63, nothing fits and the slice must be zero padding.
		if shift >= 63 {
			if (shift == 63 && slice > 1) || (shift > 63 && slice != 0) {
				c.Fail(&LEBError{Op: "uleb", Off: c.base + int64(start)})
				return 0
			}
		}
		if shift < 64 {
			v |= slice << shift
		}
		shift += 7

		if b&0x80 == 0 {
			return v
		}
	}
}

// SLEB reads a signed LEB128 value.
func (c *Cursor) SLEB() int64 {
	if c.err != nil {
		return 0
	}
	start := c.off
	var v uint64
	var shift uint
	var b byte
	for {
		if c.off >= len(c.b) {
			c.Fail(&BoundsError{
				Op:   "sleb",
				Off:  c.base + int64(start),
				Need: int64(c.off-start) + 1,
				Have: int64(c.off - start),
			})
			c.off = len(c.b)
			return 0
		}
		b = c.b[c.off]
		c.off++
		slice := uint64(b & 0x7f)

		// At shift 63 the slice is either the last value bit (0) or pure sign
		// extension (0x7f). Past 63 it must agree with the sign accumulated so
		// far.
		if shift >= 63 {
			want := uint64(0x00)
			if v&(1<<63) != 0 {
				want = 0x7f
			}
			if (shift == 63 && slice != 0 && slice != 0x7f) ||
				(shift > 63 && slice != want) {
				c.Fail(&LEBError{Op: "sleb", Off: c.base + int64(start)})
				return 0
			}
		}
		if shift < 64 {
			v |= slice << shift
		}
		shift += 7

		if b&0x80 == 0 {
			break
		}
	}
	if shift < 64 && b&0x40 != 0 {
		v |= ^uint64(0) << shift
	}
	return int64(v)
}

// ULEB appends an unsigned LEB128 value.
func (w *Buf) ULEB(v uint64) {
	for {
		b := byte(v & 0x7f)
		v >>= 7
		if v == 0 {
			w.b = append(w.b, b)
			return
		}
		w.b = append(w.b, b|0x80)
	}
}

// SLEB appends a signed LEB128 value.
func (w *Buf) SLEB(v int64) {
	for {
		b := byte(v & 0x7f)
		v >>= 7 // arithmetic shift: Go guarantees this for signed types
		signBit := b&0x40 != 0
		if (v == 0 && !signBit) || (v == -1 && signBit) {
			w.b = append(w.b, b)
			return
		}
		w.b = append(w.b, b|0x80)
	}
}

// ULEBPad appends an unsigned LEB128 value padded to exactly n bytes, so that
// the encoding can be overwritten later with any value of the same or smaller
// magnitude without moving the bytes after it. If the natural encoding is
// longer than n, it is emitted at its natural length. n <= 0 means no padding.
func (w *Buf) ULEBPad(v uint64, n int) {
	count := 0
	for {
		b := byte(v & 0x7f)
		v >>= 7
		count++
		if v != 0 || count < n {
			b |= 0x80
		}
		w.b = append(w.b, b)
		if v == 0 {
			break
		}
	}
	for ; count < n-1; count++ {
		w.b = append(w.b, 0x80)
	}
	if count < n {
		w.b = append(w.b, 0x00)
	}
}

// ULEBSize reports the number of bytes ULEB would append for v.
func ULEBSize(v uint64) int {
	n := 1
	for v >= 0x80 {
		v >>= 7
		n++
	}
	return n
}

// SLEBSize reports the number of bytes SLEB would append for v.
func SLEBSize(v int64) int {
	n := 0
	for {
		b := byte(v & 0x7f)
		v >>= 7
		n++
		signBit := b&0x40 != 0
		if (v == 0 && !signBit) || (v == -1 && signBit) {
			return n
		}
	}
}