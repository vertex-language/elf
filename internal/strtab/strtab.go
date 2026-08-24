// Package strtab builds deduplicating ELF string tables with tail sharing.
//
// Two savings compound here. Identical strings are stored once, which Add
// handles by returning the same Ref. And a string that is a suffix of another
// needs no storage at all: "printf" ends with "f", so a table holding both
// stores "printf\0" and points "f" at its last two bytes. Real symbol tables
// are full of such pairs.
package strtab

import (
	"fmt"
	"math"
	"sort"
)

// Builder accumulates strings and lays them out on Finish.
//
// Offsets are unknown until then, so Add hands back a Ref rather than a
// number, and reading a Ref early panics rather than returning a plausible
// zero.
type Builder struct {
	lead     int // bytes of NUL padding before the first string
	order    []string
	refs     map[string]*Ref
	finished bool
}

// New returns a Builder whose first string sits at offset 0.
func New() *Builder { return newBuilder(0) }

// NewELF returns a Builder with a single leading NUL, so that offset 0 is the
// empty string. Every ELF string table is built this way: sh_name or st_name
// of 0 means "no name", which only works if byte 0 is a terminator.
func NewELF() *Builder { return newBuilder(1) }

func newBuilder(lead int) *Builder {
	return &Builder{lead: lead, refs: make(map[string]*Ref)}
}

// Ref is a handle to a string's eventual position in the table.
type Ref struct {
	s     string
	off   uint32
	bound bool
}

// String returns the string this Ref names.
func (r *Ref) String() string { return r.s }

// Offset returns the string's byte offset. It panics if called before Finish,
// because there is no correct answer yet and a zero would be silently wrong.
func (r *Ref) Offset() uint32 {
	if !r.bound {
		panic("strtab: Ref.Offset read before Finish")
	}
	return r.off
}

// Add records a string and returns a handle to it. Adding the same string
// twice returns the same handle. It panics if called after Finish.
func (b *Builder) Add(s string) *Ref {
	if b.finished {
		panic("strtab: Add after Finish")
	}
	if r, ok := b.refs[s]; ok {
		return r
	}
	r := &Ref{s: s}
	b.refs[s] = r
	b.order = append(b.order, s)
	return r
}

// Len returns the number of distinct strings added.
func (b *Builder) Len() int { return len(b.order) }

// Finish lays out the table and binds every Ref. It may be called once.
func (b *Builder) Finish() []byte {
	if b.finished {
		panic("strtab: Finish called twice")
	}
	b.finished = true

	// Sorting by reversed content, descending, puts every string immediately
	// after the strings it is a suffix of, longest first.
	uniq := make([]string, len(b.order))
	copy(uniq, b.order)
	sort.Slice(uniq, func(i, j int) bool {
		return lessReversed(uniq[j], uniq[i])
	})

	blob := make([]byte, b.lead)
	var lastOff uint32
	var lastStr string
	haveLast := false

	for _, s := range uniq {
		r := b.refs[s]
		if haveLast && isSuffixOf(lastStr, s) {
			r.off = lastOff + uint32(len(lastStr)-len(s))
			r.bound = true
			// Deliberately not updating lastStr: the next string must be
			// compared against the last one actually emitted, not against
			// this shared tail. That is what lets a chain collapse —
			// "abc", "bc", "c" land at 0, 1, 2 rather than only the first
			// pair sharing.
			continue
		}
		if len(blob) > math.MaxUint32 {
			panic(fmt.Sprintf("strtab: table exceeds %d bytes; offsets do not fit sh_name",
				uint32(math.MaxUint32)))
		}
		r.off = uint32(len(blob))
		r.bound = true
		blob = append(blob, s...)
		blob = append(blob, 0)
		lastOff, lastStr, haveLast = r.off, s, true
	}
	if len(blob) > math.MaxUint32 {
		panic("strtab: table exceeds the 32-bit offset space")
	}
	return blob
}

// lessReversed compares two strings by their bytes read back to front.
func lessReversed(a, b string) bool {
	for i := 1; i <= len(a) && i <= len(b); i++ {
		ca, cb := a[len(a)-i], b[len(b)-i]
		if ca != cb {
			return ca < cb
		}
	}
	return len(a) < len(b)
}

// isSuffixOf reports whether short is a suffix of long.
func isSuffixOf(long, short string) bool {
	return len(short) <= len(long) && long[len(long)-len(short):] == short
}