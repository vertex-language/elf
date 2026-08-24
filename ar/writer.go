package ar

import (
	"encoding/binary"
	"fmt"
	"io"
	"strconv"

	"github.com/vertex-language/elf/internal/binio"
)

// Options configures a Writer.
type Options struct {
	// Thin writes a GNU thin archive: headers and an index, with member
	// contents left in the files they came from.
	Thin bool

	// Deterministic zeroes the timestamp, uid, and gid, and writes a fixed
	// mode, so that archiving the same inputs twice produces identical bytes.
	// This is what reproducible builds require and what `ar -D` does.
	Deterministic bool
}

// deterministicMode is the file mode written in deterministic mode, matching
// what GNU ar emits.
const deterministicMode = 0o644

// Input is a member to add.
type Input struct {
	Name string

	// Data is the member's contents. Ignored for a thin archive, where only
	// Name is recorded.
	Data []byte

	// Symbols are the names this member defines, which go into the archive's
	// symbol index. Leaving it empty omits the member from the index, making
	// it invisible to a linker resolving by symbol.
	//
	// The caller supplies these rather than this package extracting them:
	// ar has no business knowing what an ELF object is, and archives hold
	// things other than ELF objects.
	Symbols []string

	ModTime int64
	UID     int
	GID     int
	Mode    uint32
}

// Writer builds an archive. Nothing is written until Close.
type Writer struct {
	w    io.Writer
	opts Options

	members []Input
	err     error
	done    bool
}

// NewWriter returns a Writer that emits to w on Close.
func NewWriter(w io.Writer, opts Options) *Writer {
	return &Writer{w: w, opts: opts}
}

// Add records a member.
func (aw *Writer) Add(m Input) {
	if m.Name == "" {
		aw.fail(fmt.Errorf("ar: member with no name"))
		return
	}
	aw.members = append(aw.members, m)
}

// Err returns the first error latched, or nil.
func (aw *Writer) Err() error { return aw.err }

func (aw *Writer) fail(err error) {
	if aw.err == nil && err != nil {
		aw.err = err
	}
}

// Close lays out and writes the archive. It may be called once.
func (aw *Writer) Close() error {
	if aw.done {
		return fmt.Errorf("ar: Close called twice")
	}
	aw.done = true
	if aw.err != nil {
		return aw.err
	}
	return aw.layout()
}

// nameEncoding decides how each member's name is written and builds the "//"
// string table.
//
// A name of 15 bytes or fewer goes in the header directly, terminated by "/".
// Longer names go in the string table and are referenced by decimal offset.
// Thin archives put every name in the table: their names are paths, and the
// consistency is what GNU produces.
func (aw *Writer) nameEncoding() (fields []string, table *binio.Buf) {
	table = binio.NewBuf(binary.LittleEndian) // byte appends only; order unused
	fields = make([]string, len(aw.members))

	for i, m := range aw.members {
		inTable := len(m.Name) > 15 || aw.opts.Thin
		if !inTable {
			fields[i] = m.Name + "/"
			continue
		}
		fields[i] = "/" + strconv.Itoa(table.Len())
		table.WriteString(m.Name)
		table.WriteString(longNameTerm)
	}
	return fields, table
}

// collectSymbols gathers index entries and, for each, the member that defines
// it. Order follows member order, which is what linkers expect.
func (aw *Writer) collectSymbols() (entries []IndexEntry, owner []int) {
	for i, m := range aw.members {
		for _, s := range m.Symbols {
			entries = append(entries, IndexEntry{Name: s})
			owner = append(owner, i)
		}
	}
	return entries, owner
}

func (aw *Writer) layout() error {
	syms, owner := aw.collectSymbols()
	nameFields, table := aw.nameEncoding()

	magic := Magic
	if aw.opts.Thin {
		magic = MagicThin
	}

	// Offsets and index width are mutually dependent: widening the index to
	// /SYM64/ grows the index member, which pushes every member offset
	// further out. Compute offsets at 32 bits, and if any member lands past
	// 4 GiB, redo them at 64. The second pass can only grow offsets, and a
	// 64-bit index cannot overflow, so two passes always suffice.
	offsets := make([]int64, len(aw.members))
	wide := false
	for {
		off := int64(len(magic))
		if len(syms) > 0 {
			off += HeaderSize + indexSize(syms, wide)
			off += off % 2
		}
		if table.Len() > 0 {
			off += HeaderSize + int64(table.Len())
			off += off % 2
		}

		overflow := false
		for i, m := range aw.members {
			offsets[i] = off
			if off > 0xFFFFFFFF {
				overflow = true
			}
			off += HeaderSize
			if !aw.opts.Thin {
				off += int64(len(m.Data))
			}
			off += off % 2
		}
		if overflow && !wide {
			wide = true
			continue
		}
		break
	}
	for i := range syms {
		syms[i].HeaderOffset = offsets[owner[i]]
	}

	out := binio.NewBuf(binary.LittleEndian) // byte appends only; order unused
	out.WriteString(magic)

	if len(syms) > 0 {
		blob := encodeIndex(syms, wide)
		name := nameSymbolIndex
		if wide {
			name = nameSymbolIndex64
		}
		if err := writeHeader(out, name, 0, 0, 0, 0, int64(len(blob))); err != nil {
			return err
		}
		out.Write(blob)
		padOdd(out)
	}

	if table.Len() > 0 {
		if err := writeHeader(out, nameStringTable, 0, 0, 0, 0, int64(table.Len())); err != nil {
			return err
		}
		out.Write(table.Bytes())
		padOdd(out)
	}

	for i := range aw.members {
		m := &aw.members[i]
		if int64(out.Len()) != offsets[i] {
			return fmt.Errorf("ar: internal: member %q at %#x, layout predicted %#x",
				m.Name, out.Len(), offsets[i])
		}

		mtime, uid, gid, mode := m.ModTime, m.UID, m.GID, m.Mode
		if aw.opts.Deterministic {
			mtime, uid, gid, mode = 0, 0, 0, deterministicMode
		}

		// A thin member's header records the size of the external file even
		// though no bytes follow it.
		if err := writeHeader(out, nameFields[i], mtime, uid, gid, mode, int64(len(m.Data))); err != nil {
			return fmt.Errorf("ar: member %q: %w", m.Name, err)
		}
		if !aw.opts.Thin {
			out.Write(m.Data)
		}
		padOdd(out)
	}

	_, err := out.WriteTo(aw.w)
	return err
}