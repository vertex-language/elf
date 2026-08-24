package ar

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/vertex-language/elf/internal/binio"
)

// Reader is a parsed archive.
//
// Parsing walks the member headers, decodes the symbol index and string table
// if present, and resolves member names. Member contents are not read.
type Reader struct {
	// Thin reports whether this is a GNU thin archive, whose members name
	// files on disk rather than carrying their contents.
	Thin bool

	// Members are the regular members in archive order. The special members
	// "/", "//", and "/SYM64/" are consumed during parsing and do not appear
	// here.
	Members []*Member

	// Index is the symbol index, or nil if the archive has none. An archive
	// without an index is valid; a linker must then scan every member.
	Index []IndexEntry

	bf     *binio.File
	closer io.Closer
}

// Member describes one archive member.
type Member struct {
	Name string

	// HeaderOffset is the file offset of this member's header. Symbol index
	// entries point here.
	HeaderOffset int64

	// Size is the member's content length in bytes. For a thin member this is
	// the size the external file had when the archive was built, which may no
	// longer be true.
	Size int64

	ModTime int64
	UID     int
	GID     int
	Mode    uint32

	thin bool
	ext  binio.Extent
}

// Thin reports whether this member's contents live outside the archive.
func (m *Member) Thin() bool { return m.thin }

// Data reads the member's contents.
//
// Thin members return ErrThinMember: their bytes are in the file named by
// Name, which only the caller knows how to locate relative to the archive.
func (m *Member) Data() ([]byte, error) {
	if m.thin {
		return nil, fmt.Errorf("ar: member %q: %w", m.Name, ErrThinMember)
	}
	return m.ext.Data()
}

// Open returns a reader over the member's contents without loading them.
func (m *Member) Open() (*io.SectionReader, error) {
	if m.thin {
		return nil, fmt.Errorf("ar: member %q: %w", m.Name, ErrThinMember)
	}
	return m.ext.Open(), nil
}

// NewReader parses the archive in r.
func NewReader(r io.ReaderAt) (*Reader, error) {
	bf, err := binio.Open(r)
	if err != nil {
		return nil, err
	}
	return newReader(bf, nil)
}

// Open parses the named archive. The caller must Close the result.
func Open(name string) (*Reader, error) {
	fh, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	bf, err := binio.Open(fh)
	if err != nil {
		fh.Close()
		return nil, err
	}
	rd, err := newReader(bf, fh)
	if err != nil {
		fh.Close()
		return nil, err
	}
	return rd, nil
}

// Close releases the underlying file, if this Reader opened one.
func (r *Reader) Close() error {
	if r.closer != nil {
		return r.closer.Close()
	}
	return nil
}

// Is reports whether head begins with either archive magic. It needs
// MagicSize bytes.
func Is(head []byte) bool {
	if len(head) < MagicSize {
		return false
	}
	s := string(head[:MagicSize])
	return s == Magic || s == MagicThin
}

func newReader(bf *binio.File, closer io.Closer) (*Reader, error) {
	head, err := bf.Head(MagicSize)
	if err != nil {
		return nil, err
	}
	if len(head) < MagicSize {
		return nil, ErrNotArchive
	}

	r := &Reader{bf: bf, closer: closer}
	switch string(head) {
	case Magic:
	case MagicThin:
		r.Thin = true
	default:
		return nil, ErrNotArchive
	}

	// Name resolution is deferred to a second pass. The string table normally
	// precedes the members that reference it, but nothing enforces that, and
	// resolving as we go would fail on an archive that puts "//" last.
	type pending struct {
		m   *Member
		raw string
	}
	var members []pending
	var longNames []byte
	var idxData []byte
	var idxWide bool

	off := int64(MagicSize)
	for off < bf.Size() {
		if off%2 != 0 {
			// A member ended at an odd offset; the 0x0A filler puts the next
			// header on an even one.
			off++
			continue
		}
		if bf.Size()-off < HeaderSize {
			// Trailing bytes too short to be a header. Archives padded at the
			// end are common enough that this is not an error.
			break
		}

		hExt, err := bf.At(off, HeaderSize)
		if err != nil {
			return nil, err
		}
		hb, err := hExt.Data()
		if err != nil {
			return nil, err
		}
		h, err := parseHeader(hb, off)
		if err != nil {
			return nil, err
		}

		if isBSDLongName(h.rawName) || h.rawName == nameBSDSymbolDef {
			return nil, fmt.Errorf("ar: member at %#x uses BSD conventions: %w", off, ErrBSDArchive)
		}

		dataOff := off + HeaderSize

		switch h.rawName {
		case nameStringTable:
			longNames, err = readAt(bf, dataOff, h.size)
			if err != nil {
				return nil, fmt.Errorf("ar: reading the string table: %w", err)
			}

		case nameSymbolIndex, nameSymbolIndex64:
			idxData, err = readAt(bf, dataOff, h.size)
			if err != nil {
				return nil, fmt.Errorf("ar: reading the symbol index: %w", err)
			}
			idxWide = h.rawName == nameSymbolIndex64

		default:
			m := &Member{
				HeaderOffset: off,
				Size:         h.size,
				ModTime:      h.mtime,
				UID:          h.uid,
				GID:          h.gid,
				Mode:         h.mode,
				thin:         r.Thin,
			}
			if !r.Thin {
				m.ext, err = bf.At(dataOff, h.size)
				if err != nil {
					return nil, fmt.Errorf("ar: member at %#x: %w", off, err)
				}
			}
			members = append(members, pending{m: m, raw: h.rawName})
			r.Members = append(r.Members, m)
		}

		// A thin archive's regular members carry no data, so the next header
		// follows immediately. Its special members do carry data.
		consumed := h.size
		if r.Thin && !isSpecialName(h.rawName) {
			consumed = 0
		}
		next := dataOff + consumed
		if next <= off {
			return nil, fmt.Errorf("ar: member at %#x does not advance: %w", off, ErrBadHeader)
		}
		off = next
	}

	for _, p := range members {
		name, err := resolveName(p.raw, longNames)
		if err != nil {
			return nil, fmt.Errorf("ar: member at %#x: %w", p.m.HeaderOffset, err)
		}
		p.m.Name = name
	}

	if idxData != nil {
		r.Index, err = decodeIndex(idxData, idxWide)
		if err != nil {
			return nil, err
		}
	}
	return r, nil
}

func isSpecialName(raw string) bool {
	return raw == nameStringTable || raw == nameSymbolIndex || raw == nameSymbolIndex64
}

func readAt(bf *binio.File, off, n int64) ([]byte, error) {
	ext, err := bf.At(off, n)
	if err != nil {
		return nil, err
	}
	return ext.Data()
}

// resolveName turns a raw name field into a member name.
//
// A name of the form "/768" indexes the string table. Anything else is a
// literal name with its "/" terminator removed — trimmed only once and only
// at the end, so a member legitimately named "a/b" keeps its slash.
func resolveName(raw string, longNames []byte) (string, error) {
	if len(raw) > 1 && raw[0] == '/' && raw[1] >= '0' && raw[1] <= '9' {
		off, err := strconv.ParseUint(raw[1:], 10, 63)
		if err != nil {
			return "", fmt.Errorf("bad string table reference %q: %w", raw, ErrBadHeader)
		}
		if off >= uint64(len(longNames)) {
			return "", fmt.Errorf("string table reference %q is past the %d-byte table: %w",
				raw, len(longNames), ErrBadHeader)
		}
		rest := longNames[off:]
		if i := strings.Index(string(rest), longNameTerm); i >= 0 {
			return string(rest[:i]), nil
		}
		// Tolerate a final entry missing its terminator, which some producers
		// emit, but stop at a newline or NUL if either is present.
		end := len(rest)
		for i, c := range rest {
			if c == '\n' || c == 0 {
				end = i
				break
			}
		}
		return strings.TrimSuffix(string(rest[:end]), "/"), nil
	}
	return strings.TrimSuffix(raw, "/"), nil
}

// Member returns the first member with the given name, or nil. Archives may
// contain several members with the same name; use Members when that matters.
func (r *Reader) Member(name string) *Member {
	for _, m := range r.Members {
		if m.Name == name {
			return m
		}
	}
	return nil
}

// MemberAt returns the member whose header begins at off, or nil. Symbol index
// entries carry exactly this offset.
func (r *Reader) MemberAt(off int64) *Member {
	for _, m := range r.Members {
		if m.HeaderOffset == off {
			return m
		}
	}
	return nil
}