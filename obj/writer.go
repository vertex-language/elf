package obj

import (
	"fmt"
	"io"

	"github.com/vertex-language/elf"
	"github.com/vertex-language/elf/internal/binio"
)

// Options configures a Writer.
type Options struct {
	// Target determines the class, byte order, e_machine, and e_flags of the
	// output. It is a Target rather than a loose triple of Class, Data, and
	// Machine because those three can contradict each other and a Target
	// cannot.
	Target elf.Target

	// ABIVersion is e_ident[EI_ABIVERSION]. Zero for everything current.
	ABIVersion uint8

	// GNUStack selects the .note.GNU-stack section. The zero value emits a
	// non-executable declaration, which is the safe default: omitting the
	// section makes the kernel assume the stack should be executable.
	GNUStack elf.GNUStack

	// RelocFormat chooses REL or RELA. The zero value picks whichever the
	// target's psABI uses.
	RelocFormat elf.RelocFormat

	// RELEncoder writes implicit addends into section contents. Required when
	// the resolved format is REL, and unused otherwise.
	//
	// It exists because an implicit addend is not simply a word at the
	// relocation offset: on ARM an R_ARM_CALL addend lives in a 24-bit
	// immediate inside the instruction. Writing four raw bytes there corrupts
	// the code. The backend for the target supplies this; without one, Close
	// on a REL target fails rather than emitting a broken object.
	RELEncoder RELEncoder
}

// RELEncoder deposits an addend into section contents for a REL relocation.
//
// content is the target section's bytes, off the relocation offset within it.
// Implementations must not resize content.
type RELEncoder interface {
	EncodeAddend(content []byte, off uint64, relocType uint32, addend int64) error
}

// Writer builds a relocatable object.
//
// Sections, symbols, relocations, and groups are declared in any order and
// resolved against each other by Close, which assigns section and symbol
// indexes, builds the string tables, and emits the file. Nothing is written to
// the underlying io.Writer until then.
type Writer struct {
	w    io.Writer
	opts Options

	sections []*SectionBuilder
	symbols  []*symbol
	groups   []*group

	err  error
	done bool
}

// NewWriter returns a Writer that will emit to w on Close.
func NewWriter(w io.Writer, opts Options) *Writer {
	wr := &Writer{w: w, opts: opts}
	if !opts.Target.Valid() {
		wr.fail(fmt.Errorf("obj: %w: %v", elf.ErrInvalidTarget, opts.Target))
	}
	return wr
}

// Err returns the first error the Writer latched, or nil. Builder methods do
// not return errors individually; they record and continue, so a construction
// sequence reads without error checks and Close reports the first failure.
func (wr *Writer) Err() error { return wr.err }

func (wr *Writer) fail(err error) {
	if wr.err == nil && err != nil {
		wr.err = err
	}
}

func (wr *Writer) class() elf.Class { return wr.opts.Target.Class }

// SectionHeader describes a section to create.
type SectionHeader struct {
	Name      string
	Type      elf.SHType
	Flags     uint64
	Addralign uint64
	Entsize   uint64

	// Size is used only for SHT_NOBITS sections, which occupy memory but no
	// file space and so have no contents to write. It is ignored otherwise.
	Size uint64
}

// SectionBuilder is a section under construction.
//
// It is a distinct type from the read side's Section: a builder holds contents
// and an as-yet-unassigned index, a Section holds a file position and a fixed
// one. Nothing accepts both.
type SectionBuilder struct {
	Name      string
	Type      elf.SHType
	Flags     uint64
	Addralign uint64
	Entsize   uint64

	// LinkTo sets sh_link to another section's index. Leave nil to use Link.
	LinkTo *SectionBuilder

	// InfoSection sets sh_info to another section's index. Leave nil to use
	// Info.
	InfoSection *SectionBuilder

	// Link and Info are the raw header fields, used when the pointer forms
	// above are nil. The Writer overwrites them on the sections it creates
	// itself.
	Link uint32
	Info uint32

	buf     *binio.Buf
	nobits  uint64
	relocs  []RelocSpec
	index   uint32 // final section index, assigned by Close
	indexed bool
}

// Section creates a section and returns a handle for writing its contents.
func (wr *Writer) Section(hdr SectionHeader) *SectionBuilder {
	s := &SectionBuilder{
		Name:      hdr.Name,
		Type:      hdr.Type,
		Flags:     hdr.Flags,
		Addralign: hdr.Addralign,
		Entsize:   hdr.Entsize,
		nobits:    hdr.Size,
		buf:       binio.NewBuf(byteOrder(wr.opts.Target)),
	}
	wr.sections = append(wr.sections, s)
	return s
}

// Write appends to the section's contents. Writing to an SHT_NOBITS section is
// an error: such a section occupies no file space, so the bytes would be
// silently discarded.
func (s *SectionBuilder) Write(p []byte) (int, error) {
	if s.Type == elf.SHT_NOBITS {
		return 0, fmt.Errorf("obj: Write to %q, which is SHT_NOBITS and holds no contents", s.Name)
	}
	return s.buf.Write(p)
}

// WriteString appends a string to the section's contents.
func (s *SectionBuilder) WriteString(str string) (int, error) {
	if s.Type == elf.SHT_NOBITS {
		return 0, fmt.Errorf("obj: WriteString to %q, which is SHT_NOBITS", s.Name)
	}
	return s.buf.WriteString(str)
}

// WriteByte appends one byte to the section's contents.
func (s *SectionBuilder) WriteByte(b byte) error {
	if s.Type == elf.SHT_NOBITS {
		return fmt.Errorf("obj: WriteByte to %q, which is SHT_NOBITS", s.Name)
	}
	return s.buf.WriteByte(b)
}

// Zero appends n zero bytes.
func (s *SectionBuilder) Zero(n int) { s.buf.Zero(n) }

// Align zero-pads the contents to a multiple of n.
func (s *SectionBuilder) Align(n int) { s.buf.Align(n) }

// Len returns the number of content bytes written so far.
func (s *SectionBuilder) Len() int { return s.buf.Len() }

// Buf exposes the underlying buffer, for callers that need patching or the
// LEB128 writers. Resizing it after a relocation has been recorded against a
// later offset is the caller's problem.
func (s *SectionBuilder) Buf() *binio.Buf { return s.buf }

// Index returns the section's final index. Valid only after Close.
func (s *SectionBuilder) Index() uint32 {
	if !s.indexed {
		panic("obj: SectionBuilder.Index read before Close")
	}
	return s.index
}

// contentSize is the sh_size to write: the declared size for SHT_NOBITS, the
// buffer length otherwise.
func (s *SectionBuilder) contentSize() uint64 {
	if s.Type == elf.SHT_NOBITS {
		return s.nobits
	}
	return uint64(s.buf.Len())
}

// Placement says what a symbol's section index means.
type Placement uint8

const (
	// SymUndefined is a reference with no definition in this object.
	SymUndefined Placement = iota

	// SymInSection is a definition at an offset within a section.
	SymInSection

	// SymAbsolute is a value not subject to relocation.
	SymAbsolute

	// SymCommon is an unallocated common block. Value holds an alignment
	// rather than an offset, and Size the number of bytes required.
	SymCommon
)

// SymbolDef describes a symbol to create.
type SymbolDef struct {
	Name  string
	Value uint64
	Size  uint64
	Bind  elf.SymBind
	Type  elf.SymType

	// Other is the raw st_other byte. Use elf.WithVisibility to set the
	// visibility field without disturbing psABI-specific bits above it.
	Other uint8

	// Where defaults to SymUndefined. When Section is non-nil and Where is
	// left at its zero value it is taken as SymInSection; any other
	// combination of the two is an error.
	Where   Placement
	Section *SectionBuilder
}

type symbol struct {
	def   SymbolDef
	index uint32
}

// SymRef is a handle to a declared symbol. The zero SymRef refers to symbol
// index 0, the undefined symbol, which is what a relocation against no symbol
// should name.
type SymRef struct{ s *symbol }

// Valid reports whether the reference names a declared symbol.
func (r SymRef) Valid() bool { return r.s != nil }

// Name returns the symbol's name, or the empty string for the zero SymRef.
func (r SymRef) Name() string {
	if r.s == nil {
		return ""
	}
	return r.s.def.Name
}

// Index returns the symbol's final symbol table index. Valid only after Close;
// the zero SymRef always returns 0.
func (r SymRef) Index() uint32 {
	if r.s == nil {
		return 0
	}
	return r.s.index
}

// Symbol declares a symbol and returns a handle to it.
func (wr *Writer) Symbol(def SymbolDef) SymRef {
	if def.Section != nil && def.Where == SymUndefined {
		def.Where = SymInSection
	}
	switch def.Where {
	case SymInSection:
		if def.Section == nil {
			wr.fail(fmt.Errorf("obj: symbol %q is SymInSection with no section", def.Name))
		}
	default:
		if def.Section != nil {
			wr.fail(fmt.Errorf("obj: symbol %q names a section but is placed %v", def.Name, def.Where))
		}
	}

	s := &symbol{def: def}
	wr.symbols = append(wr.symbols, s)
	return SymRef{s: s}
}

func (p Placement) String() string {
	switch p {
	case SymInSection:
		return "in-section"
	case SymAbsolute:
		return "absolute"
	case SymCommon:
		return "common"
	}
	return "undefined"
}

// RelocSpec describes a relocation to emit.
//
// Addend is written explicitly for RELA targets and deposited into the target
// section's contents by the RELEncoder for REL targets.
type RelocSpec struct {
	Offset uint64
	Sym    SymRef
	Type   uint32
	Addend int64
}

// Reloc records a relocation against a section.
func (wr *Writer) Reloc(sec *SectionBuilder, r RelocSpec) {
	if sec == nil {
		wr.fail(fmt.Errorf("obj: Reloc on a nil section"))
		return
	}
	sec.relocs = append(sec.relocs, r)
}

type group struct {
	sec       *SectionBuilder
	signature SymRef
	flags     uint32
	members   []*SectionBuilder
}

// Group creates an SHT_GROUP section covering members.
//
// For a COMDAT group pass elf.GRP_COMDAT as flags; the signature symbol's name
// becomes the deduplication key, and the linker keeps one group per key across
// all inputs. Every member has SHF_GROUP set.
func (wr *Writer) Group(signature SymRef, flags uint32, members ...*SectionBuilder) *SectionBuilder {
	sec := wr.Section(SectionHeader{
		Name:      ".group",
		Type:      elf.SHT_GROUP,
		Addralign: 4,
		Entsize:   4,
	})
	for _, m := range members {
		if m == nil {
			wr.fail(fmt.Errorf("obj: nil member in group signed by %q", signature.Name()))
			continue
		}
		m.Flags |= elf.SHF_GROUP
	}
	wr.groups = append(wr.groups, &group{
		sec:       sec,
		signature: signature,
		flags:     flags,
		members:   members,
	})
	return sec
}