package image

import (
	"fmt"

	"github.com/vertex-language/elf"
)

// ChunkSource supplies a chunk's contents and relocations on demand.
//
// One interface, not a raw byte slice plus a loader function: input sections,
// merged blobs, and backend-generated tables all provide the same two things,
// and giving them one shape keeps `any` out of the core model.
//
// Implementations must be safe to call more than once, though Chunk caches the
// result so that the layout fixpoint does not re-read a file on every
// iteration.
type ChunkSource interface {
	Bytes() ([]byte, error)
	Relocs() ([]Reloc, error)
}

// Input is one file's contribution to the link.
type Input struct {
	// Name is what error messages call this file: a path, or
	// "libc.a(printf.o)" for an archive member.
	Name string

	// Ordinal is the file's position on the link line. Symbol resolution and
	// tie-breaking are defined in terms of it, so it must reflect command
	// order rather than the order files happened to be parsed in.
	Ordinal int

	// Target is what this file says it is. link checks it against the image's
	// target; see link.ErrMachineMismatch.
	Target elf.Target

	// Chunks are the file's contributions, in input section order.
	Chunks []*Chunk

	// Syms maps this file's symbol table indexes to global symbols, entry
	// zero included. A relocation naming index n refers to Syms[n]; an entry
	// is nil when the index named nothing.
	Syms []*Sym

	// Shared reports whether this input is a dependency shared object rather
	// than an object file. Its chunks are never placed; it contributes
	// definitions only.
	Shared bool

	// SOName is DT_SONAME for a shared input, which is what DT_NEEDED in the
	// output must name — not the path the file was found at.
	SOName string
}

// AddChunk appends a chunk and back-links it to this input.
func (in *Input) AddChunk(ch *Chunk) {
	ch.Input = in
	in.Chunks = append(in.Chunks, ch)
}

// SymAt returns the symbol at this input's table index, or nil.
func (in *Input) SymAt(i uint32) *Sym {
	if uint64(i) >= uint64(len(in.Syms)) {
		return nil
	}
	return in.Syms[i]
}

func (in *Input) String() string { return in.Name }

// Chunk is one contribution to the output: an input section, a fragment
// collection, or a linker-generated table.
//
// Size is a field rather than the length of the contents because synthetic
// chunks are laid out before they exist. A .got is sized during scan, when the
// number of entries is known, and generated after addresses are final, when the
// entries can be filled in. An input chunk's Size comes from sh_size.
type Chunk struct {
	Name  string
	Type  elf.SHType
	Flags SecFlags

	// Align is the chunk's required alignment, never less than 1.
	Align uint64

	// Size is the chunk's length in bytes.
	Size uint64

	// Entsize is sh_entsize, which for a mergeable section is the fixed
	// record width the splitter uses.
	Entsize uint64

	// Input is the file this came from, or nil for a synthetic chunk.
	Input *Input

	// Index is the chunk's section index in its input file, for diagnostics
	// and for resolving SHF_LINK_ORDER.
	Index uint32

	// Out is the output section this chunk was placed in, and OutOffset its
	// position within it. Both are reassigned on every iteration of the
	// layout fixpoint.
	Out       *OutputSection
	OutOffset uint64

	// Discarded reports that this chunk lost a COMDAT group election. It is
	// set during resolve and is permanent: a relocation pointing into a
	// discarded chunk does not revive it.
	//
	// Reachable reports that the GC sweep found this chunk.
	//
	// These are two flags rather than one live bool because collapsing them
	// is exactly how a relocation into a discarded COMDAT resurrects it.
	Discarded bool
	Reachable bool

	// Fragments are the pieces this chunk was split into, if any. A split
	// chunk is never placed itself; its surviving fragments are placed in the
	// merged chunk that adopted them.
	Fragments []*Fragment

	// Group is the COMDAT signature this chunk belongs to, or the empty
	// string. Chunks in the same group are kept or discarded together.
	Group string

	// LinkOrder is the chunk SHF_LINK_ORDER ties this one's placement to.
	LinkOrder *Chunk

	src    ChunkSource
	data   []byte
	relocs []Reloc
	loaded bool
	rloaded bool
}

// NewChunk returns a chunk backed by src.
func NewChunk(name string, typ elf.SHType, flags SecFlags, align, size uint64, src ChunkSource) *Chunk {
	if align == 0 {
		align = 1
	}
	return &Chunk{Name: name, Type: typ, Flags: flags, Align: align, Size: size, src: src}
}

// Live reports whether the chunk contributes to the output: it won its COMDAT
// election and survived the sweep.
func (c *Chunk) Live() bool { return !c.Discarded && c.Reachable }

// Split reports whether the chunk was broken into fragments and so is not
// placed as a unit.
func (c *Chunk) Split() bool { return len(c.Fragments) > 0 }

// HasBits reports whether the chunk occupies file space.
func (c *Chunk) HasBits() bool { return c.Type != elf.SHT_NOBITS }

// Addr returns the chunk's run-time address. It is meaningful only after
// address assignment, and only for a placed chunk.
func (c *Chunk) Addr() uint64 {
	if c.Out == nil {
		return 0
	}
	return c.Out.Addr + c.OutOffset
}

// FileOff returns the chunk's offset in the output file. SHT_NOBITS chunks
// have no file position; the result is meaningless for them.
func (c *Chunk) FileOff() uint64 {
	if c.Out == nil {
		return 0
	}
	return c.Out.Off + c.OutOffset
}

// Data returns the chunk's contents, reading them through its source on first
// call and caching the result.
//
// The cache is not an optimisation detail: obj.Section.Data allocates a fresh
// slice every call, and the layout fixpoint touches every chunk on every
// iteration, so an uncached read would re-decode the whole link once per round.
//
// SHT_NOBITS chunks return an empty slice.
func (c *Chunk) Data() ([]byte, error) {
	if c.Type == elf.SHT_NOBITS {
		return []byte{}, nil
	}
	if c.loaded {
		return c.data, nil
	}
	if c.src == nil {
		return nil, fmt.Errorf("image: chunk %s has no source", c)
	}
	b, err := c.src.Bytes()
	if err != nil {
		return nil, fmt.Errorf("image: reading %s: %w", c, err)
	}
	c.data, c.loaded = b, true
	return b, nil
}

// SetData replaces the chunk's contents and marks them loaded. Decompression
// and synthetic generation use it; nothing else should.
func (c *Chunk) SetData(b []byte) {
	c.data, c.loaded = b, true
}

// Relocs returns the relocations that apply to this chunk, cached like Data.
func (c *Chunk) Relocs() ([]Reloc, error) {
	if c.rloaded {
		return c.relocs, nil
	}
	if c.src == nil {
		c.rloaded = true
		return nil, nil
	}
	r, err := c.src.Relocs()
	if err != nil {
		return nil, fmt.Errorf("image: reading relocations for %s: %w", c, err)
	}
	c.relocs, c.rloaded = r, true
	return r, nil
}

// Out bytes: OutBytes returns the writable region of the output buffer this
// chunk occupies, for relocation application. It fails before Freeze.
func (c *Chunk) OutBytes(img *Image) ([]byte, error) {
	if !c.HasBits() {
		return nil, fmt.Errorf("image: %s is SHT_NOBITS and occupies no file space", c)
	}
	if c.Out == nil {
		return nil, fmt.Errorf("image: %s was never placed", c)
	}
	return img.SliceAt(c.FileOff(), c.Size)
}

func (c *Chunk) String() string {
	if c.Input == nil {
		return c.Name
	}
	return c.Input.Name + ":" + c.Name
}

// Fragment is one piece of a split chunk: a mergeable string or record, or a
// CIE or FDE from .eh_frame.
//
// Fragments exist so that layout can place surviving pieces rather than whole
// chunks. Without them, deduplicating identical strings saves nothing because
// the original section still occupies its full length, and a dead FDE keeps
// its space in .eh_frame however thoroughly the GC proved it unreachable.
type Fragment struct {
	// Parent is the chunk this piece was cut from.
	Parent *Chunk

	// Off is the piece's offset within Parent, which is what a symbol or
	// relocation addend into a mergeable section names.
	Off uint64

	// Data is the piece's bytes. It aliases the parent chunk's contents.
	Data []byte

	// Align is the piece's required alignment, inherited from the parent
	// unless the record width says otherwise.
	Align uint64

	// Live reports whether this piece survived deduplication and the sweep. A
	// piece that lost a dedup election points at the winner through Same.
	Live bool

	// Same is the surviving fragment this one was deduplicated into, or nil
	// if this fragment is itself the survivor.
	Same *Fragment

	// Out is the merged chunk that adopted this fragment, and OutOffset the
	// position within it.
	Out       *Chunk
	OutOffset uint64
}

// Winner returns the fragment that actually occupies space: this one, or the
// one it was deduplicated into.
func (f *Fragment) Winner() *Fragment {
	if f.Same != nil {
		return f.Same
	}
	return f
}

// Addr returns the fragment's run-time address, following a dedup redirect.
func (f *Fragment) Addr() uint64 {
	w := f.Winner()
	if w.Out == nil {
		return 0
	}
	return w.Out.Addr() + w.OutOffset
}

// Reloc is one relocation to apply, with its symbol already resolved.
//
// Offset is relative to the chunk the relocation belongs to, not to the input
// section or the output. Addend is meaningful only when Explicit is true; for a
// REL target the addend is in the section contents at Offset and only the
// backend knows how to read it out, through Backend.RelAddend.
type Reloc struct {
	Offset uint64

	// Sym is the resolved target, or nil when the relocation named an index
	// that resolved to nothing. Applying such a relocation is an error the
	// backend reports with its own context.
	Sym *Sym

	Type   uint32
	Addend int64

	Explicit bool
}

func (r Reloc) String() string {
	name := "<none>"
	if r.Sym != nil {
		name = r.Sym.Name
	}
	return fmt.Sprintf("%s+%#x type %d addend %d", name, r.Offset, r.Type, r.Addend)
}