package image

import (
	"fmt"

	"github.com/vertex-language/elf"
)

// Synthetic is a chunk the linker generates rather than reads: .got, .plt,
// .dynamic, .gnu.hash, the merged string blob, the build-id note.
//
// Generation is split from layout because the two need each other's results.
// The size of a .got is known during scan, once every reference has been
// counted, but its contents are addresses that do not exist until layout has
// run. So a Synthetic declares its size early, is placed like any other chunk,
// and fills itself in afterwards — at which point it must produce exactly the
// number of bytes it reserved, or it has already overrun its neighbour.
type Synthetic struct {
	// Chunk is the placeable chunk this synthetic backs.
	Chunk *Chunk

	gen func(*Image) ([]byte, error)
}

// NewSynthetic returns a synthetic chunk. gen is called once, after addresses
// are final, and must return exactly Chunk.Size bytes.
func NewSynthetic(name string, typ elf.SHType, flags SecFlags, align, entsize uint64,
	gen func(*Image) ([]byte, error)) *Synthetic {

	if align == 0 {
		align = 1
	}
	return &Synthetic{
		Chunk: &Chunk{
			Name:      name,
			Type:      typ,
			Flags:     flags,
			Align:     align,
			Entsize:   entsize,
			Reachable: true, // generated because something needs it
		},
		gen: gen,
	}
}

// SetSize declares how many bytes the synthetic will occupy. It panics after
// the image is sealed, because resizing a chunk that has already been placed
// moves everything after it without moving the addresses computed from it.
func (s *Synthetic) SetSize(img *Image, n uint64) {
	if img.Sealed() {
		panic("image: SetSize on " + s.Chunk.Name + " after the image was sealed")
	}
	s.Chunk.Size = n
}

// Grow adds n bytes to the synthetic's reserved size and returns the offset of
// the new space, which is how a GOT or PLT hands out slots.
func (s *Synthetic) Grow(img *Image, n uint64) uint64 {
	if img.Sealed() {
		panic("image: Grow on " + s.Chunk.Name + " after the image was sealed")
	}
	off := s.Chunk.Size
	s.Chunk.Size += n
	return off
}

// Generate fills the chunk's contents and checks their length against the space
// reserved for them.
func (s *Synthetic) Generate(img *Image) error {
	if s.gen == nil {
		return nil
	}
	b, err := s.gen(img)
	if err != nil {
		return fmt.Errorf("image: generating %s: %w", s.Chunk.Name, err)
	}
	if uint64(len(b)) != s.Chunk.Size {
		return fmt.Errorf("image: %s generated %d bytes into the %d reserved for it",
			s.Chunk.Name, len(b), s.Chunk.Size)
	}
	s.Chunk.SetData(b)
	return nil
}

// RawSource is a ChunkSource over a fixed byte slice, for content that is
// already in memory and has no relocations.
type RawSource []byte

func (r RawSource) Bytes() ([]byte, error)   { return []byte(r), nil }
func (r RawSource) Relocs() ([]Reloc, error) { return nil, nil }

// Finalizer is work that runs after every byte of the output has been written.
//
// The motivating case is a build-id: it hashes the finished file and writes the
// result back into a note that was emitted much earlier. A Finalizer may read
// and patch the whole buffer but must not change its length — nothing after it
// recomputes an offset.
type Finalizer interface {
	Finalize(*Image) error
}

// FinalizerFunc adapts a function to Finalizer.
type FinalizerFunc func(*Image) error

func (f FinalizerFunc) Finalize(img *Image) error { return f(img) }