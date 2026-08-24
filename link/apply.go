package link

import (
	"encoding/binary"
	"fmt"

	"github.com/vertex-language/elf"
	"github.com/vertex-language/elf/backend"
	"github.com/vertex-language/elf/image"
)

// writeChunks copies every live chunk's contents into the output buffer.
//
// SHT_NOBITS chunks are skipped: the buffer is already zero, which is exactly
// what a NOBITS section means, and copying an empty slice into the middle of
// .bss would be a no-op with a misleading intent.
func (l *Linker) writeChunks(img *image.Image) error {
	var err error
	img.Chunks(func(ch *image.Chunk) {
		if err != nil || ch.Out == nil || !ch.HasBits() || ch.Split() {
			return
		}
		var data []byte
		data, err = ch.Data()
		if err != nil {
			return
		}
		if uint64(len(data)) > ch.Size {
			// A chunk whose contents outgrew its declared size has already
			// overwritten its neighbour by the time anyone notices the
			// output is wrong.
			err = fmt.Errorf("link: %s holds %d bytes in the %d it was laid out with",
				ch, len(data), ch.Size)
			return
		}
		err = img.CopyAt(ch.FileOff(), data)
	})
	return err
}

// applyAll writes every relocation into the output.
func (l *Linker) applyAll(img *image.Image) error {
	if l.opts.Output == OutputRelocatable {
		// A partial link preserves relocations rather than resolving them.
		return nil
	}
	if err := l.writeThunks(img); err != nil {
		return err
	}

	var err error
	img.Chunks(func(ch *image.Chunk) {
		if err != nil || ch.Out == nil || !ch.HasBits() || ch.Split() {
			return
		}
		err = l.applyChunk(img, ch)
	})
	return err
}

// applyChunk applies one chunk's relocations.
func (l *Linker) applyChunk(img *image.Image, ch *image.Chunk) error {
	relocs, err := ch.Relocs()
	if err != nil {
		return err
	}
	if len(relocs) == 0 {
		return nil
	}

	s, err := l.site(img, ch)
	if err != nil {
		return err
	}

	for _, r := range relocs {
		if l.be.Classify(r.Type) == backend.KindRelax {
			// A relaxation hint marks a place rather than describing one.
			// Applying it would write over the instruction it annotates.
			continue
		}

		// A REL target's addend lives in the section contents, and only the
		// backend knows how to read it out of whatever instruction field it
		// was encoded into.
		if !r.Explicit {
			if a, ok := l.be.RelAddend(s.Data, r.Offset, r.Type); ok {
				r.Addend = a
			}
		}

		// A branch that could not reach its target goes through a
		// trampoline instead. Substituting an absolute symbol keeps the
		// backend's arithmetic identical to the direct case.
		if addr, ok := l.redirect[relocSite{ch, r.Offset}]; ok {
			r.Sym = &image.Sym{
				Name:     "<thunk>",
				Class:    image.SymAbsolute,
				Bind:     elf.STB_LOCAL,
				Value:    addr,
				GotIndex: image.NoIndex,
				PltIndex: image.NoIndex,
				DynIndex: image.NoIndex,
			}
			r.Addend = 0
		}

		if err := l.be.Apply(s, r); err != nil {
			return &OverflowError{Input: ch.Input, Err: err}
		}
	}
	return nil
}

// site builds the backend's view of one chunk's output bytes.
func (l *Linker) site(img *image.Image, ch *image.Chunk) (*backend.Site, error) {
	data, err := ch.OutBytes(img)
	if err != nil {
		return nil, err
	}
	return &backend.Site{
		Img:   img,
		Chunk: ch,
		Data:  data,
		Addr:  ch.Addr(),
		Class: img.Target.Class,
		Order: outputOrder(img.Target),
		Reqs:  l.reqs,
	}, nil
}

func outputOrder(t elf.Target) binary.ByteOrder {
	if t.Endian == elf.EndianBig {
		return binary.BigEndian
	}
	return binary.LittleEndian
}