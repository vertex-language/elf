package link

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"io"

	"github.com/vertex-language/elf"
	"github.com/vertex-language/elf/image"
	"github.com/vertex-language/elf/internal/binio"
	"github.com/vertex-language/elf/internal/format"
)

// merge turns live chunks into output sections.
//
// Four steps, in this order: allocate common symbols, decompress what needs
// it, deduplicate fragments into merged chunks, and group everything into
// output sections by name and flags.
func (l *Linker) merge(img *image.Image) error {
	if err := l.allocCommon(img); err != nil {
		return err
	}
	if err := l.decompress(img); err != nil {
		return err
	}
	if err := l.mergeFragments(img); err != nil {
		return err
	}
	return l.placeChunks(img)
}

// allocCommon gives every surviving tentative definition storage.
//
// A common symbol is a promise that some translation unit will provide the
// definition; when none does, the linker provides it. Value holds the required
// alignment and Size the required bytes, so the generated .bss is the sum of
// the sizes with each symbol aligned to its own requirement. After this pass
// no SymCommon remains, which is what lets everything downstream treat a
// defined symbol as having a chunk.
func (l *Linker) allocCommon(img *image.Image) error {
	var commons []*image.Sym
	img.Syms.Each(func(s *image.Sym) {
		if s.Class == image.SymCommon {
			commons = append(commons, s)
		}
	})
	if len(commons) == 0 {
		return nil
	}

	in := &image.Input{Name: "<common>", Target: img.Target}
	img.AddInput(in)

	var size, maxAlign uint64 = 0, 1
	offs := make([]uint64, len(commons))
	for i, s := range commons {
		align := s.Value
		if align == 0 {
			align = 1
		}
		if align > maxAlign {
			maxAlign = align
		}
		size = alignUp(size, align)
		offs[i] = size
		size += s.Size
	}

	ch := image.NewChunk(".bss", elf.SHT_NOBITS,
		image.SecFlags(elf.SHF_ALLOC|elf.SHF_WRITE), maxAlign, size, nil)
	ch.Reachable = true
	in.AddChunk(ch)

	for i, s := range commons {
		s.Class = image.SymRegular
		s.Chunk = ch
		s.Value = offs[i]
		s.Input = in
	}
	return nil
}

// decompress expands SHF_COMPRESSED chunks.
//
// The object reader deliberately hands back compressed bytes untouched,
// because only the linker knows whether it wants the section at all. This is
// where that decision has been made.
func (l *Linker) decompress(img *image.Image) error {
	var err error
	img.Chunks(func(ch *image.Chunk) {
		if err != nil || !ch.Flags.Compressed() {
			return
		}
		err = decompressChunk(ch, img.Target.Class)
	})
	return err
}

func decompressChunk(ch *image.Chunk, cl elf.Class) error {
	raw, err := ch.Data()
	if err != nil {
		return err
	}
	hdrSize := format.ChdrSize(cl)
	if len(raw) < hdrSize {
		return fmt.Errorf("link: %s is %d bytes, too small for a %d-byte compression header",
			ch, len(raw), hdrSize)
	}

	c := binio.NewCursor(raw, byteOrder(cl, ch))
	var hdr format.Chdr
	hdr.Decode(c, cl)
	if err := c.Err(); err != nil {
		return fmt.Errorf("link: %s: %w", ch, err)
	}

	var out []byte
	switch hdr.Type {
	case elf.ELFCOMPRESS_ZLIB:
		zr, err := zlib.NewReader(bytes.NewReader(raw[hdrSize:]))
		if err != nil {
			return fmt.Errorf("link: %s: %w", ch, err)
		}
		defer zr.Close()
		out = make([]byte, hdr.Size)
		if _, err := io.ReadFull(zr, out); err != nil {
			return fmt.Errorf("link: %s: decompressing: %w", ch, err)
		}
	case elf.ELFCOMPRESS_ZSTD:
		// This module has no dependencies, and zstd is not in the standard
		// library. Saying so beats emitting the compressed bytes as if they
		// were content.
		return fmt.Errorf("link: %s is zstd-compressed, which this linker cannot decompress", ch)
	default:
		return fmt.Errorf("link: %s uses compression type %v", ch, hdr.Type)
	}

	ch.SetData(out)
	ch.Size = hdr.Size
	ch.Flags &^= image.SecFlags(elf.SHF_COMPRESSED)
	if hdr.Addralign != 0 {
		ch.Align = hdr.Addralign
	}
	return nil
}

// mergeFragments deduplicates split chunks into one merged chunk per output
// identity.
//
// Deduplication is by content. For .eh_frame this collapses the identical CIE
// every object emits down to one, which is why a program built from hundreds
// of translation units ends up with a handful of them.
func (l *Linker) mergeFragments(img *image.Image) error {
	type key struct {
		name  string
		typ   elf.SHType
		flags image.SecFlags
	}
	order := []key{}
	byKey := map[key][]*image.Chunk{}

	img.Chunks(func(ch *image.Chunk) {
		if !ch.Split() {
			return
		}
		k := key{mergedName(ch), ch.Type, ch.Flags &^ image.SecFlags(elf.SHF_GROUP)}
		if _, ok := byKey[k]; !ok {
			order = append(order, k)
		}
		byKey[k] = append(byKey[k], ch)
	})
	if len(order) == 0 {
		return nil
	}

	in := &image.Input{Name: "<merged>", Target: img.Target}
	img.AddInput(in)

	for _, k := range order {
		sources := byKey[k]
		seen := make(map[string]*image.Fragment)
		var live []*image.Fragment
		var align uint64 = 1

		for _, src := range sources {
			if src.Align > align {
				align = src.Align
			}
			for _, f := range src.Fragments {
				// With GC on, only fragments the sweep reached survive.
				// With GC off, the sweep marked everything.
				if l.opts.GC && !f.Live && !isKeptFragment(src) {
					continue
				}
				s := string(f.Data)
				if w, ok := seen[s]; ok {
					f.Same = w
					continue
				}
				seen[s] = f
				live = append(live, f)
			}
		}

		var size uint64
		for _, f := range live {
			a := f.Align
			if a == 0 {
				a = 1
			}
			size = alignUp(size, a)
			f.OutOffset = size
			size += uint64(len(f.Data))
		}

		blob := make([]byte, size)
		for _, f := range live {
			copy(blob[f.OutOffset:], f.Data)
		}

		merged := image.NewChunk(k.name, k.typ, k.flags, align, size, image.RawSource(blob))
		merged.SetData(blob)
		merged.Reachable = true
		in.AddChunk(merged)

		for _, f := range live {
			f.Out = merged
		}
	}
	return nil
}

// isKeptFragment reports whether a split chunk's pieces survive without the
// sweep having reached them individually. A CIE is referenced by its FDEs
// rather than by code, so nothing marks it directly.
func isKeptFragment(ch *image.Chunk) bool { return ch.Name == ".eh_frame" }

// mergedName is the output name a split chunk's fragments land under.
func mergedName(ch *image.Chunk) string {
	if ch.Name == ".eh_frame" {
		return ".eh_frame"
	}
	return outputName(ch.Name)
}

// placeChunks assigns every live chunk to an output section.
func (l *Linker) placeChunks(img *image.Image) error {
	for _, in := range img.Inputs {
		for _, ch := range in.Chunks {
			if !ch.Live() || ch.Split() {
				// A split chunk contributed its fragments to a merged chunk
				// and is not placed itself.
				continue
			}
			if l.dropped(ch) {
				continue
			}
			flags := ch.Flags &^ image.SecFlags(elf.SHF_GROUP|elf.SHF_COMPRESSED)
			out := img.Section(outputName(ch.Name), ch.Type, flags)
			if ch.Entsize != 0 && out.Entsize == 0 {
				out.Entsize = ch.Entsize
			}
			out.Add(ch)
		}
	}
	return nil
}

// dropped reports whether a chunk is discarded by a strip option.
func (l *Linker) dropped(ch *image.Chunk) bool {
	if ch.Flags.Alloc() {
		return false
	}
	if l.opts.StripAll {
		return true
	}
	if l.opts.StripDebug {
		return hasPrefix(ch.Name, ".debug") || hasPrefix(ch.Name, ".zdebug")
	}
	return false
}

// outputName maps an input section name to its output section.
//
// -ffunction-sections produces .text.foo per function; those belong in .text.
// The mapping is prefix-based and deliberately short: anything not listed
// keeps its own name, because inventing a mapping for an unknown name is how a
// linker silently merges two things the compiler meant to keep apart.
func outputName(name string) string {
	for _, p := range []string{
		".text", ".rodata", ".data.rel.ro", ".data", ".bss",
		".tdata", ".tbss", ".init_array", ".fini_array", ".preinit_array",
		".gcc_except_table", ".ctors", ".dtors",
	} {
		if name == p {
			return p
		}
		if hasPrefix(name, p+".") {
			return p
		}
	}
	return name
}

func hasPrefix(s, p string) bool { return len(s) >= len(p) && s[:len(p)] == p }

// alignUp rounds v up to a multiple of a, which must be a power of two or 0.
func alignUp(v, a uint64) uint64 {
	if a <= 1 {
		return v
	}
	return (v + a - 1) &^ (a - 1)
}