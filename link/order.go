package link

import (
	"sort"

	"github.com/vertex-language/elf"
	"github.com/vertex-language/elf/image"
)

// Section ranks, lowest first.
//
// A rank table rather than flags alone. SHF_* cannot express that .interp must
// come first, that .tdata and .tbss must be adjacent, or that the RELRO region
// must be contiguous and page-aligned — and every one of those is a
// requirement rather than a preference.
const (
	rankInterp = iota * 10
	rankNote
	rankHash
	rankDynSym
	rankDynStr
	rankRelaDyn
	rankRelaPlt

	rankInit
	rankPlt
	rankText
	rankFini

	rankRodata
	rankEhFrameHdr
	rankEhFrame

	// The RELRO region. .tdata and .tbss lead the writable sections because
	// PT_TLS must cover them and nothing else, so they cannot be separated
	// by anything. Putting RELRO at the head of the writable segment rather
	// than after .data is what removes a page of alignment padding.
	rankTData
	rankTBss
	rankPreinitArray
	rankInitArray
	rankFiniArray
	rankDataRelRo
	rankDynamic
	rankGot
	rankGotPltRelro
	rankRelroPad

	// Outside RELRO.
	rankGotPlt
	rankData
	rankBss

	rankNonAlloc
	rankLast
)

// relroPadName is the NOBITS section that runs the RELRO region out to a page
// boundary. It is created in registerSynthetics rather than here, so that
// every section exists before the section-name table is laid out.
const relroPadName = ".relro_padding"

// order assigns each output section a rank and sorts by it.
//
// It creates no sections. Everything that will appear in the output exists by
// the time this runs, which is what lets the caller seal the image immediately
// afterward.
func (l *Linker) order(img *image.Image) error {
	full := l.opts.Relro == RelroFull || l.opts.bindNow()

	for _, s := range img.Sections {
		s.Rank = rankOf(s, full)
	}

	// Explicit ordering wins over the table, so a bare-metal caller can put
	// .text.boot first without a linker script.
	for i, name := range l.opts.SectionOrder {
		if s := img.FindSection(name); s != nil {
			s.Rank = -len(l.opts.SectionOrder) + i
		}
	}

	sort.SliceStable(img.Sections, func(i, j int) bool {
		return img.Sections[i].Rank < img.Sections[j].Rank
	})
	return nil
}

// rankOf places one output section.
func rankOf(s *image.OutputSection, fullRelro bool) int {
	if !s.Flags.Alloc() {
		return rankNonAlloc
	}

	switch s.Name {
	case ".interp":
		return rankInterp
	case ".note.gnu.build-id", ".note.ABI-tag", ".note.gnu.property":
		return rankNote
	case ".hash", ".gnu.hash":
		return rankHash
	case ".dynsym", ".gnu.version", ".gnu.version_d", ".gnu.version_r":
		return rankDynSym
	case ".dynstr":
		return rankDynStr
	case ".rela.dyn", ".rel.dyn":
		return rankRelaDyn
	case ".rela.plt", ".rel.plt":
		return rankRelaPlt
	case ".init":
		return rankInit
	case ".plt", ".plt.sec", ".iplt":
		return rankPlt
	case ".fini":
		return rankFini
	case ".eh_frame_hdr":
		return rankEhFrameHdr
	case ".eh_frame":
		return rankEhFrame
	case ".tdata":
		return rankTData
	case ".tbss":
		return rankTBss
	case ".preinit_array":
		return rankPreinitArray
	case ".init_array":
		return rankInitArray
	case ".fini_array":
		return rankFiniArray
	case ".data.rel.ro":
		return rankDataRelRo
	case ".dynamic":
		return rankDynamic
	case ".got":
		return rankGot
	case ".got.plt":
		// Under full RELRO the loader has bound every slot before the
		// program runs, so .got.plt can join the read-only region. Under
		// partial RELRO it must stay writable for lazy binding, and putting
		// it inside would produce a program that faults on its first call
		// into a library.
		if fullRelro {
			return rankGotPltRelro
		}
		return rankGotPlt
	case relroPadName:
		return rankRelroPad
	}

	if s.Flags.Exec() {
		return rankText
	}
	if !s.Flags.Write() {
		return rankRodata
	}
	if s.Type == elf.SHT_NOBITS {
		return rankBss
	}
	return rankData
}

// relroSection reports whether a section belongs in PT_GNU_RELRO.
func relroSection(s *image.OutputSection) bool {
	return s.Rank >= rankTData && s.Rank <= rankRelroPad && s.Flags.Write()
}