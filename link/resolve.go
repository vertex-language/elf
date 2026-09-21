package link

import (
	"fmt"

	"github.com/vertex-language/elf"
	"github.com/vertex-language/elf/ar"
	"github.com/vertex-language/elf/backend"
	"github.com/vertex-language/elf/image"
	"github.com/vertex-language/elf/obj"
)

// rank orders the states a name can be in, from weakest to strongest. A
// candidate replaces the incumbent only when its rank is higher.
//
// The order is not a binding comparison. A common (tentative) definition sits
// below STB_GLOBAL but above STB_WEAK, so a weak definition loses to a
// tentative one — which surprises everybody the first time and is what the
// gABI and every real linker do. A definition from an object beats one from a
// shared object, and both beat an archive member that has not been extracted.
type rank uint8

const (
	rankUndefWeak rank = iota
	rankUndef
	rankLazy
	rankSharedWeak
	rankShared
	rankWeakDef
	rankCommon
	rankGlobalDef
)

// lazy is an archive member that defines a name but has not been extracted.
type lazy struct {
	file    *inputFile
	archive *ar.Reader
	member  *ar.Member
}

// resolver holds the state of the resolution pass.
type resolver struct {
	l   *Linker
	img *image.Image

	// rank of each global symbol's current state, parallel to the symbol
	// table. It is kept here rather than on image.Sym because it is
	// meaningful only during this pass.
	rank map[*image.Sym]rank

	// lazies maps a name to the archive member that would define it.
	lazies map[string]lazy

	// pending is the extraction queue. Extracting a member can create new
	// undefined symbols, which can queue further members; the loop below
	// runs until it drains.
	pending []lazy

	// extracted records members already pulled in, so a member defining
	// twenty needed symbols is loaded once.
	extracted map[*ar.Member]bool

	// comdat maps a COMDAT signature to the input that won it. The election
	// is first-wins in link order, and the loser's whole group is discarded
	// rather than its individual sections: a group exists precisely so that
	// its members are kept or dropped together.
	comdat map[string]*image.Input

	// needed are the shared inputs, in link order, which become DT_NEEDED
	// entries unless --as-needed drops the ones nothing references.
	needed []*image.Input

	// flags accumulates e_flags across inputs, for the architectures where
	// it carries ABI facts that must agree.
	flags    uint32
	haveFlag bool
}

// resolve builds the global symbol table and settles COMDAT elections.
func (l *Linker) resolve(img *image.Image) error {
	r := &resolver{
		l:         l,
		img:       img,
		rank:      make(map[*image.Sym]rank),
		lazies:    make(map[string]lazy),
		extracted: make(map[*ar.Member]bool),
		comdat:    make(map[string]*image.Input),
	}

	// Options that reference symbols do so before any file is read, so that
	// the first archive encountered can satisfy them.
	for _, name := range l.opts.Undefined {
		s, _ := img.Syms.Insert(name)
		s.Referenced = true
		r.rank[s] = rankUndef
	}
	if l.opts.wantsEntry() {
		s, _ := img.Syms.Insert(l.opts.entryName())
		s.Referenced = true
		if _, ok := r.rank[s]; !ok {
			r.rank[s] = rankUndef
		}
	}

	for i, f := range l.files {
		if err := r.scanFile(f); err != nil {
			return err
		}
		if err := r.drain(); err != nil {
			return err
		}
		if err := r.rescanGroups(i); err != nil {
			return err
		}
	}

	l.needed = r.needed

	if l.opts.wantsEntry() {
		if s := img.Syms.Lookup(l.opts.entryName()); s != nil && s.Defined() {
			img.EntrySym = s
		}
	}
	return nil
}

// scanFile processes one input in link order.
func (r *resolver) scanFile(f *inputFile) error {
	switch f.kind {
	case kindObject:
		return r.loadObject(f.name, f.data, f)
	case kindShared:
		return r.loadShared(f.name, f.data)
	case kindArchive:
		return r.scanArchive(f)
	}
	return fmt.Errorf("link: %s: unknown input kind", f.name)
}

// scanArchive registers an archive's definitions as lazy, or extracts every
// member when --whole-archive is in effect.
func (r *resolver) scanArchive(f *inputFile) error {
	rd, err := openArchive(f.name, f.data)
	if err != nil {
		return err
	}

	if f.whole {
		for _, m := range rd.Members {
			if err := r.extract(lazy{file: f, archive: rd, member: m}); err != nil {
				return err
			}
		}
		return nil
	}

	if rd.Index == nil {
		// An archive without a symbol index is valid; a linker must then
		// read every member to learn what it defines. Doing that eagerly
		// costs what the index would have saved, which is the archive's own
		// fault, not the caller's.
		return r.scanUnindexed(f, rd)
	}

	for _, e := range rd.Index {
		if _, ok := r.lazies[e.Name]; ok {
			// An earlier archive already offers this name. First on the
			// link line wins the lazy slot.
			continue
		}
		m := rd.MemberAt(e.HeaderOffset)
		if m == nil {
			return fmt.Errorf("link: %s: symbol index entry %q points at %#x, which is not a member",
				f.name, e.Name, e.HeaderOffset)
		}
		lz := lazy{file: f, archive: rd, member: m}
		r.lazies[e.Name] = lz

		// A name already wanted by something loaded earlier pulls the member
		// in immediately.
		if s := r.img.Syms.Lookup(e.Name); s != nil && r.wants(s) {
			r.pending = append(r.pending, lz)
		}
	}
	return nil
}

// scanUnindexed reads every member of an index-less archive to discover what
// it defines.
func (r *resolver) scanUnindexed(f *inputFile, rd *ar.Reader) error {
	for _, m := range rd.Members {
		data, err := memberData(f.name, m)
		if err != nil {
			return err
		}
		of, err := openObject(memberName(f.name, m), data)
		if err != nil {
			return err
		}
		syms, err := of.Symbols()
		if err != nil {
			return err
		}
		lz := lazy{file: f, archive: rd, member: m}
		for _, s := range syms {
			if s.Bind == elf.STB_LOCAL || !s.Defined() || s.Name == "" {
				continue
			}
			if _, ok := r.lazies[s.Name]; ok {
				continue
			}
			r.lazies[s.Name] = lz
			if g := r.img.Syms.Lookup(s.Name); g != nil && r.wants(g) {
				r.pending = append(r.pending, lz)
			}
		}
	}
	return nil
}

// wants reports whether an undefined symbol should pull an archive member in.
//
// A weak reference must not: the gABI and every mainstream linker agree that
// an undefined weak symbol resolves to zero rather than dragging in a
// definition. This is the rule behind the classic libstdc++ symptom where weak
// pthread references leave the corresponding members of libpthread.a
// unextracted in a static link.
func (r *resolver) wants(s *image.Sym) bool {
	return !s.Defined() && s.Bind != elf.STB_WEAK
}

// drain extracts queued members until the queue is empty. Each extraction can
// introduce new undefined symbols, which is why this is a loop and not a pass.
func (r *resolver) drain() error {
	for len(r.pending) > 0 {
		lz := r.pending[0]
		r.pending = r.pending[1:]
		if err := r.extract(lz); err != nil {
			return err
		}
	}
	return nil
}

// rescanGroups re-runs any --start-group range that has just closed, until it
// yields nothing further.
func (r *resolver) rescanGroups(pos int) error {
	for _, g := range r.l.opts.Groups {
		if g.Last != pos+1 {
			continue
		}
		for {
			before := len(r.extracted)
			for i := g.First; i < g.Last && i < len(r.l.files); i++ {
				f := r.l.files[i]
				if f.kind != kindArchive {
					continue
				}
				if err := r.requeue(f); err != nil {
					return err
				}
			}
			if err := r.drain(); err != nil {
				return err
			}
			if len(r.extracted) == before {
				break
			}
		}
	}
	return nil
}

// requeue queues any member of f that now satisfies an undefined symbol.
func (r *resolver) requeue(f *inputFile) error {
	for name, lz := range r.lazies {
		if lz.file != f || r.extracted[lz.member] {
			continue
		}
		if s := r.img.Syms.Lookup(name); s != nil && r.wants(s) {
			r.pending = append(r.pending, lz)
		}
	}
	return nil
}

// extract pulls an archive member into the link.
func (r *resolver) extract(lz lazy) error {
	if r.extracted[lz.member] {
		return nil
	}
	r.extracted[lz.member] = true

	data, err := memberData(lz.file.name, lz.member)
	if err != nil {
		return err
	}
	return r.loadObject(memberName(lz.file.name, lz.member), data, lz.file)
}

// loadObject parses an object, creates its chunks, and merges its symbols.
func (r *resolver) loadObject(name string, data []byte, _ *inputFile) error {
	f, err := openObject(name, data)
	if err != nil {
		return err
	}

	in := &image.Input{Name: name, Target: f.Target()}
	if err := r.checkTarget(in); err != nil {
		return err
	}
	r.img.AddInput(in)

	groups, err := f.Groups()
	if err != nil {
		return fmt.Errorf("link: %s: %w", name, err)
	}
	inGroup, discard, err := r.elect(in, groups)
	if err != nil {
		return err
	}

	chunks, err := r.makeChunks(in, f, inGroup, discard)
	if err != nil {
		return err
	}

	syms, err := f.Symbols()
	if err != nil {
		return fmt.Errorf("link: %s: %w", name, err)
	}
	in.Syms = make([]*image.Sym, len(syms))
	for i, s := range syms {
		if i == 0 {
			continue
		}
		gs, err := r.merge(in, s, chunks)
		if err != nil {
			return err
		}
		in.Syms[i] = gs
	}
	return nil
}

// checkTarget rejects an input that cannot contribute to this output.
func (r *resolver) checkTarget(in *image.Input) error {
	t := r.l.target
	if in.Target.Arch != t.Arch {
		return &MismatchError{Input: in, Reason: fmt.Sprintf(
			"built for %v, linking for %v", in.Target.Arch, t.Arch)}
	}
	if in.Target.Class != t.Class {
		return &MismatchError{Input: in, Reason: fmt.Sprintf(
			"is %v, output is %v", in.Target.Class, t.Class)}
	}
	if in.Target.Endian != t.Endian {
		return &MismatchError{Input: in, Reason: fmt.Sprintf(
			"is %v-endian, output is %v-endian", in.Target.Endian, t.Endian)}
	}

	if fl, ok := backend.AsFlagger(r.l.be); ok {
		if !r.haveFlag {
			r.flags, r.haveFlag = in.Target.Flags, true
			return nil
		}
		merged, err := fl.MergeFlags(r.flags, in.Target.Flags)
		if err != nil {
			return &MismatchError{Input: in, Reason: err.Error()}
		}
		r.flags = merged
	}
	return nil
}

// elect runs this object's COMDAT elections and reports which of its sections
// belong to a group, and which of those groups it lost.
//
// First in link order wins. A loser's entire group is discarded: dropping only
// the sections that happen to be duplicated would leave the group's other
// members referring to a definition that is no longer theirs.
func (r *resolver) elect(in *image.Input, groups []obj.Group) (inGroup map[uint32]string, discard map[uint32]bool, err error) {
	inGroup = make(map[uint32]string)
	discard = make(map[uint32]bool)

	for i := range groups {
		g := &groups[i]
		key := g.Key()
		if !g.COMDAT() || key == "" {
			// A group with no COMDAT flag or no resolvable signature is kept
			// whole; there is no key to deduplicate on.
			for _, m := range g.Members {
				inGroup[m.Index] = ""
			}
			continue
		}
		winner, taken := r.comdat[key]
		if !taken {
			r.comdat[key] = in
			winner = in
		}
		lost := winner != in
		for _, m := range g.Members {
			inGroup[m.Index] = key
			if lost {
				discard[m.Index] = true
			}
		}
	}
	return inGroup, discard, nil
}

// makeChunks turns an object's sections into placeable chunks, indexed by
// section index so that symbols can find their homes.
func (r *resolver) makeChunks(in *image.Input, f *obj.File,
	inGroup map[uint32]string, discard map[uint32]bool) (map[uint32]*image.Chunk, error) {

	out := make(map[uint32]*image.Chunk, len(f.Sections))
	for _, sec := range f.Sections {
		if !contributes(sec) {
			continue
		}
		ch := image.NewChunk(sec.Name, sec.Type, image.SecFlags(sec.Flags),
			sec.Addralign, sec.Size, &objSource{sec: sec, in: in})
		ch.Index = sec.Index
		ch.Entsize = sec.Entsize
		ch.Group = inGroup[sec.Index]
		ch.Discarded = discard[sec.Index]

		// A non-allocated section that is not part of a group survives GC
		// without being a root: debug information is not reachable from
		// code, but discarding it would defeat the point of emitting it.
		if sec.Flags&elf.SHF_ALLOC == 0 && sec.Flags&elf.SHF_GROUP == 0 {
			ch.Reachable = true
		}
		// SHF_GNU_RETAIN is an explicit request to keep the section whatever
		// the sweep concludes.
		if sec.Flags&elf.SHF_GNU_RETAIN != 0 {
			ch.Reachable = true
		}

		in.AddChunk(ch)
		out[sec.Index] = ch
	}

	// SHF_LINK_ORDER ties a chunk's placement to another's, so resolve the
	// back-references now that every chunk exists.
	for _, sec := range f.Sections {
		ch, ok := out[sec.Index]
		if !ok || sec.Flags&elf.SHF_LINK_ORDER == 0 {
			continue
		}
		if target, ok := out[sec.Link]; ok {
			ch.LinkOrder = target
		}
	}
	return out, nil
}

// contributes reports whether a parsed section becomes a chunk.
//
// The metadata sections do not: symbol tables, string tables, relocation
// sections, and group sections describe the object rather than contributing to
// the output, and the linker rebuilds each of them from its own model.
func contributes(sec *obj.Section) bool {
	switch sec.Type {
	case elf.SHT_NULL, elf.SHT_SYMTAB, elf.SHT_DYNSYM, elf.SHT_STRTAB,
		elf.SHT_REL, elf.SHT_RELA, elf.SHT_RELR,
		elf.SHT_GROUP, elf.SHT_SYMTAB_SHNDX:
		return false
	}
	return sec.Name != ""
}

// merge folds one object symbol into the global table.
func (r *resolver) merge(in *image.Input, s *obj.Symbol, chunks map[uint32]*image.Chunk) (*image.Sym, error) {
	// Local symbols do not participate in resolution: two objects may each
	// define a local "tmp" without conflict. They still become Syms, because
	// relocations point at them.
	if s.Bind == elf.STB_LOCAL {
		g := r.img.Syms.Local(s.Name)
		g.Type = s.Type
		g.Other = s.Other
		g.Value = s.Value
		g.Size = s.Size
		g.Input = in
		if ch, ok := chunks[s.Shndx]; ok {
			g.Class = image.SymRegular
			g.Chunk = ch
		} else if s.Absolute() {
			g.Class = image.SymAbsolute
		}
		return g, nil
	}
	if s.Name == "" {
		return nil, nil
	}

	g, _ := r.img.Syms.Insert(s.Name)
	cand := candidateRank(s)

	// Visibility propagates whatever the outcome. The gABI requires the most
	// constraining visibility among all references and definitions to reach
	// the resolved symbol: code compiled against a hidden declaration was
	// optimised on that promise, and an output that quietly makes the symbol
	// default breaks it.
	g.SetVisibility(elf.MostConstraining(g.Visibility(), elf.Visibility(s.Other)))

	if !s.Defined() {
		g.Referenced = true
		// Bind and Type otherwise stay at their zero value — STB_LOCAL,
		// STT_NOTYPE — for a name nothing in the link ever defines, which is
		// wrong in two ways: Sym.Weak reads Bind, so an undefined symbol
		// every reference to which is weak would wrongly report as required;
		// and a dynamic symbol table entry naming this reference for the
		// loader to resolve would claim to be local, which a loader never
		// looks up by name at all. Only STB_GLOBAL and STB_WEAK reach here —
		// a local reference does not create a cross-object undefined symbol,
		// see the early return above — so the strongest bind across every
		// reference is exactly "global unless every one of them was weak".
		if s.Type != elf.STT_NOTYPE && g.Type == elf.STT_NOTYPE {
			g.Type = s.Type
		}
		if g.Bind != elf.STB_GLOBAL {
			g.Bind = s.Bind
		}
		if cur, ok := r.rank[g]; !ok || cur < cand {
			r.rank[g] = cand
		}
		// A reference to a name an archive offers pulls that member in.
		if lz, ok := r.lazies[s.Name]; ok && !r.extracted[lz.member] && r.wants(g) {
			r.pending = append(r.pending, lz)
		}
		return g, nil
	}

	cur := r.rank[g]

	// Two commons do not clash. The result is the largest size and the
	// strictest alignment, which is what makes a tentative definition
	// repeatable across translation units.
	if cand == rankCommon && cur == rankCommon {
		if s.Size > g.Size {
			g.Size = s.Size
		}
		if s.Value > g.Value {
			g.Value = s.Value
		}
		return g, nil
	}

	if cand == rankGlobalDef && cur == rankGlobalDef {
		// Two absolute symbols agreeing on a value are not a conflict; they
		// are the same constant written twice.
		if !(s.Absolute() && g.Class == image.SymAbsolute && g.Value == s.Value) &&
			!r.l.opts.AllowMultipleDefinition {
			return nil, &DuplicateError{
				Name: s.Name, First: g.Input, Second: in,
				FirstIn: g.Chunk, SecondIn: chunks[s.Shndx],
			}
		}
		return g, nil
	}

	if cand <= cur {
		return g, nil
	}

	g.Class = classOf(s, chunks)
	g.Bind = s.Bind
	g.Type = s.Type
	g.Value = s.Value
	g.Size = s.Size
	g.Input = in
	g.Chunk = chunks[s.Shndx]
	if g.Class != image.SymRegular {
		g.Chunk = nil
	}
	r.rank[g] = cand
	return g, nil
}

// candidateRank scores an object symbol.
func candidateRank(s *obj.Symbol) rank {
	if !s.Defined() {
		if s.Bind == elf.STB_WEAK {
			return rankUndefWeak
		}
		return rankUndef
	}
	if s.Common() {
		return rankCommon
	}
	if s.Bind == elf.STB_WEAK {
		return rankWeakDef
	}
	return rankGlobalDef
}

// classOf maps an object symbol's placement to a SymClass.
func classOf(s *obj.Symbol, chunks map[uint32]*image.Chunk) image.SymClass {
	switch {
	case s.Common():
		return image.SymCommon
	case s.Absolute():
		return image.SymAbsolute
	}
	if _, ok := chunks[s.Shndx]; ok {
		return image.SymRegular
	}
	// A definition in a section that contributes nothing — a symbol in a
	// discarded group, or in a section this linker drops — is treated as
	// absolute at its recorded value rather than as a dangling regular
	// definition with no home.
	return image.SymAbsolute
}

// objSource adapts a parsed section to image.ChunkSource.
//
// Relocs maps symbol table indexes through the input's Syms slice, which is
// filled during resolution. Chunk caches the result on first call, and the
// first call happens during garbage collection — after resolution — so the
// mapping is complete by the time anyone asks.
type objSource struct {
	sec *obj.Section
	in  *image.Input
}

func (s *objSource) Bytes() ([]byte, error) { return s.sec.Data() }

func (s *objSource) Relocs() ([]image.Reloc, error) {
	rs, err := s.sec.Relocs()
	if err != nil {
		return nil, err
	}
	if len(rs) == 0 {
		return nil, nil
	}
	out := make([]image.Reloc, len(rs))
	for i, r := range rs {
		out[i] = image.Reloc{
			Offset:   r.Offset,
			Sym:      s.in.SymAt(r.SymIndex),
			Type:     r.Type,
			Addend:   r.Addend,
			Explicit: r.Explicit,
		}
	}
	return out, nil
}