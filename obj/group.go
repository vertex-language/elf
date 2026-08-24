package obj

import (
	"fmt"

	"github.com/vertex-language/elf"
)

// Group is a decoded SHT_GROUP section: a set of sections that must be kept
// or discarded together.
//
// For a COMDAT group the signature symbol's name is the deduplication key. Two
// objects offering groups with the same signature contribute the same
// definition, and the linker keeps exactly one.
type Group struct {
	// Section is the SHT_GROUP section itself.
	Section *Section

	Flags uint32

	// Signature is the symbol naming this group, from sh_info. Nil if the
	// index was out of range.
	Signature *Symbol

	// Members are the sections in the group. Never nil-padded: an index that
	// names no section is an error rather than a silent hole, because a group
	// that half-exists cannot be correctly kept or discarded.
	Members []*Section
}

// COMDAT reports whether this group is subject to deduplication.
func (g *Group) COMDAT() bool { return g.Flags&elf.GRP_COMDAT != 0 }

// Key returns the deduplication key for a COMDAT group: its signature symbol's
// name. Groups without a resolvable signature return the empty string, which
// callers must treat as "do not deduplicate" rather than as a key.
func (g *Group) Key() string {
	if g.Signature == nil {
		return ""
	}
	return g.Signature.Name
}

// Groups decodes every SHT_GROUP section in the object.
func (f *File) Groups() ([]Group, error) {
	var out []Group
	for _, sec := range f.Sections {
		if sec.Type != elf.SHT_GROUP {
			continue
		}
		g, err := f.decodeGroup(sec)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, nil
}

func (f *File) decodeGroup(sec *Section) (Group, error) {
	symtab := f.SectionAt(sec.Link)
	if symtab == nil {
		return Group{}, fmt.Errorf("obj: group section %q sh_link %d names no symbol table",
			sec.Name, sec.Link)
	}
	syms, err := f.SymbolsOf(symtab)
	if err != nil {
		return Group{}, err
	}

	data, err := sec.Data()
	if err != nil {
		return Group{}, fmt.Errorf("obj: reading %q: %w", sec.Name, err)
	}
	if len(data) < 4 || len(data)%4 != 0 {
		return Group{}, fmt.Errorf("obj: group section %q has malformed size %d", sec.Name, len(data))
	}

	g := Group{
		Section:   sec,
		Flags:     f.bo.Uint32(data[0:4]),
		Signature: symAt(syms, sec.Info),
	}
	for off := 4; off+4 <= len(data); off += 4 {
		idx := f.bo.Uint32(data[off : off+4])
		m := f.SectionAt(idx)
		if m == nil {
			return Group{}, fmt.Errorf("obj: group %q member %d names section %d, which does not exist",
				sec.Name, (off-4)/4, idx)
		}
		g.Members = append(g.Members, m)
	}
	return g, nil
}