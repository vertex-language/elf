package link

import (
	"bytes"
	"fmt"
	"os"

	"github.com/vertex-language/elf"
	"github.com/vertex-language/elf/ar"
	"github.com/vertex-language/elf/obj"
)

// fileKind is what an input turned out to be.
type fileKind uint8

const (
	kindObject fileKind = iota
	kindArchive
	kindShared
)

func (k fileKind) String() string {
	switch k {
	case kindArchive:
		return "archive"
	case kindShared:
		return "shared object"
	}
	return "object"
}

// inputFile is one entry on the link line, before anything has been read out
// of it. Members and symbols appear during resolve, not here: an archive
// nothing needs should cost one magic-number check.
type inputFile struct {
	name string
	kind fileKind
	data []byte

	// group is the index of the Options.Groups range this file falls in, or
	// -1. Files in one group are rescanned together until no new member is
	// extracted.
	group int

	// whole forces every member of an archive to be extracted, the
	// equivalent of --whole-archive.
	whole bool
}

// AddFile adds an input, deciding what it is from its first bytes.
//
// Sniffing rather than trusting the extension: a .a that is really an object,
// or an .o that is really a thin archive, are both things build systems
// produce, and guessing from the name turns them into a parse error much
// further down.
func (l *Linker) AddFile(name string, data []byte) error {
	switch {
	case ar.Is(data):
		return l.AddArchive(name, data)
	case elf.Is(data):
		k, err := elf.KindOf(data)
		if err != nil {
			return fmt.Errorf("link: %s: %w", name, err)
		}
		switch k {
		case elf.KindRel:
			return l.AddObject(name, data)
		case elf.KindDyn:
			return l.AddShared(name, data)
		case elf.KindExec:
			return fmt.Errorf("link: %s: an executable is not a valid link input", name)
		case elf.KindCore:
			return fmt.Errorf("link: %s: a core file is not a valid link input", name)
		}
		return fmt.Errorf("link: %s: ELF file of a kind this linker does not accept", name)
	}
	return fmt.Errorf("link: %s: %w", name, elf.ErrNotELF)
}

// OpenFile reads a file from disk and adds it.
func (l *Linker) OpenFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("link: %w", err)
	}
	return l.AddFile(path, data)
}

// AddObject adds a relocatable object.
func (l *Linker) AddObject(name string, data []byte) error {
	l.files = append(l.files, &inputFile{name: name, kind: kindObject, data: data, group: -1})
	return nil
}

// AddArchive adds a static library. Its members are extracted lazily, only
// when one of them defines a symbol the link needs.
func (l *Linker) AddArchive(name string, data []byte) error {
	l.files = append(l.files, &inputFile{name: name, kind: kindArchive, data: data, group: -1})
	return nil
}

// AddWholeArchive adds a static library every member of which is extracted
// regardless of need.
func (l *Linker) AddWholeArchive(name string, data []byte) error {
	l.files = append(l.files, &inputFile{
		name: name, kind: kindArchive, data: data, group: -1, whole: true,
	})
	return nil
}

// AddShared adds a dependency shared object, which contributes definitions and
// a DT_NEEDED entry but no content.
func (l *Linker) AddShared(name string, data []byte) error {
	if l.opts.Static {
		return fmt.Errorf("link: %s: %w", name, ErrStaticShared)
	}
	l.files = append(l.files, &inputFile{name: name, kind: kindShared, data: data, group: -1})
	return nil
}

// StartGroup and EndGroup bracket a range of inputs that is rescanned until it
// stops yielding members, for mutually recursive archives.
//
// Without this an archive can only satisfy references known when the linker
// reached it, so a pair of libraries each calling into the other must be
// listed twice on the command line.
func (l *Linker) StartGroup() {
	l.opts.Groups = append(l.opts.Groups, Group{First: len(l.files), Last: -1})
}

// EndGroup closes the most recent open group.
func (l *Linker) EndGroup() error {
	for i := len(l.opts.Groups) - 1; i >= 0; i-- {
		if l.opts.Groups[i].Last < 0 {
			l.opts.Groups[i].Last = len(l.files)
			return nil
		}
	}
	return fmt.Errorf("link: EndGroup with no open group")
}

// openObject parses one object from memory.
func openObject(name string, data []byte) (*obj.File, error) {
	f, err := obj.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("link: %s: %w", name, err)
	}
	return f, nil
}

// openArchive parses an archive's directory from memory.
func openArchive(name string, data []byte) (*ar.Reader, error) {
	r, err := ar.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("link: %s: %w", name, err)
	}
	return r, nil
}

// memberData returns a member's bytes.
//
// A thin archive's members live in separate files, and only the caller knows
// what they are relative to; this reports that rather than substituting empty
// contents, which would produce an output missing whole translation units with
// no diagnostic at all.
func memberData(archive string, m *ar.Member) ([]byte, error) {
	if m.Thin() {
		data, err := os.ReadFile(m.Name)
		if err != nil {
			return nil, fmt.Errorf("link: %s: thin member %q: %w", archive, m.Name, err)
		}
		return data, nil
	}
	data, err := m.Data()
	if err != nil {
		return nil, fmt.Errorf("link: %s(%s): %w", archive, m.Name, err)
	}
	return data, nil
}

// memberName is what diagnostics call an archive member.
func memberName(archive string, m *ar.Member) string {
	return archive + "(" + m.Name + ")"
}