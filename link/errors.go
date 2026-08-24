package link

import (
	"errors"
	"fmt"

	"github.com/vertex-language/elf/image"
)

var (
	// ErrLayoutDivergence reports that the relax-and-thunk fixpoint did not
	// settle within Options.MaxLayoutRounds. It is its own error rather than
	// an anonymous one because it means a backend is misbehaving, and the
	// person who sees it needs to know that rather than to read a sentence.
	ErrLayoutDivergence = errors.New("link: layout did not converge")

	// ErrMachineMismatch reports an input whose architecture or ABI flags
	// disagree with the output target.
	ErrMachineMismatch = errors.New("link: input does not match the output target")

	// ErrNoEntry reports an executable link whose entry point resolved to
	// nothing.
	ErrNoEntry = errors.New("link: entry point is undefined")

	// ErrStaticShared reports a shared input to a static link.
	ErrStaticShared = errors.New("link: shared object in a static link")
)

// UndefinedError is a reference with no definition.
//
// It names where the reference came from, because "undefined reference to
// foo" without a source is the least useful message a linker emits: the
// question is always which object wanted it.
type UndefinedError struct {
	Name string

	// From is the input that referenced the symbol, and In the chunk within
	// it. Either may be nil when the reference came from an option rather
	// than from an object.
	From *image.Input
	In   *image.Chunk

	// Offset is the reference's position within In.
	Offset uint64
}

func (e *UndefinedError) Error() string {
	if e.In != nil {
		return fmt.Sprintf("link: undefined reference to %q from %s+%#x", e.Name, e.In, e.Offset)
	}
	if e.From != nil {
		return fmt.Sprintf("link: undefined reference to %q from %s", e.Name, e.From)
	}
	return fmt.Sprintf("link: undefined reference to %q", e.Name)
}

// DuplicateError is a name defined more than once, naming both sides. One
// side alone tells the reader half of what they need to fix it.
type DuplicateError struct {
	Name     string
	First    *image.Input
	Second   *image.Input
	FirstIn  *image.Chunk
	SecondIn *image.Chunk
}

func (e *DuplicateError) Error() string {
	return fmt.Sprintf("link: %q is defined in both %s and %s",
		e.Name, describe(e.First, e.FirstIn), describe(e.Second, e.SecondIn))
}

func describe(in *image.Input, ch *image.Chunk) string {
	switch {
	case ch != nil:
		return ch.String()
	case in != nil:
		return in.Name
	}
	return "<unknown>"
}

// OverflowError wraps a backend's range failure with the provenance the
// backend does not have: which input file the relocation came from.
//
// The backend knows the encoding fact — this value does not fit that field.
// It does not know which of four hundred object files produced the section,
// and that is what the user needs.
type OverflowError struct {
	Input *image.Input
	Err   error
}

func (e *OverflowError) Error() string {
	if e.Input == nil {
		return "link: " + e.Err.Error()
	}
	return fmt.Sprintf("link: %s: %s", e.Input.Name, e.Err.Error())
}

func (e *OverflowError) Unwrap() error { return e.Err }

// MismatchError reports an input incompatible with the output target.
type MismatchError struct {
	Input  *image.Input
	Reason string
}

func (e *MismatchError) Error() string {
	return fmt.Sprintf("link: %s: %s: %v", e.Input.Name, e.Reason, ErrMachineMismatch)
}

func (e *MismatchError) Unwrap() error { return ErrMachineMismatch }