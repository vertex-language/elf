package backend

// Kind is what a relocation means, with the psABI's numbering removed.
//
// Every architecture spells "PC-relative reference to the symbol's PLT entry"
// with its own number — R_X86_64_PLT32, R_AARCH64_CALL26, R_RISCV_CALL_PLT —
// but the scan pass needs the same decision from all three. Classify maps the
// number to one of these, and everything generic reasons in these terms.
//
// The names follow the psABI convention: S is the symbol's address, A the
// addend, P the place being relocated, G the symbol's GOT slot offset, GOT the
// table's base, L the PLT entry's address.
type Kind uint8

const (
	// KindUnknown is a type the backend does not recognise.
	KindUnknown Kind = iota

	// KindNone does nothing. R_*_NONE exists so a relocation can be deleted
	// without renumbering the table.
	KindNone

	// KindAbs is S + A: an absolute address. In a position-independent
	// output these need a dynamic relocation, which is what makes them worth
	// distinguishing from everything below.
	KindAbs

	// KindPC is S + A - P.
	KindPC

	// KindGot is G + A: an offset into the GOT.
	KindGot

	// KindGotPC is GOT + G + A - P: the GOT slot's address, PC-relative.
	KindGotPC

	// KindGotOff is S + A - GOT: the symbol relative to the GOT base.
	KindGotOff

	// KindGotBase is GOT + A - P: the GOT base itself, PC-relative.
	KindGotBase

	// KindPlt is L + A.
	KindPlt

	// KindPltPC is L + A - P: the ordinary call to a possibly-external
	// function.
	KindPltPC

	// KindSize is Z + A, the symbol's size rather than its address.
	KindSize

	// TLS access models, in decreasing generality. A backend that relaxes
	// TLS moves references down this list as it proves the narrower model
	// safe: general-dynamic to initial-exec once the output is known not to
	// be a shared object, initial-exec to local-exec once the symbol is
	// known to be in the executable's own TLS block.
	KindTlsGd
	KindTlsLd
	KindTlsLdOff
	KindTlsIe
	KindTlsLe

	// KindTlsDesc is the descriptor-based model, which x86 and AArch64 use
	// in place of general-dynamic when the toolchain selected it.
	KindTlsDesc

	// KindRelax marks a hint that accompanies another relocation rather than
	// describing a place of its own — R_RISCV_RELAX. It is never applied.
	KindRelax
)

func (k Kind) String() string {
	switch k {
	case KindNone:
		return "none"
	case KindAbs:
		return "abs"
	case KindPC:
		return "pc"
	case KindGot:
		return "got"
	case KindGotPC:
		return "got-pc"
	case KindGotOff:
		return "got-off"
	case KindGotBase:
		return "got-base"
	case KindPlt:
		return "plt"
	case KindPltPC:
		return "plt-pc"
	case KindSize:
		return "size"
	case KindTlsGd:
		return "tls-gd"
	case KindTlsLd:
		return "tls-ld"
	case KindTlsLdOff:
		return "tls-ld-off"
	case KindTlsIe:
		return "tls-ie"
	case KindTlsLe:
		return "tls-le"
	case KindTlsDesc:
		return "tls-desc"
	case KindRelax:
		return "relax"
	}
	return "unknown"
}

// NeedsGot reports whether a reference of this kind reaches its symbol through
// the global offset table.
func (k Kind) NeedsGot() bool {
	switch k {
	case KindGot, KindGotPC, KindTlsGd, KindTlsLd, KindTlsIe, KindTlsDesc:
		return true
	}
	return false
}

// NeedsPlt reports whether a reference of this kind reaches its symbol through
// the procedure linkage table.
func (k Kind) NeedsPlt() bool { return k == KindPlt || k == KindPltPC }

// TLS reports whether this kind is a thread-local access.
func (k Kind) TLS() bool {
	switch k {
	case KindTlsGd, KindTlsLd, KindTlsLdOff, KindTlsIe, KindTlsLe, KindTlsDesc:
		return true
	}
	return false
}

// Relative reports whether the result depends only on the distance between two
// things in the output, and so needs no dynamic relocation however the output
// is loaded. An absolute reference in a PIE does need one; a PC-relative one
// does not, and that difference is the whole reason this method exists.
func (k Kind) Relative() bool {
	switch k {
	case KindPC, KindGotPC, KindGotOff, KindGotBase, KindPltPC, KindNone:
		return true
	}
	return false
}

// DynKind is a dynamic relocation's meaning, independent of psABI numbering.
// Backend.DynType maps it to the architecture's value.
type DynKind uint8

const (
	// DynNone is the no-op relocation.
	DynNone DynKind = iota

	// DynAbsolute is a full-width absolute address needing a symbol lookup.
	DynAbsolute

	// DynRelative adds the load base to a link-time-computed address. It
	// needs no symbol, which is why RELR can pack runs of them.
	DynRelative

	// DynGlobDat writes a symbol's address into a GOT slot, eagerly.
	DynGlobDat

	// DynJumpSlot writes a symbol's address into a .got.plt slot, and may be
	// resolved lazily on first call.
	DynJumpSlot

	// DynCopy copies a shared object's data into the executable's .bss, so
	// that non-PIC references to it keep working.
	DynCopy

	// DynIRelative calls a resolver at load time and stores what it returns.
	// An ifunc cannot use DynJumpSlot: that would make it look preemptible,
	// and the loader would call the resolver expecting the function.
	DynIRelative

	// DynDtpMod, DynDtpOff, and DynTpOff are the thread-local trio: the
	// module identifier, the offset within that module's TLS block, and the
	// offset from the thread pointer.
	DynDtpMod
	DynDtpOff
	DynTpOff
)

func (k DynKind) String() string {
	switch k {
	case DynAbsolute:
		return "absolute"
	case DynRelative:
		return "relative"
	case DynGlobDat:
		return "glob-dat"
	case DynJumpSlot:
		return "jump-slot"
	case DynCopy:
		return "copy"
	case DynIRelative:
		return "irelative"
	case DynDtpMod:
		return "dtpmod"
	case DynDtpOff:
		return "dtpoff"
	case DynTpOff:
		return "tpoff"
	}
	return "none"
}