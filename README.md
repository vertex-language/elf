# elf

Read, write, and link ELF — relocatable objects, static libraries, executables, and shared objects.

```go
go get github.com/vertex-language/elf
```

Zero dependencies. The decoders, encoders, and the linker are written from the gABI, the ELF specification, and the individual psABI documents.

---

## Status

**Nothing is implemented yet.** This document is the design, not a description of
working code. It is written in the present tense because it is the contract the
implementation is being held to, not because the code exists.

| Component | State |
| --- | --- |
| `elf` (constants, `Target`, detection) | not started |
| `internal/binio`, `internal/strtab` | not started |
| `internal/format` | not started |
| `obj` (ET_REL read/write) | not started |
| `ar` | not started |
| `image`, `backend`, `link` | not started |
| `x86_64` | not started |

Every section below marked **Planned** describes an API that does not exist. When
a package lands, its row above changes and its examples stop carrying the marker.

---

## Scope

| In | Out |
| --- | --- |
| `ET_REL` read + write | DWARF (`.debug_*` round-trips as opaque bytes) |
| `ET_EXEC` / `ET_DYN` write, and read to the depth a link needs | Any other container format |
| `ar` in the flavors ELF toolchains produce | Disassembly |
| Symbol resolution, layout, relocation, dynamic metadata | Linker scripts (see the configuration API) |

---

## Design rules

These are the invariants. Code that violates one is a bug even if it produces
correct output.

**One definition of the wire format.** Every on-disk ELF structure is defined
exactly once, in `internal/format`, with symmetric `Decode`/`Encode`. No package
hand-indexes header bytes and no package re-derives a structure size. If you find
yourself writing `52` or `64` outside `internal/format`, stop.

**Class is the only width.** `elf.Class` is the single representation of 32-vs-64.
There is no `Bits uint8` and no `wide bool` in any exported API. `Class.Wide()`
is total — it never panics.

**No panics on input.** Anything reachable from parsing attacker-controlled bytes
returns an error. Panics are reserved for API misuse by the caller (nil
`ByteOrder`, `Add` after `Finish`) and are documented on the method.

**Read types and write types are distinct.** A parsed `obj.Section` and a
`obj.SectionBuilder` under construction are different types. There is no struct
with a `file != nil` branch in half its methods and a `buf != nil` branch in the
other half, and no field whose meaning depends on which world it came from.

**Machine-specific knowledge lives behind `backend.Backend`.** Addend widths,
instruction-field encodings, relaxation, PLT/GOT shapes, and REL implicit-addend
handling are psABI properties. The generic reader does not guess them.

**Every package has golden-file tests before it is called done.** Objects we
write are diffed against `llvm-readobj --elf-output-style=GNU`; objects we read
are compared field-by-field against the same. A component without a
toolchain-diffed test is "unverified," and the status table says so.

---

## Repo layout

```text
github.com/vertex-language/elf/
├── class.go               # Class, Data, Endian, EV_CURRENT
├── machine.go             # Machine, Arch, ArchOf, Machine↔Arch
├── section.go             # SHType, SHF_*, SHN_*, GRP_*
├── symbol.go              # SymBind, SymType, SymVisibility, SymInfo
├── program.go             # ProgType, PF_*
├── dynamic.go             # DynTag, DF_*, DF_1_*
├── compress.go            # CompressionType
├── eflags_arm.go          # EF_ARM_*
├── eflags_mips.go         # EF_MIPS_*
├── eflags_riscv.go        # EF_RISCV_*
├── reloc_x86_64.go        # R_X86_64_*  + String()
├── reloc_aarch64.go       # R_AARCH64_* + String()
├── reloc_*.go             # one file per psABI
├── target.go              # Target, ParseTarget, OS, ABI
├── detect.go              # Is, KindOf, MagicSize, KindPrefix
├── errors.go              # ErrNotELF, ErrInvalidTarget, ErrUnsupported*
│
├── internal/
│   ├── binio/             # bounded cursor, append buffer, LEB128
│   ├── format/            # THE wire format: Ehdr/Phdr/Shdr/Sym/Rel/Dyn/Chdr
│   └── strtab/            # dedup + tail-sharing
│
├── obj/                   # ET_REL — the relocatable side
│   ├── file.go            # NewFile/Open, header + section table
│   ├── section.go         # Section (read): Data, Open, Notes
│   ├── symbol.go          # symbol table, SHT_SYMTAB_SHNDX, st_other
│   ├── reloc.go           # REL/RELA/CREL decode
│   ├── group.go           # SHT_GROUP
│   ├── writer.go          # Writer, SectionBuilder, SymRef
│   └── layout.go          # Writer.Close — the emit pass
│
├── ar/                    # GNU/SysV `/`, `/SYM64/`, GNU thin
│
├── image/                 # the linked side — output model
│   ├── image.go           # Image, buffer, reserved symbols
│   ├── section.go         # OutputSection, Segment, SegFlags
│   ├── chunk.go           # Input, Chunk, ChunkSource, Fragment, Reloc
│   ├── symbol.go          # Sym, Class, Visibility, SymbolTable
│   └── synthetic.go       # Synthetic, Finalizer
│
├── backend/               # Backend interface + registry (public: backends import it)
│
├── link/                  # the link pipeline — ONE package
│   ├── link.go            # Linker, New, Link()
│   ├── input.go           # AddFile/AddObject/AddArchive/AddShared
│   ├── options.go         # Options — the single configuration truth
│   ├── errors.go          # UndefinedError, DuplicateError, OverflowError, …
│   ├── resolve.go         # symbol resolution, archive fixpoint, COMDAT
│   ├── split.go           # .eh_frame → CIE/FDE, mergeable fragments
│   ├── gc.go              # reachability sweep
│   ├── merge.go           # dedup, decompress, output sections
│   ├── order.go           # section ordering, RELRO
│   ├── assign.go          # address and offset assignment
│   ├── relax.go           # relaxation and thunk fixpoint
│   ├── apply.go           # relocation application
│   ├── dynamic/ hash/ version/ ehframe/ note/ emit/
│   └── read.go            # dependency .so reading
│
└── x86_64/                # Backend: scan, apply, relax, PLT/GOT
```

Three notes on the shape, since the previous cut got them wrong:

- **`link` is one package.** `resolve`, `gc`, and `layout` were separate packages
  in the first attempt, and crossing the boundary cost five injected callbacks
  (`RelocsFunc`, `RetainFunc`, `AttachFunc`, `SegmentFunc`, `GrowFunc`) whose
  contracts lived nowhere. None had a second caller. Pipeline steps take
  `*image.Image` and `*Options` directly.
- **`backend` is its own root-level package.** Backends are public (users
  blank-import them), so they cannot reach into `link/internal`. The interface
  and registry sit where both sides can see them, and `link` never imports
  `x86_64`.
- **`internal/format` exists from day one.** It is cheap now and impossible
  later: the moment `emit` and `read.go` are written, the header layout is
  duplicated in four places and nobody consolidates it.

---

## Package tour

### `elf` — identity and constants

Enumerations, flag constants, per-psABI relocation tables, and the `Target`
type. No I/O. No dependency on anything else in the repo.

Relocation constants get one file per psABI with a `String()` method each, so
`reloc_x86_64.go` can be five hundred lines without burying `machine.go`.

### `internal/binio` — bounded byte access

```go
c := binio.NewCursor(data, binary.LittleEndian)
v := c.U32()            // returns 0 and latches an error past the end
s := c.CString()
sub := c.Next(24)       // relative to current position
if err := c.Err(); err != nil { … }
```

The cursor accumulates the first error and keeps going, so a parse can read a
whole structure and check once. Bounds failures unwrap to `binio.ErrTruncated`.

`Buf` is the write side: order-aware appends, `Align`, `Zero`, and reservation
patches (`Reserve32().Set(v)`) for backpatching lengths and offsets.

ULEB/SLEB128 live here as `Cursor.ULEB/SLEB` and `Buf.ULEB/SLEB` — CREL,
`.debug_*`, and `.gnu.version` all need them, and exactly one implementation
should exist.

`Sub` and `Next` use one coordinate system: both are relative to the cursor's
current position. (`SubAt` takes an absolute offset when that is what you mean.)

### `internal/format` — the wire format

```go
type Shdr struct {
    Name, Type            uint32
    Flags, Addr, Off, Size uint64
    Link, Info            uint32
    Addralign, Entsize    uint64
}

func (h *Shdr) Decode(c *binio.Cursor, cl elf.Class) error
func (h *Shdr) Encode(b *binio.Buf, cl elf.Class)
func ShdrSize(cl elf.Class) int64
```

Same pattern for `Ehdr`, `Phdr`, `Sym`, `Rel`, `Rela`, `Dyn`, `Chdr`, `Verdef`,
`Verdaux`, `Verneed`, `Vernaux`. Class-parameterised, both directions, sizes
from one table.

`obj` reads and writes through these. So does `link/emit`. So does `link/read.go`
when it parses dependency shared objects. That is three consumers on day one and
the reason the package is not optional.

### `internal/strtab` — string table builder

Deduplicating builder with tail-sharing: `"printf"` and `"f"` share bytes when
one is a suffix of the other. `Add` returns a `*Ref`; offsets are only readable
after `Finish`, which is enforced.

The tail-sharing pass sorts reversed-descending and compares each string only
against the previously *emitted* one, which is what makes chains
(`abc`/`bc`/`c`) collapse correctly. That is subtle enough to deserve both a
comment and a test.

### `obj` — relocatable objects

Reading and writing are separate type families.

**Read.** `obj.File` is immutable after parse. `Section` exposes `Data()`,
`Open()`, `Notes()`, `Relocs()`. Symbols are parsed once per symbol table and
cached by section, so `*Symbol` pointer identity is stable across every call —
the linker keys on those pointers.

`SHF_COMPRESSED` sections report `Compressed` and their `Chdr`; the object
reader hands back the compressed bytes as they sit. Decompression is the
linker's job.

**Write.** `Writer` produces `*SectionBuilder` and `SymRef` handles. On `Close`
it sorts symbols local-first, sets `sh_info`, builds `.strtab` and `.shstrtab`
with tail-sharing, picks REL vs RELA from the target, and escapes to
`SHT_SYMTAB_SHNDX` past 65,279 sections. `Close` is idempotent-guarded: calling
it twice is an error, not a second `.note.GNU-stack`.

REL implicit-addend encoding requires a registered backend, because the addend
does not live in a raw 32-bit word on every machine — `R_ARM_CALL` puts it in an
imm24 field. Without a backend for a REL-using target, `Close` fails loudly
rather than corrupting the section.

CREL support is planned and gated on verifying the encoding against LLVM's
`decodeCrel`, not on memory of the proposal.

### `ar` — archives

SysV/GNU with `/` and `/SYM64/` indexes, GNU long names via `//`, and GNU thin
archives. BSD `#1/NN` names are rejected with a clear error rather than parsed
into garbage.

The writer takes symbol lists per member; `ar` does not import `obj`. A helper
in `link` extracts them.

### `image` — the output model

`Image` owns output sections, segments, the symbol table, and the output buffer.
`Input` and `Chunk` model contributions from input files.

```go
type ChunkSource interface {
    Bytes() ([]byte, error)
    Relocs() ([]Reloc, error)
}
```

One interface, replacing the `Raw any` + `loader func()` pair from the first
attempt. Backends and synthetic sections implement it; `any` stays out of the
core model.

Chunk liveness is **two** flags, not one:

- `Discarded` — lost a COMDAT group election. Set during resolve. GC never
  resurrects a discarded chunk, even when a relocation points at it.
- `Reachable` — survived the GC sweep.

Collapsing these was a real bug in the first attempt: a relocation into a
discarded COMDAT would revive it.

Output section names are **not** unique — ELF permits two `.text` sections in
the output — so the lookup map is keyed by `(name, flags)` and no section is
ever renamed to `.text$1` on its way to disk.

`Segment.Flags` is `SegFlags` (`PF_R/W/X`), a different type from
`SecFlags` (`SHF_*`). They are not the same flag space.

### `backend` — per-architecture behavior

```go
type Backend interface {
    Machine() elf.Machine
    Scan(*image.Image, *Reqs) error      // GOT/PLT/copy/TLS decisions
    Apply(site Site, r image.Reloc) error
    Relax(*image.Image) (changed bool, err error)
    RelAddend(sec []byte, off uint64, typ uint32) (int64, bool)
    Plt() PltShape
    Thunk() ThunkShape
}

func Register(b Backend)
func For(t elf.Target) (Backend, error)   // elf.ErrNoBackend if unregistered
```

Registration is by `elf.Machine`. `link` calls only through this interface.

### `link` — the pipeline

`Link()` is a fixed, straight-line sequence over one `*image.Image`. Single
convergence loop — the previous design nested a `grows` fixpoint inside
`Assign` *and* wrapped `assign` in a relax fixpoint, which is how you get
non-convergence that only shows up on large links.

```go
img := image.New(t)
tbl, err := l.resolve(img)     // 1. symbols, archive fixpoint, COMDAT
img.DeclareStartStop()         // 1a. __start_/__stop_ brackets
l.split(img)                   // 2. .eh_frame → CIE/FDE, mergeables
l.gc(img)                      // 3. reachability (sets Reachable)
l.checkUndefined(tbl)
l.merge(img)                   // 4. dedup, decompress, output sections
reqs, err := l.scan(img, be)   // 5. GOT/PLT/copy/TLS
l.registerSynthetics(img, reqs)
img.Seal()
l.order(img)                   // 6. ordering incl. RELRO grouping

for {                          // 7. the one fixpoint
    l.assign(img)              //    addresses and offsets
    l.bind(img)
    grew, err := l.growThunks(img)
    relaxed, err := l.relax(img, be)
    if !grew && !relaxed { break }
}

l.commit(img)                  // 8. .eh_frame patch, final binding
l.bindDynamic(img, reqs)
img.Freeze()
l.applyAll(img, be, reqs)      // 9. relocations
emit.Write(img, reqs)          // 10. ehdr, phdrs, shdrs
image.Finalize(img)            // 11. hash-then-patch
```

Failure to converge is `ErrLayoutDivergence`, not an anonymous `fmt.Errorf`.

**Ordering** is a name-pattern table with `SecFlags` as the fallback for
unmatched names. Flags alone cannot express `.interp` first, `.tdata`/`.tbss`
adjacency, or RELRO — `.data.rel.ro`, `.got`, and `.got.plt` must be contiguous
and page-aligned for a PIE link, and nothing in `SHF_*` says so.

**Merge** is fragment-aware. Splitting `.eh_frame` and mergeable sections into
fragments is pointless if layout then places whole chunks: dead FDEs keep their
space and duplicate strings never dedup.

---

## Quick start

### Read an object — **Planned**

```go
import (
    "github.com/vertex-language/elf"
    "github.com/vertex-language/elf/obj"
)

f, err := obj.Open("hello.o")
if err != nil {
    return err
}
defer f.Close()

fmt.Println(f.Target())   // x86-64/linux-gnu/little/64

for _, s := range f.Sections {
    fmt.Printf("%-20s %-14v %6d bytes  align=%d\n",
        s.Name, s.Type, s.Size, s.Addralign)
}

syms, err := f.Symbols()
if err != nil {
    return err
}
for _, s := range syms {
    if s.Bind == elf.STB_GLOBAL && s.Undefined() {
        fmt.Println("undefined:", s.Name)
    }
}
```

### Write an object — **Planned**

```go
w := obj.NewWriter(out, obj.Options{
    Target:   t,
    GNUStack: elf.StackNonExec,
})

text := w.Section(obj.SectionHeader{
    Name:      ".text",
    Type:      elf.SHT_PROGBITS,
    Flags:     elf.SHF_ALLOC | elf.SHF_EXECINSTR,
    Addralign: 16,
})
text.Write(code)

main := w.Symbol(obj.Symbol{
    Name: "main", Bind: elf.STB_GLOBAL, Type: elf.STT_FUNC,
    Section: text, Size: uint64(len(code)),
})
puts := w.Symbol(obj.Symbol{Name: "puts", Bind: elf.STB_GLOBAL})

w.Reloc(text, obj.Reloc{
    Offset: 0x0f, Sym: puts,
    Type: uint32(elf.R_X86_64_PLT32), Addend: -4,
})

err := w.Close()
```

`Options` takes a `Target`, not a loose `Class`/`Data`/`Machine` triple — those
three can disagree, and a `Target` cannot.

### Link — **Planned**

```go
import (
    "github.com/vertex-language/elf"
    "github.com/vertex-language/elf/link"
    _ "github.com/vertex-language/elf/x86_64" // registers the backend
)

t, err := elf.ParseTarget("x86_64-linux-gnu")
if err != nil {
    return err
}

l := link.New(t)
l.SetEntry("_start")
l.AddFile("main.o", mainBytes)
l.AddFile("libc.a", libcBytes)

img, err := l.Link()
if err != nil {
    return err
}
os.WriteFile("a.out", img.Bytes(), 0o755)
```

### In-memory composition — **Planned**

The object writer's output is the linker's input. No file round-trip, no
re-decode:

```go
var buf bytes.Buffer
w := obj.NewWriter(&buf, obj.Options{Target: t})
// … emit a generated object …
w.Close()

l.AddObject("generated.o", buf.Bytes())
```

### Archives — **Planned**

```go
import "github.com/vertex-language/elf/ar"

aw := ar.NewWriter(out, ar.Options{Thin: false, Deterministic: true})
aw.Add(ar.Member{Name: "hello.o", Data: helloObj, Symbols: syms})
err := aw.Close()

lib, err := ar.Open("libhello.a")
for _, e := range lib.Index {
    // e.Name, e.MemberOffset
}
```

---

## Target and detection

```go
type Target struct {
    Arch   Arch
    Class  Class
    Endian Endian
    OS     OS      // OSLinux, OSFreeBSD, OSNone, …
    ABI    ABI     // ABIGNU, ABIGNUEabiHF, ABIMusl, ABINone
    Flags  uint32  // e_flags — EF_ARM_*, EF_MIPS_*, EF_RISCV_*
}

func ParseTarget(triple string) (Target, error)

func (t Target) Machine() Machine   // Arch + Class → e_machine
func (t Target) Wide() bool
func (t Target) Valid() bool
func (t Target) String() string     // "x86-64/linux-gnu/little/64"
```

Three things the first attempt got wrong and this one fixes:

- **The environment component is kept.** `arm-linux-gnueabi` and
  `arm-linux-gnueabihf` produce different `Target`s, and the difference lands in
  `Flags` as `EF_ARM_ABI_FLOAT_SOFT` vs `EF_ARM_ABI_FLOAT_HARD`. Discarding it
  makes those constants unreachable.
- **`OSABI` is not parsed from the triple.** `musl` is not `ELFOSABI_GNU`, and
  most Linux binaries are `ELFOSABI_NONE` regardless. `e_ident[EI_OSABI]` is
  decided at emit time from what was actually emitted — `STB_GNU_UNIQUE` or
  `STT_GNU_IFUNC` force `ELFOSABI_GNU`; nothing else does.
- **`Machine → Arch` takes a `Class`.** `EM_MIPS`, `EM_RISCV`, and `EM_LOONGARCH`
  are ambiguous without it. `elf.ArchOf(m, cl)` is the only conversion, so no
  caller patches up the result afterward.

Detection:

```go
elf.MagicSize   // 4  — bytes Is needs
elf.KindPrefix  // 18 — bytes KindOf needs

elf.Is(head)      // ELF magic present
elf.KindOf(head)  // KindRel | KindExec | KindDyn | KindCore, from e_type
```

`KindOf` verifies the magic before trusting `e_ident[EI_DATA]`.

---

## Configuration without linker scripts — **Planned**

Linker scripts are not supported. For custom layouts (bare metal, UEFI), use the
configuration API:

```go
l.SetSectionOrder([]string{".text.boot", ".text", ".rodata"})
l.SetSectionAddress(".text.boot", 0x8000_0000)
l.Provide("__stack_top", link.SymbolExpr{Section: ".stack", At: link.AnchorEnd})
l.Keep(".init_array*")   // GC roots
```

`link.AnchorStart`/`link.AnchorEnd` are the same constants `image` uses. There is
one anchor vocabulary.

---

## Errors

Bounded, class-aware cursors parse attacker-controlled binaries without
panicking. Bounds failures unwrap to `internal/binio.ErrTruncated`.

Errors live in the package that returns them.

| Error | Cause |
| --- | --- |
| `elf.ErrNotELF` | Missing ELF magic |
| `elf.ErrInvalidTarget` | Triple rejected by `Valid()` |
| `elf.ErrUnsupportedClass` | `e_ident[EI_CLASS]` is neither 32 nor 64 |
| `elf.ErrUnsupportedData` | `e_ident[EI_DATA]` is neither LSB nor MSB |
| `obj.ErrNotRelocatable` | `ET_EXEC`/`ET_DYN` passed to the object reader |
| `ar.ErrNotArchive` | Missing `!<arch>` / `!<thin>` magic |
| `ar.ErrBadHeader` | Malformed member header |
| `backend.ErrNoBackend` | Valid target, but the backend was not blank-imported |
| `link.ErrLayoutDivergence` | The relax/thunk loop failed to converge |
| `link.ErrMachineMismatch` | Input `e_machine`/`e_flags` disagrees with the target |
| `*link.UndefinedError` | Unresolved name, with referencing object and section |
| `*link.DuplicateError` | Multiple definitions, with both sources |
| `*link.OverflowError` | Bounds failure on site, symbol, or relocation type |

`obj.ErrNotRelocatable` is actually returned: the object reader checks `e_type`.

---

## Testing

No component is "done" without:

1. **Round-trip.** Write with `obj`/`ar`, read back, compare structurally.
2. **Toolchain diff.** Write with `obj`, dump with `llvm-readobj
   --elf-output-style=GNU`, compare against the same dump of a `clang -c`
   reference object. Committed as golden files under `testdata/`.
3. **Fuzz.** `FuzzParseObject`, `FuzzParseArchive`, `FuzzCursor`. The bar is no
   panic and no unbounded allocation on any input.
4. **Executable smoke test.** Link, run, check exit status — on the host when the
   host matches the target, under QEMU otherwise.

The first attempt had zero tests and, it turned out, did not compile. That is the
failure mode this section exists to prevent.

---

## Roadmap

**M1 — foundation.** `elf` constants and `Target`; `internal/binio` including
LEB128; `internal/format` for Ehdr/Shdr/Sym/Rel/Rela; `internal/strtab`. Fuzz
targets for the cursor. No I/O above `binio`.

**M2 — objects.** `obj` read and write, REL/RELA, groups, notes, extended
indexes. Golden-file diffs against clang output for x86-64 and aarch64. This is
the first point where anything is usable.

**M3 — archives.** `ar` read and write, thin and `/SYM64/`. Diffed against
`llvm-ar`.

**M4 — static link.** `image`, `backend`, `link` through `applyAll` and `emit`.
`x86_64` backend: `R_X86_64_*` apply, no PLT/GOT. Statically links and runs
`hello.o` + a trivial libc.

**M5 — dynamic.** GOT/PLT, `.dynamic`, `.gnu.hash`, versioning, RELRO ordering,
PIE. `link/read.go` for dependency `.so` files, plus `-lfoo` search.

**M6 — breadth.** `aarch64`, then `riscv64`. Relaxation and thunks land here,
since x86-64 needs neither badly enough to design them well.

CREL, `SHT_RELR`, and `SHF_COMPRESSED` output are post-M5 and each gated on
verification against a reference implementation.