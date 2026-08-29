# elf

Read, write, and link ELF — relocatable objects, SysV/GNU Unix archives (`.a`), and linked executables and shared objects.

## Install

```sh
go get github.com/vertex-language/elf
```

Backends register themselves via blank import, so a build only pays for the architectures it uses:

```go
import _ "github.com/vertex-language/elf/x86_64" // registers AMD64
```

## Contents

- [Package map](#package-map)
- [Quick start](#quick-start)
  - [Detect and classify a file](#detect-and-classify-a-file)
  - [Parse a target triple](#parse-a-target-triple)
  - [Read a relocatable object](#read-a-relocatable-object)
  - [Write a relocatable object](#write-a-relocatable-object)
  - [Read a static library](#read-a-static-library)
  - [Link an executable](#link-an-executable)
- [How it's put together](#how-its-put-together)

## Package map

The module is layered, and each package only imports the ones below it:

| Package | Purpose |
|---|---|
| `elf` | Core identities, constants, and target descriptions. Pure data, no I/O. Everything else depends on it. |
| `obj` | Reads and writes ET_REL relocatable objects. |
| `ar` | Reads and writes SysV/GNU Unix archives (`.a`), including GNU thin archives. |
| `image` | The linker's output model — chunks, output sections, segments, synthetics. |
| `backend` | The per-architecture interface a linker backend implements (`Scan`, `Apply`, PLT/GOT shapes, relaxation, thunks). |
| `link` | The link pipeline: resolve, GC, layout, relocate, emit. Never imports a backend directly. |
| `x86_64` | The AMD64 backend. Blank-import it to register support for that architecture. |
| `arm64` | The AArch64 backend. Blank-import it to register support for that architecture. |
| `riscv64` | The RISC-V RV64 backend. Blank-import it to register support for that architecture. |
| `i386` | The Intel 386 backend. Static linking, and dynamic linking wherever nothing needs a PLT; see the package doc for the %ebx/GOT-base gap that excludes PLT support specifically. |

## Quick start

### Detect and classify a file

```go
head := make([]byte, elf.KindPrefix) // 18 bytes
f.Read(head)

if !elf.Is(head) {
	return elf.ErrNotELF
}

kind, err := elf.KindOf(head)
if err != nil {
	log.Fatal(err)
}

switch kind {
case elf.KindRel:
	fmt.Println("relocatable object")
case elf.KindExec:
	fmt.Println("executable")
case elf.KindDyn:
	fmt.Println("shared object or PIE")
case elf.KindCore:
	fmt.Println("core dump")
}
```

### Parse a target triple

```go
t, err := elf.ParseTarget("x86_64-unknown-linux-gnu")
if err != nil {
	log.Fatal(err)
}
fmt.Println(t.String()) // arch/os-abi/endian/bits
fmt.Println(t.Wide())   // true — 64-bit addresses
```

### Read a relocatable object

```go
f, err := obj.Open("main.o")
if err != nil {
	log.Fatal(err)
}
defer f.Close()

syms, err := f.Symbols()
if err != nil {
	log.Fatal(err)
}
for _, s := range syms {
	if s.Defined() && s.Bind == elf.STB_GLOBAL {
		fmt.Println(s.Name, s.Value)
	}
}

if text := f.Section(".text"); text != nil {
	relocs, err := text.Relocs()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(len(relocs), "relocations in .text")
}
```

### Write a relocatable object

```go
w := obj.NewWriter(out, obj.Options{
	Target: elf.Target{
		Arch:   elf.ArchAMD64,
		Class:  elf.ELFCLASS64,
		Endian: elf.EndianLittle,
	},
})

text := w.Section(obj.SectionHeader{
	Name:  ".text",
	Type:  elf.SHT_PROGBITS,
	Flags: uint64(elf.SHF_ALLOC | elf.SHF_EXECINSTR),
})
text.Write(code)

main := w.Symbol(obj.SymbolDef{
	Name:    "main",
	Bind:    elf.STB_GLOBAL,
	Type:    elf.STT_FUNC,
	Section: text, // Where defaults to SymInSection when Section is set
})

w.Reloc(text, obj.RelocSpec{
	Offset: 4,
	Sym:    main,
	Type:   uint32(elf.R_X86_64_PLT32),
})

if err := w.Close(); err != nil {
	log.Fatal(err)
}
```

### Read a static library

```go
r, err := ar.Open("libfoo.a")
if err != nil {
	log.Fatal(err)
}
defer r.Close()

for _, m := range r.Members {
	data, err := m.Data() // errors on a thin member
	if err != nil {
		continue
	}
	fmt.Println(m.Name, len(data), "bytes")
}
```

### Link an executable

```go
import (
	"github.com/vertex-language/elf"
	"github.com/vertex-language/elf/link"
	_ "github.com/vertex-language/elf/x86_64" // register the AMD64 backend
)

t, err := elf.ParseTarget("x86_64-linux-gnu")
if err != nil {
	log.Fatal(err)
}

l := link.New(t)
if err := l.AddFile("main.o", mainData); err != nil {
	log.Fatal(err)
}
if err := l.AddArchive("libc.a", libcData); err != nil {
	log.Fatal(err)
}
l.SetEntry("_start")

opts := l.Options()
opts.GC = true
opts.StripDebug = true
opts.BuildID = true

img, err := l.Link()
if err != nil {
	log.Fatal(err)
}

os.WriteFile("a.out", img.Bytes(), 0o755)
```

## How it's put together

- `elf` has no `Bits`/wide `bool` field anywhere — width is always `Class`, and `Class.Wide()` is the one conversion to a bool, used only at the `internal/binio` boundary.
- `Arch`, not `Machine`, is the identity backends register against: `EM_MIPS`, `EM_RISCV`, and `EM_LOONGARCH` each cover a 32- and a 64-bit architecture, so resolving through `elf.ArchOf(machine, class)` is required wherever a class is available.
- `link` never imports a backend package; backends register themselves via `backend.Register` from an `init` function, so a blank import is all a caller needs.
- `image.Image` moves through three one-way phases — `open`, `sealed` (via `Seal`), `frozen` (via `Freeze`) — and each pipeline step is only legal in one of them.