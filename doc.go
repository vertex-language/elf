// Package elf defines the ELF object file format's identities, constants, and
// target descriptions.
//
// The package is pure data and pure functions. It performs no I/O, allocates
// nothing that outlives a call, and imports nothing from the rest of the
// module. Everything above it — obj, ar, image, link, and the backends —
// depends on it; it depends on nothing.
//
// Width is expressed as Class throughout. There is no Bits field and no wide
// bool in this package's API: Class is the single representation, and
// Class.Wide reports it as a bool for the one layer (internal/binio) that
// speaks bytes rather than ELF.
package elf