package obj

// stringAt returns the NUL-terminated string beginning at off in a string
// table blob.
//
// An out-of-range offset yields the empty string rather than an error: a
// symbol or section with an unreadable name is nameless, which every consumer
// here can already represent, and failing the whole parse over one bad
// sh_name would make otherwise-usable objects unreadable.
func stringAt(blob []byte, off uint32) string {
	if uint64(off) >= uint64(len(blob)) {
		return ""
	}
	rest := blob[off:]
	for i := 0; i < len(rest); i++ {
		if rest[i] == 0 {
			return string(rest[:i])
		}
	}
	// Unterminated final entry. Return what is there.
	return string(rest)
}