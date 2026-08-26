// Package rendersafe holds render-side belts shared by the config generators
// that interpolate operator-supplied text into a third-party daemon's
// configuration file (#6833).
//
// # A function here is NOT a security boundary on its own
//
// Everything in this package is a PRIMITIVE: it performs a byte substitution
// and knows nothing about the grammar it is protecting. Whether that
// substitution is SAFE is a per-consumer fact, because the substituted byte has
// to be ordinary text in the consuming parser. That fact belongs at the call
// site, not here, and every caller is expected to state it.
//
// The failure this package exists to prevent is the one #6833 describes: two
// packages carried byte-identical sanitizers whose doc comments justified them
// by newline injection, while neither recorded whether the SPACE they substitute
// in was safe for its own consumer. A sanitizer whose apparent purpose is "no
// control characters" while the load-bearing constraint is something else invites
// a future edit relaxing it to "printable ASCII" — an edit that looks like a
// cleanup, still blocks the newline the comment names, and admits the byte that
// actually matters. Duplicating the body means that edit can be made twice,
// independently.
//
// So: the body lives here once, and the JUSTIFICATION lives at each call site.
package rendersafe

// ReplaceControlBytes returns s with every ASCII C0 control byte (0x00-0x1F,
// which includes CR and LF) and DEL (0x7F) replaced by repl. All other bytes,
// including every byte of a multi-byte UTF-8 sequence, are returned unchanged —
// C0 and DEL cannot appear as a continuation byte, so this is safe on UTF-8
// input and never splits a rune.
//
// It returns s itself when there is nothing to replace, so the common clean path
// allocates nothing.
//
// # Choosing repl is the caller's decision, and it is the load-bearing one
//
// repl must be a byte the CONSUMING parser treats as ordinary text. A space is
// the usual choice and is wrong wherever the consumer's grammar makes whitespace
// significant — a whitespace-separated list key, or a
// <selector><whitespace><action> line grammar, where substituting a space
// manufactures the very delimiter the sanitizer was supposed to be protecting.
// See #6829 for a case where the space, not the newline, was the live byte.
//
// This function cannot check that for you. State it where you call it.
func ReplaceControlBytes(s string, repl byte) string {
	isCtl := func(c byte) bool { return c < 0x20 || c == 0x7f }

	clean := true
	for i := 0; i < len(s); i++ {
		if isCtl(s[i]) {
			clean = false
			break
		}
	}
	if clean {
		return s
	}
	b := []byte(s)
	for i := range b {
		if isCtl(b[i]) {
			b[i] = repl
		}
	}
	return string(b)
}
