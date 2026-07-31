// Package termsafe escapes device-originated strings before they are printed
// to an operator's terminal. Several fields the CLI displays are
// attacker-controlled — a DHCP lease hostname (DHCP option 12) and client
// hardware address are supplied by a device on a served segment and stored
// opaque by Kea, and the DHCP dynamic-DNS forward record name is built from
// that same client hostname. Printed verbatim, such a value can carry terminal
// escape sequences (an OSC 52 clipboard write, an OSC 8 hyperlink, CSI
// cursor/erase controls) that the operator's terminal would ACT on when the
// table is displayed — clipboard hijack and output spoofing (a forged "commit
// complete" line, or a rogue lease row erased from view).
//
// The same class covers more than lease data. A DDNS provider's response body
// reaches the operator through the `show services dynamic-dns` LastError column
// (Cloudflare and Route 53 embed the provider message with %s), and captured
// `vtysh` stdout carries text a BGP or IS-IS peer advertised — the BGP hostname
// capability, IS-IS dynamic hostname TLVs. Anything a remote party can put
// bytes into and an operator then reads on a terminal belongs here.
//
// Two entry points, chosen by the SHAPE of the value, not by its source:
//
//   - SanitizeForDisplay for a single-line FIELD rendered into a row the caller
//     formats. LF and TAB are escaped along with everything else, because an
//     embedded newline in a field is itself a forgery vector — it fakes a row.
//   - SanitizeBlockForDisplay for a MULTI-LINE blob whose own line structure is
//     the output (vtysh stdout). LF and TAB are preserved so the table survives;
//     CR and the Unicode line/paragraph separators are not, because they forge
//     or overwrite rows.
//
// This is a leaf package (it imports only the standard library) so BOTH the
// in-process CLI renderer (pkg/cli) and the gRPC text renderer that feeds the
// remote `cli`'s verbatim terminal print (pkg/grpcapi) can guard the same
// device-originated values with one implementation. Every guarded surface must
// be applied on BOTH renderers — the remote `cli` is the more common operator
// posture, and a fix on one alone leaves the other at pre-fix behavior.
// Sanitizing happens at the display boundary only: stored lease data, the
// DDNS status views, and the gRPC/JSON structs are unchanged, so machine
// consumers still receive the raw value. See #6468.
package termsafe

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

const hexDigits = "0123456789abcdef"

// SanitizeForDisplay escapes the terminal-protocol control bytes in a
// device-originated string so the terminal does not ACT on embedded escape
// sequences when the value is printed. Every C0 control byte (0x00-0x1F,
// including ESC), DEL (0x7F), C1 control byte (0x80-0x9F), and invalid UTF-8
// byte is replaced with a visible backslash-hex escape (e.g. an ESC becomes the
// four printable characters \x1b) so the operator sees exactly what the device
// sent instead of the terminal interpreting it. Every printable rune —
// including legitimate multibyte UTF-8, so an international hostname is not
// corrupted — passes through unchanged.
//
// Scope is deliberately narrow. This neutralizes exactly the C0/DEL/C1
// terminal-protocol control bytes and invalid UTF-8 that drive escape-sequence
// injection (OSC clipboard writes, CSI cursor/erase) — unicode.IsControl covers
// only Unicode category Cc. It does NOT address Unicode display-order spoofing:
// bidirectional overrides (U+200E, U+202A-U+202E), line/paragraph separators
// (U+2028/U+2029), and zero-width format (Cf) characters are printable runes and
// pass through unchanged. Defending against Trojan-Source-style bidi reordering
// is a separate, lower-severity concern and out of scope here.
func SanitizeForDisplay(s string) string {
	// Fast path: the overwhelming majority of names are already clean, so
	// return the input without allocating a builder.
	if DisplaySafe(s) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 8)
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			// Invalid UTF-8 byte — escape the raw byte value so a crafted
			// non-UTF-8 sequence cannot smuggle bytes past the rune checks.
			writeHexEscape(&b, s[i])
			i++
			continue
		}
		if unicode.IsControl(r) {
			// Control runes (Unicode category Cc) are all <= U+009F, so a
			// single \xHH byte escape represents each one exactly.
			writeHexEscape(&b, byte(r))
			i += size
			continue
		}
		b.WriteRune(r)
		i += size
	}
	return b.String()
}

// SanitizeBlockForDisplay is SanitizeForDisplay for a MULTI-LINE device- or
// remote-supplied blob — captured `vtysh` stdout, a provider response body, any
// text whose own line structure is part of the output.
//
// It neutralizes the same terminal-protocol control bytes but PRESERVES the two
// layout controls that carry the block's shape: LF (0x0A) and TAB (0x09).
// SanitizeForDisplay escapes those too — correctly, for a single-field value
// where an embedded newline is itself a forgery vector (it can fake a new table
// row) — but applying it to a table would collapse the whole thing into one
// `\x0a`-laden line, which is a display regression rather than a fix.
//
// CR (0x0D) is deliberately NOT preserved. A bare carriage return re-homes the
// cursor and lets later text overwrite a line the operator has already read —
// the same class of display forgery the ESC escaping defends against, and not
// something a legitimate line-oriented blob needs.
//
// U+2028 LINE SEPARATOR and U+2029 PARAGRAPH SEPARATOR are escaped too, and
// this is where the block variant deliberately diverges from SanitizeForDisplay
// rather than inheriting its rationale. Neither is Unicode category Cc, so
// unicode.IsControl does not catch them and the single-line sanitizer — whose
// doc out-scopes bidi/Cf display-order spoofing — lets them through. That is
// defensible for a single-line field, where the caller's own format string
// bounds the row. It is NOT defensible here: the whole premise of this variant
// is that the blob's LINE STRUCTURE is meaningful output, and terminals and
// pagers that honor U+2028 as a break let a peer-advertised hostname forge a
// row in exactly the table this function exists to keep honest. Escaping them
// is the same argument that escapes CR. They render as the visible escapes
// \u2028 / \u2029 (a \xHH byte escape cannot represent a rune above U+00FF).
//
// Bidi overrides and other Cf runes remain out of scope here, as in
// SanitizeForDisplay: they can reorder characters WITHIN a line but cannot
// forge or erase a row, so they are a different, lower-severity class.
func SanitizeBlockForDisplay(s string) string {
	if blockDisplaySafe(s) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 8)
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			writeHexEscape(&b, s[i])
			i++
			continue
		}
		if r == '\n' || r == '\t' {
			b.WriteRune(r)
			i += size
			continue
		}
		if unicode.IsControl(r) {
			writeHexEscape(&b, byte(r))
			i += size
			continue
		}
		if isLineSeparator(r) {
			writeUnicodeEscape(&b, r)
			i += size
			continue
		}
		b.WriteRune(r)
		i += size
	}
	return b.String()
}

// blockDisplaySafe is DisplaySafe with LF and TAB treated as printable and the
// Unicode line/paragraph separators treated as unsafe, so a clean multi-line
// blob keeps the allocation-free fast path while a row-forging separator does
// not slip past it.
func blockDisplaySafe(s string) bool {
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			return false
		}
		if r != '\n' && r != '\t' && unicode.IsControl(r) {
			return false
		}
		if isLineSeparator(r) {
			return false
		}
		i += size
	}
	return true
}

// isLineSeparator reports whether r is a Unicode line/paragraph separator —
// category Zl/Zp, which unicode.IsControl does not cover. Only the block
// sanitizer treats these as unsafe; see SanitizeBlockForDisplay.
func isLineSeparator(r rune) bool {
	return r == '\u2028' || r == '\u2029'
}

// DisplaySafe reports whether s can be printed to a terminal verbatim: it holds
// no control rune and no invalid UTF-8 byte, so SanitizeForDisplay would return
// it unchanged. Splitting this out keeps the common (clean) path allocation-free.
func DisplaySafe(s string) bool {
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			return false
		}
		if unicode.IsControl(r) {
			return false
		}
		i += size
	}
	return true
}

// writeHexEscape appends a \xHH escape for a single byte.
func writeHexEscape(b *strings.Builder, c byte) {
	b.WriteString(`\x`)
	b.WriteByte(hexDigits[c>>4])
	b.WriteByte(hexDigits[c&0x0f])
}

// writeUnicodeEscape appends a \uHHHH escape for a rune in the Basic
// Multilingual Plane. The \xHH form writeHexEscape emits cannot represent a
// rune above U+00FF, so the line/paragraph separators the block sanitizer
// escapes need this wider form.
func writeUnicodeEscape(b *strings.Builder, r rune) {
	b.WriteString(`\u`)
	for shift := 12; shift >= 0; shift -= 4 {
		b.WriteByte(hexDigits[(r>>uint(shift))&0x0f])
	}
}
