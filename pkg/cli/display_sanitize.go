package cli

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

const displayHexDigits = "0123456789abcdef"

// sanitizeForDisplay renders a device-originated string safe to print to an
// operator's terminal. Several fields shown by the CLI are attacker-controlled:
// a DHCP lease hostname (DHCP option 12) and the client hardware address are
// supplied by a device on a served segment and stored opaque by Kea, and the
// DHCP dynamic-DNS forward record name is built from that same client hostname.
// Printed verbatim, such a value can carry terminal escape sequences — an OSC 52
// clipboard write, an OSC 8 hyperlink, or CSI cursor/erase controls — that the
// operator's terminal would ACT on when the table is displayed. That yields
// clipboard hijack and output spoofing: a forged "commit complete" line, or a
// rogue lease row erased from view. Sanitizing at the display boundary closes
// this without touching the stored lease data or the gRPC/JSON structs (machine
// consumers keep the raw value; only the terminal renderer is guarded).
//
// Every C0 control byte (0x00-0x1F), DEL (0x7F), C1 control byte (0x80-0x9F),
// and invalid UTF-8 byte is replaced with a visible backslash-hex escape (e.g.
// an ESC becomes the four printable characters \x1b) so the operator sees
// exactly what the device sent instead of the terminal interpreting it. Every
// printable rune — including legitimate multibyte UTF-8, so an international
// hostname is not corrupted — passes through unchanged.
func sanitizeForDisplay(s string) string {
	// Fast path: the overwhelming majority of names are already clean, so
	// return the input without allocating a builder.
	if displaySafe(s) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 8)
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			// Invalid UTF-8 byte — escape the raw byte value so a crafted
			// non-UTF-8 sequence cannot smuggle bytes past the rune checks.
			writeDisplayHexEscape(&b, s[i])
			i++
			continue
		}
		if unicode.IsControl(r) {
			// Control runes (Unicode category Cc) are all <= U+009F, so a
			// single \xHH byte escape represents each one exactly.
			writeDisplayHexEscape(&b, byte(r))
			i += size
			continue
		}
		b.WriteRune(r)
		i += size
	}
	return b.String()
}

// displaySafe reports whether s can be printed to a terminal verbatim: it holds
// no control rune and no invalid UTF-8 byte, so sanitizeForDisplay would return
// it unchanged. Splitting this out keeps the common (clean) path allocation-free.
func displaySafe(s string) bool {
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

// writeDisplayHexEscape appends a \xHH escape for a single byte.
func writeDisplayHexEscape(b *strings.Builder, c byte) {
	b.WriteString(`\x`)
	b.WriteByte(displayHexDigits[c>>4])
	b.WriteByte(displayHexDigits[c&0x0f])
}
