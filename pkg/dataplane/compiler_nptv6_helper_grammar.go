package dataplane

import (
	"net/netip"
	"strconv"
	"strings"
)

// This file mirrors the NPTv6 prefix grammar of the Rust helper's
// `parse_prefix` (userspace-dp/src/nptv6.rs) so `compileNPTv6` can answer ONE
// question before it turns a per-rule prefix fault into a hard error:
//
//	will the helper INSTALL this rule as written?
//
// That question is the correct discriminator, and it took a regression to
// learn why (#7077, #6894 r10). The obvious alternative -- "hard-error only on
// the strict commit path, warn-and-skip on the lenient tolerant-load /
// peer-sync path" -- CANNOT be implemented here and would not be right if it
// could:
//
//   - `pkg/dataplane` has no strict/lenient signal at all. `CompileConfig`
//     receives a `*config.Config` with no provenance; the distinction lives
//     entirely in `pkg/config`'s `compileOpts.lenientNPTv6`.
//   - More importantly it is not a DISCRIMINATOR, because it does not vary.
//     `validateNPTv6Strict` hard-rejects EVERY malformed NPTv6 prefix class at
//     strict commit -- unparseable, host-bits-set, mismatched lengths, an
//     unsupported length -- so a malformed rule can only ever reach this
//     compiler from the lenient path. Measured at this head: strict REJECTs all
//     five classes and lenient RETAINS all five with the #1960 warning.
//     "Warn-and-skip when lenient" therefore means "warn-and-skip always",
//     which is a full revert of the #4960 NPTv6 fix and re-opens the
//     half-applied shape it closed.
//
// What actually varies across those classes is whether the HELPER accepts the
// string, and that is what decides the right disposition:
//
//   - Helper REJECTS it (`"not-a-prefix"`, host bits set, mismatched lengths,
//     a /56, an IPv4 CIDR): today's apply ALREADY fails, at
//     `publishSnapshotFailClosedLocked`, AFTER `compileZones` created VLANs and
//     reconciled addresses. Hard-erroring here moves an already-certain failure
//     ahead of the mutation point. This is the #4960 fix and it stays.
//   - Helper ACCEPTS it (`"fd00:9::/+48"` -- Rust's `u8::from_str` takes a
//     leading `+`, Go's `net.ParseCIDR` mask parser does not): today's apply
//     SUCCEEDS and the helper installs the translation. Hard-erroring here
//     fails an apply that works, on the tolerant-load / HA-peer-sync path #1960
//     exists to keep booting. That is a no-brick violation, so this class keeps
//     the pre-#4960 warn-and-skip disposition.
//
// Skipping costs nothing observable: `compileNPTv6` writes to the retired eBPF
// map surface, while `buildNptv6Snapshots` (pkg/dataplane/userspace) copies
// `rule.Match` / `rule.Then` out of the config INDEPENDENTLY. A rule this
// compiler skips still reaches the helper and is still installed.
//
// This is deliberately a PROPERTY and not a patch keyed to `+`: any future
// grammar divergence in either direction is classified correctly by
// construction rather than by enumerating known-bad strings.
//
// DRIFT is the cost of a second copy of a Rust grammar, and it is bound rather
// than hoped for: `TestNPTv6HelperGrammarMatchesTheRustParser_7077` pins this
// mirror against a 40-string table whose expected column was produced by
// compiling `parse_prefix` VERBATIM with rustc. When the helper's grammar is
// tightened (that is the remaining half of #7077, and it is the plane that
// should own this), update the table and this mirror together -- the `+` arm is
// expected to disappear from both at once.

// nptv6HelperPrefixWords reports how many 16-bit words of prefix the Rust
// helper's `parse_prefix` would take from s, and whether it accepts s at all.
//
// Mirrors, statement for statement:
//
//	split on '/' -> exactly two fields
//	field[1] parsed as Rust `u8` (an optional leading sign, then ASCII digits)
//	length must be 48 (3 words) or 64 (4 words)
//	field[0] parsed as Rust `Ipv6Addr` (no zone, no bare IPv4)
//	every word beyond the prefix length must be zero (#4519 fail-closed)
//
// The sign handling is the one place the mirror is narrower than
// `u8::from_str`: this accepts a single leading '+' and rejects a leading '-',
// whereas Rust accepts "-0". The COMPOSED answers are identical, because the
// only negative value `u8::from_str` admits is 0 and 0 is not 48 or 64 -- both
// sides return false. `"2001:db8::/-0"` and `"2001:db8::/-48"` are in the
// parity table for exactly this reason.
func nptv6HelperPrefixWords(s string) (int, bool) {
	parts := strings.Split(s, "/")
	if len(parts) != 2 {
		return 0, false
	}

	maskTok := parts[1]
	maskTok = strings.TrimPrefix(maskTok, "+")
	// TrimPrefix removes at most one, but a second '+' must still be refused:
	// Rust's `u8::from_str` accepts ONE sign, so "++48" is an error there.
	if maskTok == "" || !isASCIIDigits(maskTok) {
		return 0, false
	}
	// bitSize 8 makes the overflow boundary exactly Rust's u8: "256" and "999"
	// are errors on both sides. Base 10 (not 0) refuses "_" separators and
	// "0x30", matching Rust.
	bits, err := strconv.ParseUint(maskTok, 10, 8)
	if err != nil {
		return 0, false
	}
	var words int
	switch bits {
	case 48:
		words = 3
	case 64:
		words = 4
	default:
		return 0, false
	}

	addr, err := netip.ParseAddr(parts[0])
	if err != nil {
		return 0, false
	}
	// `Ipv6Addr::from_str` takes neither a zone nor a bare IPv4 literal.
	// netip accepts both, so both are refused explicitly. A v4-mapped literal
	// (`::ffff:1.2.3.4`) IS an Ipv6Addr on both sides and is left to the
	// host-bits check below, which is what actually rejects it at /48 and /64.
	if addr.Zone() != "" || !addr.Is6() {
		return 0, false
	}
	// #4519: the helper fails CLOSED on host bits rather than masking, so a
	// prefix that is not its own network address is refused.
	if netip.PrefixFrom(addr, int(bits)).Masked().Addr() != addr {
		return 0, false
	}
	return words, true
}

// isASCIIDigits reports whether s is one or more ASCII digits and nothing
// else. Written out rather than delegating, because strconv accepts forms Rust
// does not (a sign via ParseInt) and unicode.IsDigit accepts forms Rust does
// not (non-ASCII decimal digits such as "๔๘"); both are in the parity
// table.
func isASCIIDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// nptv6HelperWouldInstall reports whether `Nptv6State::try_from_snapshots`
// would accept the rule carrying these two prefixes -- i.e. whether the apply
// SUCCEEDS today with the rule installed.
//
// It replicates the helper's per-rule gates: both prefixes parse, and their
// lengths agree (`iwords != ewords` is a distinct rejection over there, after
// both parse individually).
//
// It deliberately does NOT replicate the helper's CROSS-rule overlap rejection
// (#2241, zone-partitioned per #5176). That is a property of the whole rule
// set, not of one rule, and replicating it coarsely would reject configs the
// helper accepts. It is tracked as the named residual in #7078; its only effect
// here is that this function can return true for a rule the helper later
// refuses for an unrelated reason -- which is the SAFE direction, because it
// keeps the pre-#4960 warn-and-skip rather than inventing a new hard error.
func nptv6HelperWouldInstall(match, then string) bool {
	extWords, extOK := nptv6HelperPrefixWords(match)
	if !extOK {
		return false
	}
	intWords, intOK := nptv6HelperPrefixWords(then)
	if !intOK {
		return false
	}
	return extWords == intWords
}
