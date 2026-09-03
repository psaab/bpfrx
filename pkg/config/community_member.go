package config

import (
	"fmt"
	"regexp"
	"strings"
)

// CommunityRegexChars are the characters whose presence in a community member
// forces pkg/frr to render the whole definition as an FRR `expanded`
// community-list rather than a `standard` one (#2643). This is the SSOT for
// that classification; pkg/frr's communityMemberIsRegex reads it so the render
// decision and the commit gate below cannot disagree about which members FRR
// will run through regcomp.
const CommunityRegexChars = `*.+?^$[]()|\{}`

// CommunityMemberIsRegex reports whether a member forces the expanded list
// kind. FRR does NOT allow one list name to be both standard and expanded, so
// the decision is per-DEFINITION: if any member is a regex, the ENTIRE
// definition renders as expanded and EVERY member is compiled as a POSIX ERE.
func CommunityMemberIsRegex(member string) bool {
	return strings.ContainsAny(member, CommunityRegexChars)
}

// ValidCommunityMember reports why a `policy-options community` member cannot
// be rendered into frr.conf, or nil when it can.
//
// xpf renders one `bgp community-list <kind> <name> permit <member>` line per
// member. Two values break that line rather than narrowing it:
//
//   - an EMPTY member renders the command with no argument, which FRR rejects
//     as incomplete;
//   - a member that forces the EXPANDED list kind but is not a valid POSIX
//     extended regular expression fails FRR's regcomp at config load.
//
// Either is a CMD_WARNING_CONFIG_FAILED, and a single such failure exits the
// whole vtysh add-batch non-zero — so it does not merely lose this one
// community-list, it fails the ENTIRE frr-reload and leaves every dynamic
// routing change stale. That is the reasoning #6686 recorded for as-path
// regexes; it applies here unchanged, and this is the sibling gate it never
// got (#8449).
//
// SCOPE, deliberately narrow. A member that renders and compiles today keeps
// committing: this gate rejects only what provably breaks the reload. It does
// NOT check that a standard-kind member is a well-formed community literal
// (`ASN:VALUE` or a well-known name). FRR would reject a bogus literal too,
// but enumerating the well-known names is a second, independent claim, and a
// gate that over-approximates would false-reject working configs — a worse
// failure than the one being fixed. That residual is tracked on #8449.
//
// The check is regexp.CompilePOSIX, Go's POSIX-ERE mode, the same dialect FRR
// compiles with REG_EXTENDED. Where the engines differ they differ in the SAFE
// direction: Go is stricter, so a pattern rejected here is at worst one glibc
// would have accepted with undefined semantics.
//
// Control characters are NOT re-checked here: the strict #1798 commit gate
// rejects them, and pkg/frr's sanitizeFRRValue is the render-side belt for the
// leniently-loaded case (#4097).
func ValidCommunityMember(member string) error {
	if strings.TrimSpace(member) == "" {
		return fmt.Errorf("empty community member")
	}
	if !CommunityMemberIsRegex(member) {
		return nil
	}
	if _, err := regexp.CompilePOSIX(member); err != nil {
		return fmt.Errorf("contains a regex metacharacter (%s) so it renders into an "+
			"FRR `expanded` community-list, but it is not a valid POSIX extended "+
			"regular expression: %w", CommunityRegexChars, err)
	}
	return nil
}
