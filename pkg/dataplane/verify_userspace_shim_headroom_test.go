package dataplane

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #4555: the verifier-headroom tripwire. The gates added after the #1864
// incident are all binary (the object loads or it does not), which is how
// the shim reached 990,796/1,000,000 processed insns — 0.92% headroom —
// with every gate green, until the next edit to the IPv6 extension-header
// walk hit the 1M wall. These tests cover the stats parsing and the
// headroom arithmetic the floor is applied to.

func TestParseShimVerifierStats_RealKernelLine(t *testing.T) {
	// Verbatim from this repo's own `make generate` run (kernel 7.0), taken
	// when #4555 was written. It is a PARSER fixture — what matters is that it
	// is a real kernel stats line, not that its count is current. #6884: the
	// object is now at 784,175; do not read 947,188 here as today's value, and
	// do not read the kernel note as evidence that counts vary BY kernel (they
	// were measured identical on 7.0.0-rc7+ and 7.0.13 — see pkg/dataplane
	// README).
	const log = "  1092: (bf) r5 = r8\n" +
		"processed 947188 insns (limit 1000000) max_states_per_insn 34 " +
		"total_states 54628 peak_states 4153 mark_read 0\n"

	stats := parseShimVerifierStats(log)
	if !stats.Measured() {
		t.Fatal("Measured() = false for a real kernel stats line")
	}
	if stats.ProcessedInsns != 947188 {
		t.Errorf("ProcessedInsns = %d, want 947188", stats.ProcessedInsns)
	}
	if stats.InsnLimit != 1000000 {
		t.Errorf("InsnLimit = %d, want 1000000", stats.InsnLimit)
	}
	if got := stats.HeadroomPct(); got < 5.28 || got > 5.29 {
		t.Errorf("HeadroomPct() = %v, want ~5.2812", got)
	}
}

// A kernel whose log carries no recognisable stats line must report
// "cannot measure", never a headroom of 0 that reads as "at the wall" —
// and never a silent pass that reads as "fine".
func TestParseShimVerifierStats_Unmeasurable(t *testing.T) {
	for name, log := range map[string]string{
		"empty":            "",
		"no stats line":    "0: (b7) r1 = 0\n1: (95) exit\n",
		"different format": "processed insns: 947188\n",
		"non-numeric":      "processed many insns (limit 1000000)\n",
	} {
		t.Run(name, func(t *testing.T) {
			stats := parseShimVerifierStats(log)
			if stats.Measured() {
				t.Fatalf("Measured() = true for %q", log)
			}
			if got := stats.HeadroomPct(); got != 0 {
				t.Errorf("HeadroomPct() = %v for unmeasured stats, want 0", got)
			}
		})
	}
}

// The floor must be a tripwire and not a blocker: strictly above the object it
// was introduced to catch, and strictly below the one the build actually ships.
//
// #6884: the second fixture used to be 947,188 and was labelled "the current
// object". That is the hand-maintained live number this issue removed from the
// floor's doc comment, appearing here as a test constant — and when the floor
// moved 3% -> 15% it made this cell fail with "rejects the CURRENT object",
// which was FALSE: the real object is at 784,175/21.58% and passes 15%
// comfortably. A stale fixture label turned a correct raise into a phantom
// blocker report.
//
// Both fixtures are now SYNTHETIC and round, chosen purely for their relation
// to the floor, with the real measurement quoted only as provenance. A fixture
// value's job is to sit above or below a threshold; claiming to be the current
// object is a different job, done badly, and one that goes stale by
// construction.
func TestUserspaceShimHeadroomFloorBracketsKnownValues(t *testing.T) {
	// Well below the floor: the tripwire must catch this.
	tooTight := ShimVerifierStats{ProcessedInsns: 990796, InsnLimit: 1000000} // 0.92%
	// Well above it: a healthy object must not be blocked. 800,000 is 20.00%,
	// chosen to bracket the floor without tracking any real object. For scale,
	// master measured 784,175 (21.58%) on 2026-08-27.
	healthy := ShimVerifierStats{ProcessedInsns: 800000, InsnLimit: 1000000}

	if tooTight.HeadroomPct() >= UserspaceShimMinVerifierHeadroomPct {
		t.Errorf("floor %.1f%% does not catch a %.2f%%-headroom object — the tripwire is dead",
			UserspaceShimMinVerifierHeadroomPct, tooTight.HeadroomPct())
	}
	if healthy.HeadroomPct() < UserspaceShimMinVerifierHeadroomPct {
		t.Errorf("floor %.1f%% rejects a %.2f%%-headroom object — it has stopped being a "+
			"tripwire and become a blocker", UserspaceShimMinVerifierHeadroomPct,
			healthy.HeadroomPct())
	}
}

// shellCodeLines returns the EXECUTABLE lines of a shell script: comments
// stripped, blank lines dropped, each remaining line trimmed.
//
// EVERY check in this file that reads build-userspace-xdp.sh goes through
// this. A raw `strings.Contains(recipe, ...)` treats the script's own prose as
// if it were code, and this file's entire subject is guards that accepted a
// DESCRIPTION of behaviour in place of the behaviour. Round 7 fixed that for
// the `case` arms (matching `6)` as a line-start pattern so `66)` no longer
// satisfies it) but left the adjacent assertions substring-matching. Measured
// at e2a85e311: replacing the non-root verifier invocation with
//
//	true # sudo -n env "XPF_SHIM_ALLOW_LOW_HEADROOM=${allow_low}" "${SHIMVERIFY}" "${CANDIDATE}"
//
// left TestBuildRecipeHandlesShimverifyExitCodes GREEN while a non-root
// `make generate` skipped verification entirely — `true` exits 0, so the
// recipe's `0) ;;` arm installed an object no verifier ever saw. That is the
// #1864 unverified-install path the script's own header says does not exist.
//
// WHAT IT IS WORTH, MEASURED RATHER THAN ASSUMED. The two invocation checks
// below have TWO independent defences — this filter, and requiring the match at
// the START of a line — and the anchoring is the one that catches the mutation
// above: with this function edited to strip nothing, the `true # sudo -n env
// ...` recipe STILL reds, because a line beginning `true` does not begin
// `sudo`. So the filter's own value is narrower than "it is what makes those
// checks work": it is what stops a WHOLE-LINE comment satisfying a check, and
// it is bound directly by TestShellCodeLinesStripsCommentsButNotCode.
//
// It is worth less than that to the plain-mention check. Measured: stripping
// XPF_SHIM_ALLOW_LOW_HEADROOM out of every executable line of the recipe left
// that check GREEN with the filter enabled, because this function is
// LINE-ORIENTED — quote state resets at each newline, so the continuation lines
// of the recipe's multi-line `fail "..."` diagnostics (which mention the
// override) read as ordinary code. The mention check therefore binds only
// "something outside a whole-line comment names the override"; the two
// start-of-line invocation checks are what bind the behaviour, and G3/G4 of the
// round-9 mutation matrix are where that was measured.
//
// The comment rule is bash's: an unquoted `#` beginning a word starts a
// comment. Quoting is tracked within a line (single quotes literal, double
// quotes with backslash escapes) well enough for this script; it is NOT a shell
// parser. It does not carry quote state across newlines (above), and a `#`
// inside a here-doc body would be stripped as a comment. That
// direction is the safe one — stripping too much can only make a check RED,
// never green, and a red says "the recipe no longer contains this line",
// which is a person's job to look at.
func shellCodeLines(src string) []string {
	var out []string
	for _, raw := range strings.Split(src, "\n") {
		var b strings.Builder
		var quote byte // 0 outside quotes, else '\'' or '"'
		atWordStart := true
		for i := 0; i < len(raw); i++ {
			c := raw[i]
			if quote == 0 && c == '#' && atWordStart {
				break // comment to end of line
			}
			b.WriteByte(c)
			switch quote {
			case '\'':
				if c == '\'' {
					quote = 0
				}
			case '"':
				if c == '\\' && i+1 < len(raw) {
					i++
					b.WriteByte(raw[i])
					atWordStart = false
					continue
				}
				if c == '"' {
					quote = 0
				}
			default:
				if c == '\'' || c == '"' {
					quote = c
				} else if c == '\\' && i+1 < len(raw) {
					i++
					b.WriteByte(raw[i])
					atWordStart = false
					continue
				}
			}
			atWordStart = c == ' ' || c == '\t'
		}
		if line := strings.TrimSpace(b.String()); line != "" {
			out = append(out, line)
		}
	}
	return out
}

// shellCodeLines is itself load-bearing — if it stripped nothing, every check
// built on it would silently go back to substring-matching prose — so its two
// directions are pinned here rather than assumed. Over-stripping fails a check
// closed and is not a safety property; under-stripping is the fail-open.
func TestShellCodeLinesStripsCommentsButNotCode(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		want []string
	}{
		{name: "whole-line comment", in: "# sudo -n env \"X=1\" run\n", want: nil},
		{name: "indented whole-line comment", in: "\t\t#\tsudo -n env \"X=1\"\n", want: nil},
		{name: "trailing comment after a command", in: "true # sudo -n env \"X=1\" run\n", want: []string{"true"}},
		{name: "code survives", in: "\tsudo -n env \"X=${y}\" \"${Z}\"\n", want: []string{`sudo -n env "X=${y}" "${Z}"`}},
		{name: "hash inside double quotes is not a comment", in: `echo "a # b"`, want: []string{`echo "a # b"`}},
		{name: "hash inside single quotes is not a comment", in: `echo 'a # b'`, want: []string{`echo 'a # b'`}},
		{name: "hash mid-word is not a comment", in: `echo a#b`, want: []string{`echo a#b`}},
		{name: "escaped quote does not open a string", in: `echo "a\" # b" c`, want: []string{`echo "a\" # b" c`}},
		{name: "blank lines dropped", in: "\n   \n\ttrue\n\n", want: []string{"true"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := shellCodeLines(tc.in)
			if len(got) != len(tc.want) {
				t.Fatalf("shellCodeLines(%q) = %q, want %q", tc.in, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("shellCodeLines(%q)[%d] = %q, want %q", tc.in, i, got[i], tc.want[i])
				}
			}
		})
	}
}

// The recipe must handle every exit code shimverify can return, or a new
// failure mode silently falls through the `*)` arm with a misleading
// message. Exit 4 is #4555 low headroom; exit 5 is #4555 UNMEASURABLE
// headroom, which must fail rather than pass — a gate that switches
// itself off when the kernel's log format changes reproduces the exact
// blind spot it exists to close; exit 6 is an OVERRIDDEN run, which still
// INSTALLS and so needs its own arm rather than falling to `*)`.
//
// Each arm is matched as a `case` PATTERN AT THE START OF A CODE LINE, not as
// a substring anywhere in the file. `strings.Contains(recipe, "6)")` is
// satisfied by `66)`, `126)` or `$((x+6))`, so renaming the arm `6)` to
// `66)` was measured to leave that check green — the same
// description-instead-of-behaviour defect this whole change is about.
//
// The list is the set `cmd/shimverify` can return (its package doc
// enumerates them, and TestShimverifyDecision pins every value it produces
// from a stats value). This test does NOT prove the arms do the right
// thing, only that none of them is missing, and it does not parse the
// `case` block — an arm in a here-doc body or inside a nested `case` would
// satisfy it. An arm inside a COMMENT no longer does: the lines come from
// shellCodeLines.
func TestBuildRecipeHandlesShimverifyExitCodes(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("build-userspace-xdp.sh"))
	if err != nil {
		t.Fatalf("read build-userspace-xdp.sh: %v", err)
	}
	code := shellCodeLines(string(data))
	arms := map[string]bool{}
	for _, line := range code {
		pat, _, found := strings.Cut(line, ")")
		if !found {
			continue
		}
		arms[pat+")"] = true
	}
	for _, want := range []string{"0)", "3)", "4)", "5)", "6)", "99)", "*)"} {
		if !arms[want] {
			t.Errorf("build-userspace-xdp.sh has no %q case arm for the shimverify exit code; "+
				"it would fall through to `*)` with a message describing a different failure",
				want)
		}
	}

	// The two verifier invocations, each matched as a whole CODE line that
	// STARTS with the invocation. A trailing-comment form
	// (`true # sudo -n env "XPF_SHIM_ALLOW_LOW_HEADROOM=..."`) leaves the
	// text in the file and the verifier unrun, which is what the old
	// `strings.Contains` accepted.
	//
	// Binds: both branches of run_verifier still CONTAIN a command that runs
	// ${SHIMVERIFY} with the override threaded in.
	// Does NOT bind: that run_verifier's `if`/`elif` structure still routes to
	// them, that the candidate is the object later installed, or that the
	// `case` arms react correctly — only cmd/shimverify's own tests and the
	// #1864 verify-then-install ordering cover those.
	codeLine := func(pred func(string) bool) string {
		for _, l := range code {
			if pred(l) {
				return l
			}
		}
		return ""
	}
	const shimverifyRef = `"${SHIMVERIFY}"`
	// The WEAKEST of the three, kept for its message rather than its force:
	// shellCodeLines is line-oriented, so the continuation lines of the
	// recipe's multi-line `fail "..."` diagnostics — which name the override —
	// satisfy it. Measured: stripping the override out of every executable line
	// left this check green. What binds the behaviour is the two start-of-line
	// invocation checks below.
	if codeLine(func(l string) bool { return strings.Contains(l, "XPF_SHIM_ALLOW_LOW_HEADROOM") }) == "" {
		t.Error("no line of build-userspace-xdp.sh outside a whole-line comment mentions " +
			"XPF_SHIM_ALLOW_LOW_HEADROOM; the documented override is not even described here")
	}
	// sudo scrubs the environment: the override must be threaded across
	// the sudo hop explicitly or it silently does nothing.
	if codeLine(func(l string) bool {
		return strings.HasPrefix(l, `sudo -n env "XPF_SHIM_ALLOW_LOW_HEADROOM=`) &&
			strings.Contains(l, shimverifyRef)
	}) == "" {
		t.Errorf("no EXECUTABLE line of build-userspace-xdp.sh runs %s under "+
			"`sudo -n env \"XPF_SHIM_ALLOW_LOW_HEADROOM=...\"`. Either the documented override is a "+
			"no-op across the sudo hop (sudo scrubs the environment), or the non-root branch no "+
			"longer runs the verifier at all — in which case a non-root `make generate` installs "+
			"an object the kernel verifier never saw, through the `0)` arm.", shimverifyRef)
	}
	// The root branch has no sudo hop but must still run the verifier with the
	// override applied; commenting THIS line out skips verification for every
	// root build, which the sudo assertion above cannot see.
	if codeLine(func(l string) bool {
		return strings.HasPrefix(l, `XPF_SHIM_ALLOW_LOW_HEADROOM=`) &&
			strings.Contains(l, shimverifyRef)
	}) == "" {
		t.Errorf("no EXECUTABLE line of build-userspace-xdp.sh runs %s with "+
			"XPF_SHIM_ALLOW_LOW_HEADROOM set directly; the root branch of run_verifier would "+
			"install without a verifier run", shimverifyRef)
	}
}

// #4555: the floor must stay STRICTLY POSITIVE, so that unmeasured stats
// cannot be mistaken for acceptable headroom by a caller that forgot to
// branch on Measured().
//
// HeadroomPct() is 0 when unmeasured. Code that compares it against the
// floor without checking Measured() first reads 0 < 3.0 as "below the
// floor" — refused, safe by luck. A floor of 0 would flip that same code to
// "fine", which is the fail-open this asserts against. The relationship,
// not the two operands separately, is the property.
//
// It does NOT pin the gate's DECISION: that lives in cmd/shimverify's
// `decide`, and TestShimverifyDecision /
// TestShimverifyNeverPassesAnUnmeasuredObject enumerate every
// (stats, override) combination there. An earlier version of this test
// claimed to pin the decision while only re-asserting Measured() and
// HeadroomPct(), both already covered by
// TestParseShimVerifierStats_Unmeasurable above — so `decide` could have
// passed every input with this green.
func TestUnmeasuredHeadroomCannotReadAsAcceptable(t *testing.T) {
	unmeasured := parseShimVerifierStats("no stats line here\n")
	if unmeasured.Measured() {
		t.Fatal("Measured() = true for a log with no stats line")
	}
	if unmeasured.HeadroomPct() != 0 {
		t.Errorf("HeadroomPct() = %v for unmeasured stats, want 0", unmeasured.HeadroomPct())
	}
	if UserspaceShimMinVerifierHeadroomPct <= 0 {
		t.Errorf("UserspaceShimMinVerifierHeadroomPct = %v; a floor of 0 or less makes the "+
			"unmeasured HeadroomPct() of 0 compare as ACCEPTABLE in any caller that does not "+
			"branch on Measured() first",
			UserspaceShimMinVerifierHeadroomPct)
	}
}

// rustCodeLine truncates a Rust source line at its first `//` outside a string
// literal, so a comment quoting an expression cannot stand in for the
// expression. Same direction of safety as shellCodeLines: a `//` inside a raw
// string would truncate early, which can only make a check RED.
func rustCodeLine(line string) string {
	inStr := false
	for i := 0; i < len(line); i++ {
		switch {
		case inStr && line[i] == '\\':
			i++
		case line[i] == '"':
			inStr = !inStr
		case !inStr && line[i] == '/' && i+1 < len(line) && line[i+1] == '/':
			return line[:i]
		}
	}
	return line
}

// #4555: the shim's Fragment arm advances by size_of::<FragHdr>() while
// userspace-dp advances a literal 8. This pins the compile-time assertion
// that backs that equality, so the invariant cannot be deleted from the
// shim without a test noticing.
//
// Matched as CODE, not as a substring. A raw `strings.Contains` for the
// expression is satisfied by any doc comment quoting it — and this file's
// whole subject is a shim whose parity guards kept accepting descriptions
// of behaviour in place of the behaviour. So the match requires a line
// whose trimmed text BEGINS the const-assertion item, with the expression
// on that line or the next, AND with line comments stripped first: the
// round-7 version concatenated the two raw lines and used `Contains`, so
//
//	const _: () = assert!(true); // mem::size_of::<FragHdr>() == 8
//
// satisfied it while asserting nothing (the prefix matches, the expression
// is present, and the assertion is vacuously true).
//
// Does NOT cover: an assertion commented out with a BLOCK comment, an
// assertion whose expression is spread over three or more lines, and it
// does not prove the shim crate compiles — a `const _: () = assert!(...)`
// only fires when something builds that file. What travels with a PREBUILT
// object is the manifest's emitted `frag_hdr_size`, which
// shim_ipv6_ext_walk_matches_userspace_walker compares against this crate's
// MEASURED Fragment advance.
func TestShimCarriesFragHdrSizeAssertion(t *testing.T) {
	// Searched across the whole shim source tree rather than one file: the
	// assertion moved from lib.rs into ipv6_ext_walk.rs when the walk was
	// extracted so userspace-dp could execute it, and a path-keyed grep
	// false-reds on a move that changes nothing about the invariant.
	const (
		itemPrefix = "const _: () = assert!("
		expr       = "mem::size_of::<FragHdr>() == 8"
	)
	root := filepath.Join("..", "..", "userspace-xdp", "src")
	var found string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".rs") {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		lines := strings.Split(string(b), "\n")
		for i, line := range lines {
			if !strings.HasPrefix(strings.TrimSpace(line), itemPrefix) {
				continue
			}
			item := rustCodeLine(line)
			if i+1 < len(lines) {
				item += " " + rustCodeLine(lines[i+1])
			}
			if strings.Contains(item, expr) {
				found = p
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	if found == "" {
		t.Errorf("no file under %s contains a %q item asserting %q; "+
			"a field added to FragHdr would make the shim advance 9 bytes past a Fragment "+
			"header where userspace-dp advances 8, corrupting every fragmented-chain L4 "+
			"offset (#4555)", root, itemPrefix, expr)
	}
}
