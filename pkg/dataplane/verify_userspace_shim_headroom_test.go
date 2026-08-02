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
	// Verbatim from this repo's own `make generate` run (kernel 7.0).
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

// The floor must sit strictly between the pre-#4555 headroom (0.92%) and
// the current one (5.28%), or it is either dead or an immediate blocker.
func TestUserspaceShimHeadroomFloorBracketsKnownValues(t *testing.T) {
	preFix := ShimVerifierStats{ProcessedInsns: 990796, InsnLimit: 1000000}
	current := ShimVerifierStats{ProcessedInsns: 947188, InsnLimit: 1000000}

	if preFix.HeadroomPct() >= UserspaceShimMinVerifierHeadroomPct {
		t.Errorf("floor %.1f%% does not catch the pre-#4555 object (%.2f%% headroom) — the tripwire is dead",
			UserspaceShimMinVerifierHeadroomPct, preFix.HeadroomPct())
	}
	if current.HeadroomPct() < UserspaceShimMinVerifierHeadroomPct {
		t.Errorf("floor %.1f%% rejects the CURRENT object (%.2f%% headroom) — `make generate` would be blocked",
			UserspaceShimMinVerifierHeadroomPct, current.HeadroomPct())
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
// Each arm is matched as a `case` PATTERN AT THE START OF A LINE, not as a
// substring anywhere in the file. `strings.Contains(recipe, "6)")` is
// satisfied by `66)`, `126)` or `$((x+6))`, so renaming the arm `6)` to
// `66)` was measured to leave that check green — the same
// description-instead-of-behaviour defect this whole change is about.
//
// The list is the set `cmd/shimverify` can return (its package doc
// enumerates them, and TestShimverifyDecision pins every value it produces
// from a stats value). This test does NOT prove the arms do the right
// thing, only that none of them is missing, and it does not parse the
// `case` block — an arm inside a comment or a nested `case` would satisfy
// it.
func TestBuildRecipeHandlesShimverifyExitCodes(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("build-userspace-xdp.sh"))
	if err != nil {
		t.Fatalf("read build-userspace-xdp.sh: %v", err)
	}
	arms := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
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
	recipe := string(data)
	if !strings.Contains(recipe, "XPF_SHIM_ALLOW_LOW_HEADROOM") {
		t.Error("build-userspace-xdp.sh never mentions XPF_SHIM_ALLOW_LOW_HEADROOM")
	}
	// sudo scrubs the environment: the override must be threaded across
	// the sudo hop explicitly or it silently does nothing.
	if !strings.Contains(recipe, `sudo -n env "XPF_SHIM_ALLOW_LOW_HEADROOM=`) {
		t.Error("XPF_SHIM_ALLOW_LOW_HEADROOM is not passed through sudo — the documented override would be a no-op")
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
// on that line or the next.
//
// Does NOT cover: an assertion commented out with a block comment, and it
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
			item := line
			if i+1 < len(lines) {
				item += " " + lines[i+1]
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
