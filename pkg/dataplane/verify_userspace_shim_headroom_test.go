package dataplane

import (
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
// blind spot it exists to close.
func TestBuildRecipeHandlesShimverifyExitCodes(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("build-userspace-xdp.sh"))
	if err != nil {
		t.Fatalf("read build-userspace-xdp.sh: %v", err)
	}
	recipe := string(data)
	for _, want := range []string{"0) ;;", "99)", "3)", "4)", "5)"} {
		if !strings.Contains(recipe, want) {
			t.Errorf("build-userspace-xdp.sh has no %q arm for the shimverify exit code", want)
		}
	}
	if !strings.Contains(recipe, "XPF_SHIM_ALLOW_LOW_HEADROOM") {
		t.Error("build-userspace-xdp.sh never mentions XPF_SHIM_ALLOW_LOW_HEADROOM")
	}
	// sudo scrubs the environment: the override must be threaded across
	// the sudo hop explicitly or it silently does nothing.
	if !strings.Contains(recipe, `sudo -n env "XPF_SHIM_ALLOW_LOW_HEADROOM=`) {
		t.Error("XPF_SHIM_ALLOW_LOW_HEADROOM is not passed through sudo — the documented override would be a no-op")
	}
}

// #4555: an unmeasurable stats line must reach the refusal path, not the
// pass path. This pins the decision the gate makes on that input; the
// end-to-end exit code is exercised by the shimverify binary itself.
func TestUnmeasuredStatsAreNotTreatedAsAcceptableHeadroom(t *testing.T) {
	unmeasured := parseShimVerifierStats("no stats line here\n")
	if unmeasured.Measured() {
		t.Fatal("Measured() = true for a log with no stats line")
	}
	// The dangerous shape is code that compares HeadroomPct() against the
	// floor without checking Measured() first: 0 < 3.0 would look like
	// "below the floor" (safe by luck), but any future floor of 0 would
	// make it read as "fine". Callers MUST branch on Measured().
	if unmeasured.HeadroomPct() != 0 {
		t.Errorf("HeadroomPct() = %v for unmeasured stats, want 0", unmeasured.HeadroomPct())
	}
}

// #4555: the shim's Fragment arm advances by size_of::<FragHdr>() while
// userspace-dp advances a literal 8. The Rust parity guard models that
// struct's layout; this pins the compile-time assertion that backs it, so
// the invariant cannot be deleted from the shim without a test noticing.
func TestShimCarriesFragHdrSizeAssertion(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "userspace-xdp", "src", "lib.rs"))
	if err != nil {
		t.Fatalf("read userspace-xdp/src/lib.rs: %v", err)
	}
	src := string(data)
	if !strings.Contains(src, "mem::size_of::<FragHdr>() == 8") {
		t.Error("the shim no longer asserts size_of::<FragHdr>() == 8 at compile time; " +
			"a field added to FragHdr would make it advance 9 bytes past a Fragment header " +
			"where userspace-dp advances 8, corrupting every fragmented-chain L4 offset (#4555)")
	}
}
