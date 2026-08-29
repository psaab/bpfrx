package config

import (
	"strings"
	"testing"
)

// plaintext_advisory_ifid_implication_7090_test.go — #7090.
//
// warnSecureTunnelPlaintextUnadjudicatedAST used to filter its population
// twice: once on `XFRMIfNameAndID(bindIface)` returning a non-zero if_id, and
// again on `IsSecureTunnelIfName(base)`. The second filter could not fire for
// any input, because the first ALREADY implies it — XFRMIfNameAndID returns a
// non-zero id only after secureTunnelIndex succeeds on the base name, and
// IsSecureTunnelIfName IS secureTunnelIndex on that same base, both splitting
// on the first '.'.
//
// Deleting a branch is only safe while that implication holds, so this binds
// the implication rather than the deleted line. If XFRMIfNameAndID ever gains a
// path to a non-zero id for a name IsSecureTunnelIfName rejects, the advisory's
// population silently widens — and this reds instead.

// TestNonZeroIfIDImpliesSecureTunnelName_7090 sweeps the name space for the
// combination the deleted branch existed to catch.
//
// The table is generated rather than listed because the question is about a
// SPACE, not about the handful of names anyone thinks to write down: a
// hand-picked table proves the branch is dead for those rows and says nothing
// about the rest. The generators deliberately include names that are rejected
// for different REASONS — bad prefix, out-of-range index, negative, non-numeric,
// empty, multi-dot — since a violation would come from exactly such an edge.
func TestNonZeroIfIDImpliesSecureTunnelName_7090(t *testing.T) {
	prefixes := []string{"st", "ST", "s", "st-", "st+", "xt", "", "st0", "stx", "et", "gr"}
	indices := []string{"", "0", "1", "5", "9", "10", "255", "65535", "65536", "99999",
		"-1", "+5", "0x1", "00", "007", "abc", " 1"}
	units := []string{"", ".", ".0", ".1", ".255", ".65535", ".65536", ".abc", ".-1",
		"..", ".0.1", ".+1"}

	var checked, nonZero int
	for _, p := range prefixes {
		for _, idx := range indices {
			for _, u := range units {
				name := p + idx + u
				_, ifID := XFRMIfNameAndID(name)
				checked++
				if ifID == 0 {
					continue
				}
				nonZero++
				base := name
				if i := strings.IndexByte(base, '.'); i >= 0 {
					base = base[:i]
				}
				if !IsSecureTunnelIfName(base) {
					t.Fatalf("XFRMIfNameAndID(%q) returned if_id %d while "+
						"IsSecureTunnelIfName(%q) is false.\n"+
						"The #7090 deletion removed a second filter on exactly this "+
						"combination, on the grounds that it cannot occur. It just did, so "+
						"the advisory now warns about a binding the device derivation would "+
						"not build — restore the predicate check, or narrow XFRMIfNameAndID",
						name, ifID, base)
				}
			}
		}
	}

	// Non-vacuity: a sweep in which NOTHING produced a non-zero id would satisfy
	// the implication for free, and would keep doing so if XFRMIfNameAndID were
	// broken to return 0 always.
	if nonZero == 0 {
		t.Fatalf("swept %d names and none produced a non-zero if_id, so the implication "+
			"above held vacuously and this test proves nothing", checked)
	}
	t.Logf("swept %d names, %d with a non-zero if_id", checked, nonZero)
}

// TestAdvisoryPopulationIsTheIfIDPopulation_7090 pins the surviving filter, so
// the deletion cannot be "simplified" further by removing the if_id check too.
//
// `st0.65535` is the case that matters: IsSecureTunnelIfName accepts the base,
// but XFRMIfNameAndID builds no device (the unit is out of range), and
// pkg/routing/xfrm.go skips exactly those. An advisory that warned here would
// describe a plaintext path that does not exist — and it is the row that
// distinguishes the two filters, which is why the deleted one looked plausible.
func TestAdvisoryPopulationIsTheIfIDPopulation_7090(t *testing.T) {
	for _, tc := range []struct {
		name       string
		wantDevice bool
	}{
		{"st0.0", true},
		{"st5.1", true},
		{"st0.65535", false},
		{"st0.abc", false},
		{"st65536.0", false},
		{"ge-0/0/0.0", false},
	} {
		_, ifID := XFRMIfNameAndID(tc.name)
		if got := ifID != 0; got != tc.wantDevice {
			t.Errorf("XFRMIfNameAndID(%q): builds-a-device = %v, want %v — the advisory's "+
				"population is exactly this set, so a change here changes which configs "+
				"are warned about (#7090)", tc.name, got, tc.wantDevice)
		}
		if tc.name == "st0.65535" && !IsSecureTunnelIfName("st0") {
			t.Error("precondition: IsSecureTunnelIfName must ACCEPT st0 here, or this row " +
				"no longer distinguishes the two filters")
		}
	}
}
