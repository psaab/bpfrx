package config

import (
	"strings"
	"testing"
)

// #6640 — the host-inbound commit advisory reasoned over RAW stanzas while the
// dataplane enforces a RESOLVED effective view, so it warned that a service was
// DENIED on configurations where enforcement full-admits it.
//
// Runtime enforcement was correct throughout; this is the advisory path, so the
// defect is a trust/usability one rather than a security one. That does not make
// it cheap: a commit warning that cries wolf on a correct configuration teaches
// operators to scroll past it, and the real case — a genuinely unported service
// silently denied — goes past with it. The negative control at the bottom is the
// half that keeps this a FIX and not a blanket suppression.
//
// THE FOUR SHAPES the issue reproduced, all four false:
//
//   - physical `any-service` + unit `rpm`  (enforcement unions to a full admit)
//   - physical `rpm` + unit `any-service`  (same union, other order)
//   - a lifeline-only zone                 (nothing is denied on a lifeline)
//   - an `fxp0.0` interface override       (same, at the interface level)
//
// The first two exist because the advisory modelled NO physical->unit layer at
// all: `ResolveInterfaceHostInbound` merges a physical-level override into each
// of its units (#3720) before the zone/interface replacement (#6515) is applied,
// and the advisory was unioning the zone with each raw stanza instead. The last
// two exist because the lifeline exemption (#3277) was applied to the SCOPING
// advisory and never ported to the UNPORTED one.
//
// The fix is structural rather than another special case: the advisory now calls
// config.ResolveInterfaceHostInbound, the same function the enforcement builders
// in pkg/dataplane/userspace call. See
// pkg/dataplane/userspace/host_inbound_shared_view_6640_test.go — breaking that
// shared function must red an advisory test AND an enforcement test together.

// hostInboundDenialWarnings6640 returns the unported-service DENIAL advisories.
// The phrase is unique to that check, so this cannot pick up the full-admit
// breadth notice or the `all` scoping notice.
func hostInboundDenialWarnings6640(t *testing.T, lines []string) []string {
	t.Helper()
	cfg, err := CompileConfig(buildTree(t, lines))
	if err != nil {
		t.Fatalf("CompileConfig must ACCEPT these stanzas (all real Junos): %v", err)
	}
	var out []string
	for _, w := range ValidateConfig(cfg) {
		if strings.Contains(w, "accepted but NOT enforced") {
			out = append(out, w)
		}
	}
	return out
}

// hostInbound6640PhysicalUnit is the two-level fixture shared with the
// enforcement-side test. `phy` goes on the PHYSICAL interface ref and `unit` on
// the logical unit; both are interface-level statements, so #3720 unions them
// before #6515's zone replacement is considered.
func hostInbound6640PhysicalUnit(phy, unit string) []string {
	return []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
		"set security zones security-zone trust interfaces ge-0/0/0.0",
		"set security zones security-zone trust interfaces ge-0/0/0 host-inbound-traffic system-services " + phy,
		"set security zones security-zone trust interfaces ge-0/0/0.0 host-inbound-traffic system-services " + unit,
	}
}

// TestHostInboundAdvisoryDoesNotCryWolf_6640 is the four-shape table. Each row
// is a configuration on which the effective set FULL-ADMITS (or is not enforced
// at all), so the denial the advisory used to predict cannot happen.
func TestHostInboundAdvisoryDoesNotCryWolf_6640(t *testing.T) {
	cases := []struct {
		name  string
		why   string
		lines []string
	}{
		{
			name: "physical any-service beside a unit rpm",
			why: "the physical override is inherited by ge-0/0/0.0 and UNIONED with the " +
				"unit override (#3720), so the effective set carries any-service and " +
				"admits everything",
			lines: hostInbound6640PhysicalUnit("any-service", "rpm"),
		},
		{
			name: "physical rpm beside a unit any-service",
			why: "same union, other order — the advisory keyed on the PHYSICAL stanza and " +
				"never saw that the unit it governs resolves to a full admit",
			lines: hostInbound6640PhysicalUnit("rpm", "any-service"),
		},
		{
			name: "lifeline-only zone",
			why: "every interface in the zone is a management lifeline, whose host traffic " +
				"is served unconditionally (#3277) — the zone-level narrowing is not " +
				"enforced anywhere",
			lines: []string{
				"set interfaces fxp0 unit 0 family inet address 10.9.0.1/24",
				"set security zones security-zone mgmt interfaces fxp0.0",
				"set security zones security-zone mgmt host-inbound-traffic system-services rpm",
			},
		},
		{
			name: "fxp0.0 interface override",
			why:  "an override on a lifeline unit denies nothing, for the same reason",
			lines: []string{
				"set interfaces fxp0 unit 0 family inet address 10.9.0.1/24",
				"set security zones security-zone mgmt interfaces fxp0.0",
				"set security zones security-zone mgmt interfaces fxp0.0 host-inbound-traffic system-services rpm",
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if got := hostInboundDenialWarnings6640(t, tc.lines); len(got) != 0 {
				t.Errorf("FALSE denial advisory on a configuration where %s; got %d: %v",
					tc.why, len(got), got)
			}
		})
	}
}

// TestHostInboundAdvisoryStillWarnsWhenDenialIsREAL_6640 is the negative control,
// and it is the half that makes the change a fix rather than a suppression. Each
// row genuinely denies the unported service somewhere the dataplane enforces,
// so the advisory MUST still fire and MUST still name the service.
//
// The rows are chosen to be the minimal EDIT of the false rows above: drop the
// full-admit token, or move the stanza off the lifeline. If a row here stopped
// warning, the four rows above would be passing for the wrong reason.
func TestHostInboundAdvisoryStillWarnsWhenDenialIsREAL_6640(t *testing.T) {
	cases := []struct {
		name  string
		where string
		lines []string
	}{
		{
			name:  "unit rpm with no full-admit anywhere",
			where: `interface "ge-0/0/0.0"`,
			lines: []string{
				"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
				"set security zones security-zone trust interfaces ge-0/0/0.0",
				"set security zones security-zone trust interfaces ge-0/0/0.0 host-inbound-traffic system-services rpm",
			},
		},
		{
			name: "physical rpm inherited by a unit that does NOT full-admit",
			// The minimal edit of row 2 above: the unit's own token is `ping`, not
			// `any-service`, so the union is [rpm ping] and rpm really is denied.
			where: `interface "ge-0/0/0"`,
			lines: hostInbound6640PhysicalUnit("rpm", "ping"),
		},
		{
			name:  "zone-level rpm on an ENFORCING (non-lifeline) zone",
			where: `zone "trust" host-inbound-traffic`,
			lines: []string{
				"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
				"set security zones security-zone trust interfaces ge-0/0/0.0",
				"set security zones security-zone trust host-inbound-traffic system-services rpm",
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := hostInboundDenialWarnings6640(t, tc.lines)
			if len(got) != 1 {
				t.Fatalf("a REAL denial must still warn — the fix must not be a blanket "+
					"suppression; got %d advisories: %v", len(got), got)
			}
			if !strings.Contains(got[0], "rpm") {
				t.Errorf("advisory must name the denied service, got: %q", got[0])
			}
			if !strings.Contains(got[0], tc.where) {
				t.Errorf("advisory must name %s, got: %q", tc.where, got[0])
			}
		})
	}
}

// TestHostInboundAdvisoryUsesTheEnforcementKeys_6640 pins the reason the two
// physical/unit rows above stopped warning, so a future change cannot make them
// pass for a different reason (for example by suppressing every physical-level
// advisory outright).
//
// The advisory now reasons about the keys the dataplane ENFORCES on — a physical
// interface WITH units is never itself a key, its units are — and the resolved
// override on those keys is what it reads. Asserting the resolved view directly
// here means the advisory test above and the enforcement test in
// pkg/dataplane/userspace are anchored to the same observable.
func TestHostInboundAdvisoryUsesTheEnforcementKeys_6640(t *testing.T) {
	cfg, err := CompileConfig(buildTree(t, hostInbound6640PhysicalUnit("any-service", "rpm")))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	resolved := ResolveInterfaceHostInbound(cfg)
	unit := resolved["ge-0/0/0.0"]
	if unit == nil {
		t.Fatalf("the physical override did not resolve onto the unit key at all: %v", resolved)
	}
	var sawAny, sawRPM bool
	for _, s := range unit.SystemServices {
		switch strings.ToLower(s) {
		case "any-service":
			sawAny = true
		case "rpm":
			sawRPM = true
		}
	}
	if !sawAny || !sawRPM {
		t.Errorf("resolved unit set = %v, want the UNION of the physical and unit overrides "+
			"(#3720) — the advisory reads this, so a merge that dropped either token would "+
			"make it warn or stay silent for the wrong reason", unit.SystemServices)
	}
}
