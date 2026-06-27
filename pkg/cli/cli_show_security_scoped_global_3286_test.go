package cli

import (
	"regexp"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// #3286: the CLI `show security policies` surfaces rendered a scoped global
// policy (#3148, `match from-zone`/`to-zone`) as all-zones — the detail view
// printed "From zone: junos-global, To zone: junos-global", the standard view
// printed "From zones: any / To zones: any", and the brief view printed "*"/"*"
// — hiding the configured zone scope. These tests are the fail-on-revert guard:
// each surface must now print the scoped zones for a scoped global and keep the
// all-zones placeholder for an unscoped global.

// scopedGlobalCLIConfig has one scoped global (trust->untrust deny) and one
// unscoped global (all-zones permit).
func scopedGlobalCLIConfig() *config.Config {
	cfg := &config.Config{}
	cfg.Security.GlobalPolicies = []*config.Policy{
		{
			Name:   "scoped-global",
			Match:  config.PolicyMatch{FromZone: "trust", ToZone: "untrust"},
			Action: config.PolicyDeny,
		},
		{
			Name:   "open-global",
			Action: config.PolicyPermit,
		},
	}
	return cfg
}

// Test_3286_PolicyDetailScopedGlobalShowsZones covers the detail view
// (showPoliciesDetail). Reverting the render to the hard-coded junos-global
// placeholder turns the scoped assertion RED.
func Test_3286_PolicyDetailScopedGlobalShowsZones(t *testing.T) {
	cfg := scopedGlobalCLIConfig()
	c := &CLI{}

	out := captureStdout(t, func() {
		if err := c.showPoliciesDetail(cfg, "", ""); err != nil {
			t.Fatalf("showPoliciesDetail: %v", err)
		}
	})

	scoped := policyDetailZoneLine(t, out, "scoped-global")
	if !strings.Contains(scoped, "From zone: trust") || !strings.Contains(scoped, "To zone: untrust") {
		t.Fatalf("scoped-global detail zone line = %q, want From zone: trust / To zone: untrust "+
			"(scoped global shown as all-zones — #3286 regression)", scoped)
	}
	open := policyDetailZoneLine(t, out, "open-global")
	if !strings.Contains(open, "From zone: junos-global") || !strings.Contains(open, "To zone: junos-global") {
		t.Fatalf("open-global detail zone line = %q, want junos-global/junos-global (unscoped global)", open)
	}
}

// policyDetailZoneLine returns the "From zone: ..., To zone: ..." line that
// follows the named policy's "Policy: <name>" header in detail output.
func policyDetailZoneLine(t *testing.T, out, name string) string {
	t.Helper()
	lines := strings.Split(out, "\n")
	hdr := regexp.MustCompile(`Policy: ` + regexp.QuoteMeta(name) + `,`)
	for i, line := range lines {
		if hdr.MatchString(line) {
			for _, follow := range lines[i:] {
				if strings.Contains(follow, "From zone:") {
					return follow
				}
			}
		}
	}
	t.Fatalf("policy %q zone line not found in detail output:\n%s", name, out)
	return ""
}

// Test_3286_PolicyStandardScopedGlobalShowsZones covers the standard
// (non-detail) view reached via handleShow. Reverting to the hard-coded
// "any"/"any" lines turns the scoped assertion RED.
func Test_3286_PolicyStandardScopedGlobalShowsZones(t *testing.T) {
	c := scopedGlobalCLI(t)

	out := captureStdout(t, func() {
		if err := c.handleShow([]string{"security", "policies"}); err != nil {
			t.Fatalf("handleShow(security policies): %v", err)
		}
	})

	scoped := policyStandardBlock(t, out, "scoped-global")
	if !strings.Contains(scoped, "From zones: trust") || !strings.Contains(scoped, "To zones: untrust") {
		t.Fatalf("scoped-global standard block = %q, want From zones: trust / To zones: untrust "+
			"(scoped global shown as all-zones — #3286 regression)", scoped)
	}
	open := policyStandardBlock(t, out, "open-global")
	if !strings.Contains(open, "From zones: any") || !strings.Contains(open, "To zones: any") {
		t.Fatalf("open-global standard block = %q, want any/any (unscoped global)", open)
	}
}

// policyStandardBlock returns the two zone lines following a named policy
// header in the standard "Global policies:" view.
func policyStandardBlock(t *testing.T, out, name string) string {
	t.Helper()
	lines := strings.Split(out, "\n")
	hdr := regexp.MustCompile(`Policy: ` + regexp.QuoteMeta(name) + `,`)
	for i, line := range lines {
		if hdr.MatchString(line) {
			end := i + 6
			if end > len(lines) {
				end = len(lines)
			}
			return strings.Join(lines[i:end], "\n")
		}
	}
	t.Fatalf("policy %q block not found in standard output:\n%s", name, out)
	return ""
}

// Test_3286_PolicyBriefScopedGlobalShowsZones covers the brief tabular view.
// Reverting to the hard-coded "*"/"*" columns turns the scoped assertion RED.
func Test_3286_PolicyBriefScopedGlobalShowsZones(t *testing.T) {
	c := scopedGlobalCLI(t)

	out := captureStdout(t, func() {
		if err := c.handleShow([]string{"security", "policies", "brief"}); err != nil {
			t.Fatalf("handleShow(security policies brief): %v", err)
		}
	})

	scoped := briefRow(t, out, "scoped-global")
	if !(strings.Contains(scoped, "trust") && strings.Contains(scoped, "untrust")) {
		t.Fatalf("scoped-global brief row = %q, want trust/untrust columns "+
			"(scoped global shown as all-zones — #3286 regression)", scoped)
	}
	open := briefRow(t, out, "open-global")
	fields := strings.Fields(open)
	if len(fields) < 2 || fields[0] != "*" || fields[1] != "*" {
		t.Fatalf("open-global brief row = %q, want */* columns (unscoped global)", open)
	}
}

// Test_3286_PolicyHitCountScopedGlobalShowsZones covers the CLI hit-count
// table. Reverting to the hard-coded junos-global columns turns the scoped
// assertion RED.
func Test_3286_PolicyHitCountScopedGlobalShowsZones(t *testing.T) {
	c := scopedGlobalCLI(t)
	// hit-count returns early unless a dataplane is loaded.
	c.dp = &policyCounterCLIDP{
		Manager:  dataplane.New(),
		counters: map[uint32]dataplane.CounterValue{},
	}

	out := captureStdout(t, func() {
		if err := c.handleShow([]string{"security", "policies", "hit-count"}); err != nil {
			t.Fatalf("handleShow(security policies hit-count): %v", err)
		}
	})

	scoped := briefRow(t, out, "scoped-global")
	if !(strings.Contains(scoped, "trust") && strings.Contains(scoped, "untrust")) {
		t.Fatalf("scoped-global hit-count row = %q, want trust/untrust columns "+
			"(scoped global shown as all-zones — #3286 regression)", scoped)
	}
	open := briefRow(t, out, "open-global")
	if !strings.Contains(open, "junos-global") {
		t.Fatalf("open-global hit-count row = %q, want junos-global columns (unscoped global)", open)
	}
}

func briefRow(t *testing.T, out, name string) string {
	t.Helper()
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, name) {
			return line
		}
	}
	t.Fatalf("policy %q row not found in brief output:\n%s", name, out)
	return ""
}

// scopedGlobalCLI builds a store-backed CLI with a scoped + unscoped global
// policy via the configuration grammar (exercises the #3148 compile path).
func scopedGlobalCLI(t *testing.T) *CLI {
	t.Helper()
	store := newConfigStore(t, t.TempDir()+"/xpf.conf")
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	for _, cmd := range []string{
		"security zones security-zone trust",
		"security zones security-zone untrust",
		"security policies global policy scoped-global match from-zone trust",
		"security policies global policy scoped-global match to-zone untrust",
		"security policies global policy scoped-global match source-address any",
		"security policies global policy scoped-global match destination-address any",
		"security policies global policy scoped-global match application any",
		"security policies global policy scoped-global then deny",
		"security policies global policy open-global match source-address any",
		"security policies global policy open-global match destination-address any",
		"security policies global policy open-global match application any",
		"security policies global policy open-global then permit",
	} {
		if err := store.SetFromInput(cmd); err != nil {
			t.Fatalf("SetFromInput(%q): %v", cmd, err)
		}
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	cfg := store.ActiveConfig()
	if cfg == nil || len(cfg.Security.GlobalPolicies) != 2 {
		t.Fatalf("expected 2 global policies, got %v", cfg)
	}
	if cfg.Security.GlobalPolicies[0].Match.FromZone != "trust" {
		t.Fatalf("scoped-global FromZone = %q, want trust", cfg.Security.GlobalPolicies[0].Match.FromZone)
	}
	return &CLI{store: store}
}
