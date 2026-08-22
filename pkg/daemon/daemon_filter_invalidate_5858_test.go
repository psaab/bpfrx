package daemon

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// filterCfg builds a config with one interface unit whose family-inet input
// filter is `filterName`, and a firewall filter of that name carrying `action`
// on a single term (empty action = no terminating action at all).
func filterCfg(filterName, action string) *config.Config {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/1": {
			Name: "ge-0/0/1",
			Units: map[int]*config.InterfaceUnit{
				0: {FilterInputV4: filterName},
			},
		},
	}
	if filterName != "" {
		cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
			filterName: {
				Name:  filterName,
				Terms: []*config.FirewallFilterTerm{{Name: "t1", Action: action}},
			},
		}
	}
	return cfg
}

// TestInputFilterAttachIsReported_5858 is the issue's scenario. Attaching a
// filter with `then discard` to an interface does NOT revoke sessions already
// established through it — the session-hit path re-evaluates an input filter
// only for DSCP / per-packet-L4 terms, so a static deny is never rechecked and
// the flow forwards until it idles out.
//
// The policy analogue of this clear SHIPPED (clearSessionsForPolicyChanges), so
// an operator who has seen a policy tightening take effect immediately has
// every reason to expect the same here. The commit must say it does not.
//
// RED-on-revert: drop the warnInputFilterRevocationGap call (or the append) and
// the commit reports clean on a config whose new deny is not in force.
func TestInputFilterAttachIsReported_5858(t *testing.T) {
	oldCfg := filterCfg("", "")
	newCfg := filterCfg("block-ssh", "discard")

	(&Daemon{}).warnInputFilterRevocationGap(oldCfg, newCfg)

	if len(newCfg.Warnings) == 0 {
		t.Fatal("attaching a discard filter produced no commit warning: the operator sees a " +
			"clean commit and believes the deny is in force on established sessions")
	}
	w := strings.Join(newCfg.Warnings, "\n")
	for _, want := range []string{"ge-0/0/1", "block-ssh", "clear security flow session interface", "#5858"} {
		if !strings.Contains(w, want) {
			t.Errorf("the advisory must contain %q — it has to name the affected interface, the "+
				"filter, and the command that revokes the sessions. got:\n%s", want, w)
		}
	}
}

// TestInputFilterDefinitionChangeIsReported_5858 covers the case a name
// comparison alone misses, and the more common one in practice: the interface
// keeps pointing at the same filter and the FILTER is edited. If only the
// attachment name were compared, adding `then discard` to an already-attached
// filter would warn about nothing.
func TestInputFilterDefinitionChangeIsReported_5858(t *testing.T) {
	oldCfg := filterCfg("wan-in", "accept")
	newCfg := filterCfg("wan-in", "discard")

	(&Daemon{}).warnInputFilterRevocationGap(oldCfg, newCfg)

	if len(newCfg.Warnings) == 0 {
		t.Fatal("editing an already-attached filter to add a deny produced no warning; a " +
			"name-only comparison would miss exactly this case")
	}
	if !strings.Contains(strings.Join(newCfg.Warnings, "\n"), "wan-in") {
		t.Errorf("the advisory must name the edited filter: %v", newCfg.Warnings)
	}
}

// TestInputFilterNoiseControls_5858 holds the false-alarm line. A commit-time
// warning an operator cannot act on is one they learn to ignore, which costs
// the warnings that matter — so every case here must stay SILENT.
//
// Together these also stop the fix from being satisfiable by warning
// unconditionally.
func TestInputFilterNoiseControls_5858(t *testing.T) {
	t.Run("unchanged filter", func(t *testing.T) {
		oldCfg := filterCfg("wan-in", "discard")
		newCfg := filterCfg("wan-in", "discard")
		(&Daemon{}).warnInputFilterRevocationGap(oldCfg, newCfg)
		if len(newCfg.Warnings) != 0 {
			t.Errorf("an unrelated commit that does not touch the filter warned about it; "+
				"established sessions were ALREADY subject to it: %v", newCfg.Warnings)
		}
	})

	t.Run("accept-only filter attached", func(t *testing.T) {
		oldCfg := filterCfg("", "")
		newCfg := filterCfg("count-only", "accept")
		(&Daemon{}).warnInputFilterRevocationGap(oldCfg, newCfg)
		if len(newCfg.Warnings) != 0 {
			t.Errorf("a filter that can deny nothing cannot revoke anything, so warning about "+
				"it is a false alarm: %v", newCfg.Warnings)
		}
	})

	t.Run("filter detached", func(t *testing.T) {
		oldCfg := filterCfg("block-ssh", "discard")
		newCfg := filterCfg("", "")
		(&Daemon{}).warnInputFilterRevocationGap(oldCfg, newCfg)
		if len(newCfg.Warnings) != 0 {
			t.Errorf("removing a filter is strictly LOOSENING; no session can be newly denied "+
				"by the absence of one: %v", newCfg.Warnings)
		}
	})

	t.Run("no interfaces at all", func(t *testing.T) {
		newCfg := &config.Config{}
		(&Daemon{}).warnInputFilterRevocationGap(&config.Config{}, newCfg)
		if len(newCfg.Warnings) != 0 {
			t.Errorf("an empty config warned: %v", newCfg.Warnings)
		}
	})
}

// TestFilterCanDenyReadsTerminalActions_5858 pins the reason both action fields
// are consulted. Action is single-valued and last-write-wins, while
// TerminalActions records EVERY terminating keyword the term's `then` blocks
// carried — so a term with `then discard` followed by `then accept` resolves
// Action to "accept" and still denies through the recorded set. Reading Action
// alone would call that filter harmless.
func TestFilterCanDenyReadsTerminalActions_5858(t *testing.T) {
	f := &config.FirewallFilter{
		Name: "mixed",
		Terms: []*config.FirewallFilterTerm{{
			Name:            "t1",
			Action:          "accept",
			TerminalActions: []string{"discard", "accept"},
		}},
	}
	if !filterCanDeny(f) {
		t.Error("a term whose recorded terminal actions include discard was classified as " +
			"unable to deny, because only the last-write-wins Action was read")
	}

	// Control: a genuinely accept-only term must stay classified harmless, so
	// this is not satisfiable by returning true.
	harmless := &config.FirewallFilter{
		Name:  "ok",
		Terms: []*config.FirewallFilterTerm{{Name: "t1", Action: "accept", TerminalActions: []string{"accept"}}},
	}
	if filterCanDeny(harmless) {
		t.Error("an accept-only filter was classified as able to deny")
	}
}

// TestInputFilterV6IsCovered_5858 pins the inet6 family. The two families carry
// independent attachments (FilterInputV4 / FilterInputV6) resolved through
// independent tables (FiltersInet / FiltersInet6), so a v4-only implementation
// would leave every IPv6 filter change silent — and this box is dual-stack by
// design.
func TestInputFilterV6IsCovered_5858(t *testing.T) {
	newCfg := &config.Config{}
	newCfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/2": {Name: "ge-0/0/2", Units: map[int]*config.InterfaceUnit{0: {FilterInputV6: "v6-block"}}},
	}
	newCfg.Firewall.FiltersInet6 = map[string]*config.FirewallFilter{
		"v6-block": {Name: "v6-block", Terms: []*config.FirewallFilterTerm{{Name: "t1", Action: "reject"}}},
	}

	(&Daemon{}).warnInputFilterRevocationGap(&config.Config{}, newCfg)

	w := strings.Join(newCfg.Warnings, "\n")
	if !strings.Contains(w, "inet6") || !strings.Contains(w, "v6-block") {
		t.Errorf("an inet6 input filter change was not reported: %v", newCfg.Warnings)
	}
}

// TestReportSessionAuthorizationChangesIncludesFilterAdvisory_5858 binds the
// WIRING. Every other test in this file calls warnInputFilterRevocationGap
// directly, so all of them would pass on a build where no commit path ever
// invokes it — the advisory present in the package and absent from `commit`.
//
// The three commit paths (commit, commit-confirmed, confirmed-rollback) all go
// through reportSessionAuthorizationChanges, so pinning it here pins them.
//
// RED-on-revert: drop the warnInputFilterRevocationGap call from
// reportSessionAuthorizationChanges and this fails while every other test in
// the file still passes.
func TestReportSessionAuthorizationChangesIncludesFilterAdvisory_5858(t *testing.T) {
	oldCfg := filterCfg("", "")
	newCfg := filterCfg("block-ssh", "discard")

	// A nil dataplane makes the policy-clear half a no-op, which is what we
	// want: this test is about the advisory being reached, not about the clear.
	if err := (&Daemon{}).reportSessionAuthorizationChanges(oldCfg, newCfg); err != nil {
		t.Fatalf("policy clear half errored on a no-dataplane daemon: %v", err)
	}
	if len(newCfg.Warnings) == 0 {
		t.Fatal("the commit-time entry point did not produce the #5858 advisory: a commit that " +
			"attaches a discard filter reports clean, and the operator never learns that " +
			"established sessions keep forwarding")
	}
}
