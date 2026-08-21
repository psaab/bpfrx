package userspace

// #7077: the claim that makes pkg/dataplane's warn-and-skip disposition
// harmless lives over HERE.
//
// `compileNPTv6` skips a rule whose prefix the GO compiler cannot decode but
// the Rust helper accepts (`fd00:9::/+48`). That is only safe because this
// builder reads `rule.Match` / `rule.Then` out of the config INDEPENDENTLY of
// whatever the compiler did, so the rule still reaches
// `Nptv6State::try_from_snapshots` and is still installed — the apply keeps
// working exactly as it did before #6894.
//
// If this builder ever started deriving its snapshot from the compiler's
// written set instead, that skip would silently become a DROP: the operator's
// translation would stop being installed with no error anywhere, which is the
// #2240 fail-open. This test is what makes that change loud.

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func nptv6HelperAcceptedCfg7077(match, then string) *config.Config {
	cfg := &config.Config{}
	cfg.Security.NAT.Static = []*config.StaticNATRuleSet{{
		Name: "rs-7077", FromZone: "untrust",
		Rules: []*config.StaticNATRule{
			{Name: "r-7077", IsNPTv6: true, Match: match, Then: then},
		},
	}}
	return cfg
}

func TestSnapshotStillEmitsAPrefixTheGoCompilerSkips_7077(t *testing.T) {
	const match, then = "2001:db8:9::/48", "fd00:9::/+48"

	snaps := buildNptv6Snapshots(nptv6HelperAcceptedCfg7077(match, then))
	if len(snaps) != 1 {
		t.Fatalf("buildNptv6Snapshots emitted %d rules, want 1 — a rule "+
			"pkg/dataplane.compileNPTv6 warn-and-SKIPS (#7077) must still reach "+
			"the helper, or the skip becomes a silent DROP of the operator's "+
			"translation (#2240 fail-open)", len(snaps))
	}
	if snaps[0].ExternalPrefix != match || snaps[0].InternalPrefix != then {
		t.Errorf("the builder rewrote the prefixes to (%q, %q); it must copy the "+
			"VERBATIM strings, because the helper's grammar — not Go's — decides "+
			"what installs", snaps[0].ExternalPrefix, snaps[0].InternalPrefix)
	}

	// Control: the builder is not simply emitting everything. A rule carrying
	// an unsupported match scope is still DROPPED (#5818), which is the
	// separate disposition compileNPTv6 also honors.
	scoped := nptv6HelperAcceptedCfg7077(match, then)
	scoped.Security.NAT.Static[0].Rules[0].MatchDestinationPort = 443
	if got := buildNptv6Snapshots(scoped); len(got) != 0 {
		t.Errorf("a rule with an unsupported match scope was emitted (%d rules) "+
			"— without this control the assertion above is satisfied by a builder "+
			"that emits unconditionally", len(got))
	}
}
