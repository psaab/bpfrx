package config

import (
	"strings"
	"testing"
)

// #4313: `snmp community <name>` is closed-world.
//
// This subtree was on the PR-C SKIP list — "snmp community (Junos view /
// client-list-name / routing-instance unmodeled)" — because closing a
// partially-modeled subtree false-rejects valid config, which is strictly
// worse than the silent-drop it replaces. Modeling those three leaves is what
// made the flip safe, in the same add-then-arm order `security ike proposal`
// followed when one missing `description` leaf was all that blocked it.
//
// The rejection direction was MEASURED, not assumed: arming the subtree before
// modeling them failed TestSNMPInertKnobAdvisories on
// `set snmp community <name> view myview`, a real Junos leaf carried by a
// committed fixture. That is the "a leaf the schema is missing, so the subtree
// is not ready" case, and it is why the three leaves land in the same change.
//
// NOTE on the measurement's own limit: the corpus surfaced `view` because a
// fixture happened to use it. It could not have surfaced `client-list-name` or
// `routing-instance`, which no fixture exercises — those come from the Junos
// grammar recorded in the PR-C skip note. A corpus run bounds what you can
// observe, not what exists.

// TestSNMPCommunityClosedWorldRejectsUnmodeled_4313 is the fail-on-revert:
// remove `closedWorld: true` from the `community` node and this goes green
// while the typo commits clean and is silently dropped.
func TestSNMPCommunityClosedWorldRejectsUnmodeled_4313(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  string
	}{
		// A plausible typo of a modeled leaf.
		{"typo of authorization", "set snmp community public authorisation read-only"},
		// A Junos-shaped keyword this subtree genuinely does not model.
		{"unmodeled keyword", "set snmp community public logical-system LS1"},
		// Garbage.
		{"garbage", "set snmp community public zzzz 1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildTree4303(t, []string{tc.set})
			err := SchemaValidate(tree, nil)
			if err == nil {
				t.Fatalf("closed-world must REJECT %q at commit; it committed clean, which "+
					"means the keyword is silently dropped and the operator is told nothing", tc.set)
			}
			if !strings.Contains(err.Error(), "closed-world subtree") {
				t.Fatalf("expected the closed-world rejection, got: %v", err)
			}
		})
	}
}

// TestSNMPCommunityClosedWorldAcceptsEveryModeledLeaf_4313 is the negative
// control, and it is the assertion that stops the guard degenerating into
// "reject everything under snmp community".
//
// It exercises EVERY modeled child, including the three added to make the flip
// safe. If any of them were dropped from the schema, closed-world would turn a
// valid Junos config into a commit failure — the #4191 false-reject class the
// leaf-completeness audit exists to prevent — and this test is what catches it.
func TestSNMPCommunityClosedWorldAcceptsEveryModeledLeaf_4313(t *testing.T) {
	tree := buildTree4303(t, []string{
		"set snmp community public authorization read-only",
		"set snmp community public clients 10.0.0.0/8",
		"set snmp community public view myview",
		"set snmp community public client-list-name trusted-nms",
		"set snmp community public routing-instance mgmt-vrf",
	})
	if err := SchemaValidate(tree, nil); err != nil {
		t.Fatalf("a config using only MODELED snmp community leaves must COMMIT — closing a "+
			"subtree must reject unmodeled keywords, not valid Junos: %v", err)
	}
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("the same config must survive the full strict compile: %v", err)
	}
}

// TestSNMPCommunityClosedWorldTolerantPathDoesNotBrick_4313 pins the
// strict-vs-tolerant asymmetry this rollout relies on.
//
// Closing a subtree is a behaviour change: a config that used to commit now
// fails. That is correct at the OPERATOR boundary, where the alternative is a
// silent drop. It would NOT be correct on the paths where refusing means an
// outage — `Store.Load` at boot and `Store.SyncApply` on HA peer sync — so
// configstore downgrades schema violations to a warning there (store.go). A
// config an older build persisted, or a peer sends, must still load.
//
// Without this leg the rollout would be one upgrade away from a boot-time
// brick, and nothing else in the file would say so.
func TestSNMPCommunityClosedWorldTolerantPathDoesNotBrick_4313(t *testing.T) {
	tree := buildTree4303(t, []string{
		"set snmp community public authorization read-only",
		"set snmp community public logical-system LS1", // unmodeled: strict rejects
	})
	if err := SchemaValidate(tree, nil); err == nil {
		t.Fatalf("premise: strict validation must reject the unmodeled keyword")
	}
	if _, err := CompileConfigLenient(tree); err != nil {
		t.Fatalf("the TOLERANT path must not brick on a config carrying a keyword that strict "+
			"now rejects — a persisted or peer-synced config would fail to load and the node "+
			"would come up with no configuration at all: %v", err)
	}
}
