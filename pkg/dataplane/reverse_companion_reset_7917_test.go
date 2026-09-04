package dataplane

import (
	"reflect"
	"testing"
)

// #7917: the reverse companion must not inherit the FORWARD direction's ingress
// identity.
//
// `mirrorSessionPairV4`/`V6` used to synthesize a reverse companion by copying
// the forward value, swapping the zones, and clearing the cached FIB result. They
// did not clear the #4983 ingress identity, so the companion carried the forward
// direction's ingress binding — a value `pkg/dataplane/types.go` names as a
// legitimate-`0` population, because a prediction of where the reply will arrive
// is not an observation of where it did and routing may be asymmetric.
//
// #8015 deleted those Go-side companion builders; the helper's
// `synthesized_synced_reverse_entry` is the only companion builder left and it
// applies the same rule (pinned by
// `synthesized_synced_reverse_entry_carries_no_ingress_identity_7917`). These
// cells outlive that deletion on purpose: they pin the RULE and its divergence
// from `ScrubNodeLocal`, which is what stops a future node-local field from
// silently becoming a companion reset — see the note in
// `session_reverse_companion.go`.
//
// These tests use the same census shape as the #7097 scrub guard (fill every
// field with a sentinel, compare the zeroed set against a declared set in BOTH
// directions), and add the one thing that change did not need: a pin that this
// reset and `ScrubNodeLocal` stay DIFFERENT rules.

// companionResetFields are the fields a reverse companion must not inherit.
var companionResetFields = map[string]bool{
	// Forward egress — the reply's egress is a separate lookup.
	"FibIfindex": true,
	"FibVlanID":  true,
	"FibDmac":    true,
	"FibSmac":    true,
	"FibGen":     true,
	// Forward ingress — unobserved for the reply, in all three spellings.
	"IngressIfindex":   true,
	"IngressVlanID":    true,
	"IngressIfaceFold": true,
}

func assertCompanionCensus(t *testing.T, before, after reflect.Value) {
	t.Helper()
	reset := zeroedFields(before, after)
	if len(reset) == 0 {
		t.Fatal("the companion reset cleared NOTHING — the fixture or the call did " +
			"not run, and the two directional checks below would both pass vacuously")
	}
	for name := range companionResetFields {
		if !reset[name] {
			t.Errorf("%s records something the REVERSE direction has not observed, "+
				"but the companion inherited it from the forward session. That is a "+
				"confident value on an unobserved binding, which is the failure mode "+
				"`0` exists to avoid (#7917)", name)
		}
	}
	for name := range reset {
		if !companionResetFields[name] {
			t.Errorf("the companion reset clears %s, which is not declared unobserved. "+
				"Either it is and this list is stale, or the reset is destroying a "+
				"field the companion legitimately carries — the forward row's counters "+
				"and zones are deliberately NOT reset here (#7917)", name)
		}
	}
}

func TestReverseCompanionResetCoversExactlyTheUnobservedFields7917(t *testing.T) {
	t.Run("v4", func(t *testing.T) {
		var val SessionValue
		fillNonZero(t, reflect.ValueOf(&val).Elem())
		before := reflect.ValueOf(val)
		val.ResetUnobservedForReverseCompanion()
		assertCompanionCensus(t, before, reflect.ValueOf(val))
	})
	t.Run("v6", func(t *testing.T) {
		var val SessionValueV6
		fillNonZero(t, reflect.ValueOf(&val).Elem())
		before := reflect.ValueOf(val)
		val.ResetUnobservedForReverseCompanion()
		assertCompanionCensus(t, before, reflect.ValueOf(val))
	})
}

// The divergence pin. The tempting simplification is to make the companion call
// `ScrubNodeLocal` — it clears most of the same fields. This asserts why that is
// wrong, in a form that fails if someone does it.
//
// The two rules answer different questions:
//
//	ScrubNodeLocal                    "does this value belong to another NODE?"
//	ResetUnobservedForReverseCompanion "has this DIRECTION observed this yet?"
//
// `IngressIfaceFold` is where they visibly part company, and it is not a
// hypothetical: #7095 added it as a CLUSTER-STABLE fold whose whole purpose is
// to cross the wire, so the node-local scrub must leave it alone — while the
// companion must clear it, because the wire request derives its ingress identity
// from the fold and would otherwise stamp the forward binding on the reply.
func TestCompanionResetAndNodeLocalScrubAreDifferentRules7917(t *testing.T) {
	if !companionResetFields["IngressIfaceFold"] {
		t.Fatal("the companion reset must clear IngressIfaceFold: the helper wire " +
			"request derives its ingress identity from the fold, so a companion that " +
			"keeps it stamps the FORWARD direction's binding on the reply (#7917)")
	}
	if nodeLocalSessionFields["IngressIfaceFold"] {
		t.Fatal("ScrubNodeLocal must NOT clear IngressIfaceFold: it is the #7095 " +
			"CLUSTER-STABLE fold, and zeroing it on a peer install is what it exists " +
			"to prevent — the #4983 identity would stop surviving a failover (#7917)")
	}
	if reflect.DeepEqual(companionResetFields, nodeLocalSessionFields) {
		t.Fatal("the reverse-companion reset and the node-local scrub now cover the " +
			"same fields. They are different rules — 'belongs to another node' and " +
			"'this direction has not observed it' — and collapsing them makes every " +
			"future node-local field a companion reset and vice versa, neither of " +
			"which follows (#7917)")
	}

	// Anti-vacuity: the check above is only meaningful while both sets are
	// non-empty and actually overlap. Two unrelated sets would satisfy
	// !DeepEqual for the wrong reason.
	var shared int
	for name := range companionResetFields {
		if nodeLocalSessionFields[name] {
			shared++
		}
	}
	if shared == 0 {
		t.Fatal("the two sets no longer overlap at all, so the divergence assertion " +
			"above proves nothing about them being confusable — re-read whether " +
			"either list is still describing what this test thinks it describes")
	}
}
