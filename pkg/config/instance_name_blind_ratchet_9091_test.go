package config

import (
	"sort"
	"strings"
	"testing"
)

// The schema walk does not close a world around instance-name containers, so an
// unknown keyword in one's body commits clean and is silently ignored (#9091).
//
//	system login class c1 { xpfbogus 5; }           -> ACCEPTED (unknown keyword)
//	system login class c1 { idle-timeout notanum; } -> REJECTED (declared leaf, bad value)
//	security ike gateway g1 { bogus-token 5; }      -> ACCEPTED
//	security flow tcp-session { bogus-token 5; }    -> REJECTED (closed world)
//
// So the operator-facing consequence is narrower than an unqualified reading: a
// mistyped KEYWORD is silent, a bad VALUE on a correctly-spelled leaf is still
// caught. It is still #8928's shape — no value and no complaint — reached by
// schema blindness rather than by elision.
//
// WHY A RATCHET RATHER THAN A FIX. Making the walk descend strictly would turn
// every one of these containers strict AT ONCE, so every config that commits
// today with a typo in one starts failing at commit. That is the correct
// direction and the loud one, but it is exactly what #1960's no-brick doctrine
// exists to stage — and it is ASYMMETRIC: Store.Commit takes the strict path
// while Store.Load (boot from the persisted DB) and Store.SyncApply (HA config
// sync) take compileTreeLenient, which downgrades the identical violation to a
// warning. A config that stopped committing would still boot, warn, and
// silently truncate. The useful shape is per-container opt-in (closedWorld),
// worked down with evidence per container — which is what this ratchet makes
// visible and safe to do.

// instanceNameBlind9091 splits instance-name containers into those a
// closed-world subtree covers and those it does not.
//
// Predicate: args>=1 && len(children)>0 && wildcard==nil, with closedWorld
// INHERITED exactly as walkSchemaNode inherits it
// (childClosed := closed || childSchema.closedWorld).
//
// Path-keyed `seen`, `groups` skipped at the root, depth capped — the same
// three precautions inert_validator_ratchet_test.go takes and for the same
// three reasons: a node-keyed walk plus a path filter is non-deterministic
// under Go's randomised map order and gives a different count per run while
// looking stable within one; the groups/ mirror re-hosts the SAME schema node
// objects and would double every hit (#8921); and a deep or cyclic schema
// would not terminate. Measured stable at 156/7 over five consecutive runs.
func instanceNameBlind9091() (blind, armed []string) {
	seen := map[string]bool{}
	var walk func(n *schemaNode, path string, closed bool)
	walk = func(n *schemaNode, path string, closed bool) {
		if n == nil || seen[path] || strings.Count(path, "/") > 14 {
			return
		}
		seen[path] = true
		for k, c := range n.children {
			if c == nil || (path == "" && k == "groups") {
				continue
			}
			p := path + "/" + k
			childClosed := closed || c.closedWorld
			if c.args >= 1 && len(c.children) > 0 && c.wildcard == nil {
				if childClosed {
					armed = append(armed, p)
				} else {
					blind = append(blind, p)
				}
			}
			walk(c, p, childClosed)
		}
		if n.wildcard != nil {
			walk(n.wildcard, path+"/*", closed || n.wildcard.closedWorld)
		}
	}
	walk(setSchema, "", setSchema.closedWorld)
	sort.Strings(blind)
	sort.Strings(armed)
	return blind, armed
}

// instanceNameBlindCeiling9091 is the measured schema-blind population.
//
// WHAT THIS NUMBER IS NOT. #9091's headline is 102, and this is deliberately a
// DIFFERENT measurement — conflating them would misreport the state. 102 is the
// set that fails open END TO END at configstore.CheckText. This is the
// SCHEMA-SIDE set, which is a strict SUPERSET: the issue's own correction
// records 246 schema-blind collapsing to 205 end-to-end, because a later
// compiler gate catches some of them (`applications application`, `chassis
// cluster redundancy-group`). Schema blindness is an UPPER BOUND on fail-open,
// not the fail-open set, and a walk result is a claim about the walk.
//
// The upper bound is nonetheless the right thing to bound here, because the
// anti-regression property the issue asks for is "a new instance-name container
// cannot be added silently" — and a new container enters this set whether or
// not some later compiler gate happens to catch it. Bounding the superset
// cannot miss one.
//
// Lowering it is the goal: arming a container's closedWorld moves it from blind
// to armed and this number drops. The equality assertion is deliberate — a
// DROP fails too, so the ceiling cannot silently stop tracking reality after
// someone does the work.
const instanceNameBlindCeiling9091 = 156

// instanceNameArmedFloor9091 is the count of instance-name containers already
// covered by a closed-world subtree. Asserted so the instrument cannot report
// "nothing is blind" by having stopped finding anything.
const instanceNameArmedFloor9091 = 7

func TestInstanceNameBlindPopulationIsRatcheted9091(t *testing.T) {
	blind, armed := instanceNameBlind9091()

	if len(blind) > instanceNameBlindCeiling9091 {
		t.Errorf("#9091: the schema-blind instance-name container population GREW to "+
			"%d (ceiling %d). A new container that takes an instance name, declares "+
			"children and sits outside a closed world accepts an unknown keyword in "+
			"its body at commit — the operator gets no value and no complaint. Arm "+
			"it (closedWorld) or, if it is genuinely open-world, raise the ceiling "+
			"WITH the reason.\nnew: %v",
			len(blind), instanceNameBlindCeiling9091, added9091(blind))
	}
	if len(blind) < instanceNameBlindCeiling9091 {
		t.Errorf("#9091: the population SHRANK to %d (ceiling %d) — good, but lower "+
			"the ceiling in the same change. A ceiling left above reality stops "+
			"being a ratchet: it silently re-admits every container between the two "+
			"numbers.", len(blind), instanceNameBlindCeiling9091)
	}
	if len(armed) != instanceNameArmedFloor9091 {
		t.Errorf("#9091: the ARMED count moved to %d (expected %d). Arming is the "+
			"remedy, so it moving is expected — but it must move deliberately, and "+
			"a DROP means a closed world was disarmed and its container silently "+
			"went back to accepting unknown keywords.\narmed: %v",
			len(armed), instanceNameArmedFloor9091, armed)
	}
}

// TestInstanceNameBlindInstrumentStillDiscriminates9091 is the control, and it
// runs in BOTH directions on purpose.
//
// A ratchet that goes green because its population emptied is indistinguishable
// from one that went green because it stopped looking. A count assertion alone
// cannot tell those apart: break the predicate, the walk, or the closedWorld
// inheritance and the number simply changes, which reads as news about the
// schema rather than about the instrument.
//
// So the instrument is pinned against containers whose classification #9091
// established INDEPENDENTLY, by measuring commit behaviour end-to-end at
// configstore.CheckText rather than by reading the schema. That the two
// instruments agree on these six is a cross-check, not a restatement.
func TestInstanceNameBlindInstrumentStillDiscriminates9091(t *testing.T) {
	blind, armed := instanceNameBlind9091()
	if len(blind) == 0 || len(armed) == 0 {
		t.Fatalf("#9091: the enumeration returned blind=%d armed=%d. An empty side "+
			"makes every verdict below vacuous — the instrument is broken, not the "+
			"schema clean.", len(blind), len(armed))
	}
	set := func(l []string) map[string]bool {
		m := map[string]bool{}
		for _, p := range l {
			m[p] = true
		}
		return m
	}
	blindSet, armedSet := set(blind), set(armed)

	// Direction 1 — known BLIND. #9091 measured each of these accepting a bogus
	// keyword at CheckText.
	for _, p := range []string{
		"/security/ike/gateway", // security ike gateway g1 { bogus-token 5; } -> ACCEPTED
		"/security/ipsec/vpn",   // security ipsec vpn v1   { bogus-token 5; } -> ACCEPTED
		"/system/login/class",   // system login class c1   { xpfbogus 5; }    -> ACCEPTED
	} {
		if !blindSet[p] {
			t.Errorf("#9091: %s is no longer classified blind. Either it was armed "+
				"(then lower the ceiling and say so) or the instrument stopped "+
				"detecting blindness — and those two look identical in the count.", p)
		}
	}

	// Direction 2 — known ARMED. Without this, a predicate that classified
	// EVERYTHING as blind would pass direction 1 completely.
	for _, p := range []string{
		"/protocols/rip/group",   // armed by #9206
		"/security/ike/proposal", // armed by an earlier closed-world flip
	} {
		if !armedSet[p] {
			t.Errorf("#9091: %s is no longer classified armed. If a closed world was "+
				"disarmed that is a real regression; if not, the instrument has "+
				"stopped seeing closedWorld inheritance and every 'armed' verdict "+
				"it reports is unearned.", p)
		}
	}

	// A path in NEITHER set that should be in one would be invisible above, so
	// pin that the two sets are disjoint and that a non-candidate stays out.
	for _, p := range blind {
		if armedSet[p] {
			t.Errorf("#9091: %s is in both sets — the classification is not a partition", p)
		}
	}
	// `security flow tcp-session` has args==0, so it is not a candidate at all.
	// #9091 measured it REJECTING a bogus keyword; if it ever appears here the
	// predicate has drifted off "takes an instance name".
	if blindSet["/security/flow/tcp-session"] || armedSet["/security/flow/tcp-session"] {
		t.Error("#9091: /security/flow/tcp-session is args==0 and must not be a " +
			"candidate — the predicate has drifted off 'takes an instance name'")
	}
}

// added9091 reports the paths that would need justifying if the ceiling were
// raised. Cheap to compute and it turns a bare count into something reviewable:
// an aggregate count is not reviewable, the list is.
func added9091(blind []string) []string {
	if len(blind) <= instanceNameBlindCeiling9091 {
		return nil
	}
	return blind[instanceNameBlindCeiling9091:]
}
