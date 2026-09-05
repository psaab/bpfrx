package config

import "testing"

// #8844: `perfect-forward-secrecy keys <group>;` -- the brace-elided spelling --
// silently DISABLED PFS. The compiled state was byte-identical to never having
// configured it.
//
//	braced   perfect-forward-secrecy { keys group14; }   PFSGroup=14
//	packed   perfect-forward-secrecy keys group14;       PFSGroup=0   <- ABSENT
//	absent   (no stanza)                                 PFSGroup=0
//
// Cause is the #8800 shape: `perfect-forward-secrecy` was declared
// `children: nil` while compileIPsec reads a `keys` CHILD of it, so the head was
// not a schema child, the pass was never ASKED about the pair, and no scope
// entry could name it. The schema's own desc -- "Perfect forward secrecy (keys
// group<N>)" -- documented the child it failed to declare.
//
// WHY THIS ONE IS DIFFERENT FROM THE REST OF ITS FAMILY, and why the guard is
// worth more here: every other member fails CLOSED or LOUD. A zero-address NAT
// pool (#8800) is rejected at strict commit; an empty application-set (#8825) is
// caught by the #3146 gate. This one fails OPEN and is undetectable after the
// fact, because PFSGroup==0 is a legitimate value meaning "deliberately
// disabled" -- so no downstream gate can distinguish "operator chose no PFS"
// from "operator configured PFS and we dropped it". The tunnel comes up,
// traffic flows, and a later compromise of long-term keys retroactively
// decrypts every session negotiated meanwhile.
func TestPFSPackedKeys8844(t *testing.T) {
	// A COMPLETE config: the policy references a proposal that exists, so the
	// strict path is meaningful rather than rejecting every row for an
	// unrelated missing reference.
	mk := func(body string) string {
		return "security { ipsec { " +
			"proposal ip1 { protocol esp; authentication-algorithm hmac-sha-256-128; encryption-algorithm aes-256-cbc; } " +
			"policy p1 { proposals ip1; " + body + " } } }"
	}
	pfs := func(t *testing.T, txt string, masked bool) int {
		t.Helper()
		tree, errs := NewParser(txt).Parse()
		if len(errs) > 0 {
			t.Fatalf("parse: %v", errs)
		}
		if masked {
			// Reproduce pre-#8844 exactly: the pair unadmitted. Paired with
			// skipCompactNormalize, because the pass ALSO runs inside
			// compileConfigWithOpts and would otherwise re-fold with the real
			// scope -- a pre-normalised tree is not a baseline on its own.
			normalizeCompactStanzasWithScope(tree, func(kw, head string) bool {
				if kw == "perfect-forward-secrecy" && head == "keys" {
					return false
				}
				return compactNormalizeInScope(kw, head)
			})
		} else {
			normalizeCompactStanzas(tree)
		}
		lo := lenientCompileOpts()
		lo.skipCompactNormalize = true
		cfg, err := compileConfigWithOpts(tree, lo)
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		if p := cfg.Security.IPsec.Policies["p1"]; p != nil {
			return p.PFSGroup
		}
		return -1
	}

	for _, tc := range []struct {
		name, packed, braced string
		want                 int
	}{
		{"group14", "perfect-forward-secrecy keys group14;", "perfect-forward-secrecy { keys group14; }", 14},
		{"group19", "perfect-forward-secrecy keys group19;", "perfect-forward-secrecy { keys group19; }", 19},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, b := pfs(t, mk(tc.packed), false), pfs(t, mk(tc.braced), false)
			if p != b || p != tc.want {
				t.Errorf("packed and braced DIFFER for perfect-forward-secrecy (#8844)\n"+
					"  packed %q -> PFSGroup=%d\n  braced %q -> PFSGroup=%d (want %d)\n"+
					"PFSGroup==0 means DISABLED and is indistinguishable from the stanza "+
					"being absent, so this fails OPEN and silently: the tunnel comes up "+
					"with no forward secrecy and nothing downstream can detect it. The "+
					"cause was a MISSING SCHEMA DECLARATION -- `keys` was not a child of "+
					"`perfect-forward-secrecy` -- so a scope entry alone cannot fix it.",
					tc.packed, p, tc.braced, b, tc.want)
			}
		})
	}

	// The defect, pinned against its own baseline: with the pair unadmitted the
	// packed spelling must still collapse to 0, or this cell is measuring
	// nothing.
	t.Run("baseline-was-broken", func(t *testing.T) {
		if got := pfs(t, mk("perfect-forward-secrecy keys group14;"), true); got != 0 {
			t.Fatalf("the pre-#8844 baseline no longer reproduces the defect "+
				"(PFSGroup=%d, want 0). If the defect is unreachable by that route "+
				"this guard measures nothing and must be re-derived.", got)
		}
	})

	// DEGENERACY CONTROL: absent must still be 0, or a fix that hard-coded a
	// non-zero default would satisfy every assertion above.
	t.Run("absent-still-disabled", func(t *testing.T) {
		if got := pfs(t, mk(""), false); got != 0 {
			t.Errorf("with no perfect-forward-secrecy stanza PFSGroup must be 0 "+
				"(disabled); got %d. A non-zero default would turn PFS on for "+
				"operators who did not ask for it and would make every other "+
				"assertion here pass vacuously.", got)
		}
	})

	// SEPARATE ROUTE, pinned as known and NOT fixed here: an unparseable group
	// also yields 0. parseDHGroup returns (0,false) and the caller leaves
	// PFSGroup alone. Validating `keys` would newly REJECT a value the tolerant
	// Load path accepts today, so it is deliberately out of scope -- but it is
	// recorded so nobody reads this fix as closing the whole silent-disable
	// surface.
	t.Run("bad-value-still-silently-disables", func(t *testing.T) {
		if got := pfs(t, mk("perfect-forward-secrecy keys nonsense;"), false); got != 0 {
			t.Errorf("expected an unparseable group to leave PFSGroup=0 (unchanged "+
				"by this fix), got %d", got)
		}
	})
}
