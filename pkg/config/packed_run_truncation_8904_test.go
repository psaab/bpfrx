package config

import "testing"

// issue 8904: a PACKED RUN of two statements keeps the first and silently
// discards the rest.
//
// This is the sibling mode of #8883's INJECTION. There a `multi` leaf absorbed
// the repeated keyword as one of its own values, producing a phantom extra
// member; here the container carries the first statement correctly and drops
// everything after it. #8883's fix does not reach it and no gate did either.
//
// WHY THE TUNNEL ROW LEADS: a GRE tunnel that keeps its source and loses its
// destination is worse than one that fails to compile. The interface exists,
// `show configuration` renders both endpoints because the config is stored as
// authored, and the tunnel points nowhere -- with warnings=0 on the tolerant
// path and no rejection on the strict one. That is missing-becomes-WRONG rather
// than missing-becomes-absent: an object that exists, reads as configured, and
// does not work.
//
// THE ELIDED ARM IS A LEGAL SPELLING, checked before believing the divergence:
// `ParseSetCommand` accepts `set … tunnel source A destination B`, so this is a
// form the CLI grammar admits rather than a fixture artifact. That check is
// cheap and it is the one that separates a real divergence from a fabricated
// one -- a two-statement container has no elided spelling unless the grammar
// says it does.
//
// SCOPE: THE HIERARCHICAL SPELLING ONLY, and the boundary was measured rather
// than assumed. The flat-set CLI reaches the same symptom by a DIFFERENT
// mechanism, which this fix does not and should not address:
//
//	set interfaces gr-0/0/0 unit 0 tunnel source 10.0.0.1 destination 10.0.0.2
//	  -> SetPath builds a NESTED CHAIN, tunnel > source 10.0.0.1 > destination
//	     10.0.0.2, so `destination` is a CHILD of `source` rather than a packed
//	     tail. normalizeCompactStanzas folds nothing (measured: folded=0)
//	     because there is no packed tail to split.
//
// That is a grammar-side defect in what `ParseSetCommand`/`SetPath` accept, it
// affects at least four unrelated stanzas, and it is tracked separately. Fixing
// it here would mean changing the flat-set grammar under cover of a
// compact-normalize change.
func TestPackedRunKeepsEveryStatement8904(t *testing.T) {
	tunnel := func(c *Config) (string, string) {
		for _, i := range c.Interfaces.Interfaces {
			for _, u := range i.Units {
				if u.Tunnel != nil {
					return u.Tunnel.Source, u.Tunnel.Destination
				}
			}
		}
		return "", ""
	}

	t.Run("tunnel/hierarchical", func(t *testing.T) {
		braced := compileText(t, `interfaces { gr-0/0/0 { unit 0 { tunnel { source 10.0.0.1; destination 10.0.0.2; } } } }`)
		packed := compileText(t, `interfaces { gr-0/0/0 { unit 0 { tunnel source 10.0.0.1 destination 10.0.0.2; } } }`)
		if braced == nil || packed == nil {
			t.Fatal("fixture did not compile (#8904)")
		}
		bs, bd := tunnel(braced)
		ps, pd := tunnel(packed)
		if bd == "" {
			t.Fatalf("the BRACED arm delivered no destination, so this cell cannot "+
				"tell a preserved run from a broken fixture: src=%q dst=%q (#8904)", bs, bd)
		}
		if ps != bs || pd != bd {
			t.Errorf("packed run truncated: braced src=%q dst=%q, packed src=%q dst=%q.\n"+
				"  The second statement of the run is discarded. A GRE tunnel that "+
				"keeps its source and loses its destination still creates the "+
				"interface and still renders both endpoints in `show "+
				"configuration`; it simply points nowhere, on a commit that "+
				"reported success (#8904).", bs, bd, ps, pd)
		}
	})

	t.Run("policer/if-exceeding", func(t *testing.T) {
		braced := compileText(t, `firewall { policer p1 { if-exceeding { bandwidth-limit 10m; burst-size-limit 100k; } then { discard; } } }`)
		packed := compileText(t, `firewall { policer p1 { if-exceeding bandwidth-limit 10m burst-size-limit 100k; then { discard; } } }`)
		if braced == nil || packed == nil {
			t.Fatal("fixture did not compile (#8904)")
		}
		if len(braced.Firewall.Policers) == 0 || len(packed.Firewall.Policers) == 0 {
			t.Fatal("no policer compiled (#8904)")
		}
		b, p := braced.Firewall.Policers["p1"], packed.Firewall.Policers["p1"]
		if b == nil || p == nil {
			t.Fatal("policer p1 missing from one arm (#8904)")
		}
		if b.BurstSizeLimit == 0 {
			t.Fatal("the BRACED arm produced burst=0, so this cell would pass " +
				"against a policer that lost it in both spellings (#8904)")
		}
		if p.BandwidthLimit != b.BandwidthLimit || p.BurstSizeLimit != b.BurstSizeLimit {
			t.Errorf("packed run truncated: braced bw=%d burst=%d, packed bw=%d "+
				"burst=%d. A rate limiter whose burst allowance silently becomes "+
				"zero polices differently from the one that was written (#8904).",
				b.BandwidthLimit, b.BurstSizeLimit, p.BandwidthLimit, p.BurstSizeLimit)
		}
	})

	// The single-statement form was never broken. Kept so a future change that
	// "fixes" the run by breaking the single statement cannot pass.
	t.Run("control/single-statement-unaffected", func(t *testing.T) {
		one := compileText(t, `interfaces { gr-0/0/0 { unit 0 { tunnel source 10.0.0.1; } } }`)
		if one == nil {
			t.Fatal("fixture did not compile (#8904)")
		}
		if s, _ := tunnel(one); s != "10.0.0.1" {
			t.Errorf("the single-statement packed form lost its source (%q) -- the "+
				"run fix must not cost the spelling that already worked (#8904)", s)
		}
	})
}
