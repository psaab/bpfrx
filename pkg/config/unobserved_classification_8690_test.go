package config

import "testing"

// #8690 unruled-fixture sweep, third increment: the LARGEST bucket, measured
// rather than assumed.
//
// "leaf value not observable in the typed config" holds 236 sites, and the
// census's own note described every one of them as "a site whose synthesized
// fixture was too thin to observe the value (as #6821 was before its
// required-sibling context line)".
//
// Measured, that describes FIVE of them:
//
//	nothing registered (fixture too thin)          5
//	stanza registered, leaf contributed nothing  219
//	registered, but the value did not vary        12
//
// The 219 are not a fixture backlog. Their stanza compiles, their empty
// skeleton compiles, and the two are EQUAL — so the compiler reads the stanza
// and does not read the leaf, under either spelling. That is why they cannot be
// compact/block divergences, and it is a question about the COMPILER (a leaf
// that commits and does nothing, a leaf consumed elsewhere, or one needing an
// in-stanza sibling) rather than about this census.
//
// Recording the split is the whole point: 236 read as one backlog, and the
// three numbers are three different pieces of work.

func TestTheUnobservedBucketIsClassified_8690(t *testing.T) {
	res := runCompactBlockCensus(t)
	total := res.skipped["leaf value not observable in the typed config"]
	if total == 0 {
		t.Fatal("the bucket is empty, so this cell measures nothing — either the " +
			"census stopped populating it or the skip key was renamed")
	}
	var summed int
	for _, k := range []string{
		unobservedNothingRegistered, unobservedLeafIgnored, unobservedOther,
	} {
		summed += res.unobservedClass[k]
	}
	if summed != total {
		t.Errorf("the classes sum to %d but the bucket holds %d. Every skipped site "+
			"must land in exactly one class, or the split is a sample rather than a "+
			"partition and the numbers cannot be reasoned from (#8690)", summed, total)
	}

	// The load-bearing claim, in the direction that matters: the note's
	// original reading — "the fixture was too thin" — is the MINORITY case.
	// Pinning the shape rather than the exact number, because the other lanes'
	// normalization moves these counts every day.
	thin := res.unobservedClass[unobservedNothingRegistered]
	ignored := res.unobservedClass[unobservedLeafIgnored]
	if thin >= ignored {
		t.Errorf("nothing-registered=%d is no longer the minority against "+
			"leaf-ignored=%d. The census note is written the other way round; if "+
			"the populations really have inverted, the note has to move with them "+
			"(#8690)", thin, ignored)
	}
	if ignored == 0 {
		t.Error("no site is classified 'stanza registered, leaf contributed " +
			"nothing', which is the class the classification exists to name")
	}
	// Each class must be REACHABLE. An arm that never fires makes the split
	// three names over two populations, and the sum check above cannot see it —
	// found by mutation: swapping the two arms moves every nothing-registered
	// site into leaf-ignored (their skeleton also compiles to empty, so the
	// leaf-ignored test is true for them too) and every other assertion here
	// still passed.
	if thin == 0 {
		t.Error("no site is classified 'nothing registered', so that arm is " +
			"unreachable — most likely it is tested AFTER the leaf-ignored arm, " +
			"which is true for those sites as well (#8690)")
	}
	if res.unobservedClass[unobservedOther] == 0 {
		t.Log("note: the residual class is empty; that is legitimate, but if it " +
			"stays empty the two-way split is the honest description")
	}
}

// The classifier must be able to tell the two apart at all — a discriminator
// that answers the same way for both is worse than none, because it launders a
// distinction into a number.
func TestTheClassifierDistinguishesRegisteredFromAbsent_8690(t *testing.T) {
	empty := compileText(t, "")
	if empty == nil {
		t.Fatal("an empty config does not compile; the 'nothing registered' arm " +
			"compares against it and would never fire")
	}
	// A stanza that DOES register: its compiled config differs from empty.
	registered := compileText(t, "system { host-name xpfhost; }")
	if registered == nil {
		t.Fatal("the control fixture does not compile")
	}
	if cfgEqual(registered, empty) {
		t.Error("a config that plainly sets a value compares EQUAL to the empty " +
			"config, so the 'nothing registered' arm would classify every site that " +
			"way and the split would be meaningless")
	}
	// And a stanza that registers but carries nothing: equal to its skeleton.
	skel := compileText(t, "system { }")
	if skel == nil {
		t.Fatal("the skeleton fixture does not compile")
	}
	if !cfgEqual(skel, empty) {
		// Not a failure — some stanzas register from their skeleton alone. Say
		// so, because it is exactly the case the middle class describes.
		t.Logf("note: `system { }` already differs from an empty config, which is " +
			"the shape the leaf-ignored class is about")
	}
}
