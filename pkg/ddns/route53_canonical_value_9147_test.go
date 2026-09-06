package ddns

import (
	"reflect"
	"testing"
)

// The same address, in AWS's documented expanded form and in the form
// netip.Addr.String() produces.
const (
	expanded9147   = "2001:0db8:85a3:0000:0000:0000:0000:0001"
	compressed9147 = "2001:db8:85a3::1"
)

// #9147: the three RRset comparisons keyed on the RAW string, so an AAAA
// pre-seeded in AWS's own documented example format ("Supported DNS record
// types" gives the expanded spelling) could never byte-equal what xpf writes.
//
// mergeUpsertValues then puts BOTH spellings into one ChangeBatch, and its own
// comment says "Route 53 rejects a duplicate value in one RRset" — so that
// publish 400s on every tick and the record never converges.
func TestUpsertDedupsAcrossAddressSpellings9147(t *testing.T) {
	got := mergeUpsertValues([]string{expanded9147}, "", compressed9147)
	if len(got) != 1 {
		t.Errorf("merging the SAME address in two spellings produced %v — both go "+
			"into one ChangeBatch, Route 53 rejects the duplicate, and the record "+
			"never converges", got)
	}
	// The PRESERVED spelling must be the one already live, not ours. Rewriting a
	// value we do not own to suit our comparison edits someone else's record.
	if len(got) == 1 && got[0] != expanded9147 {
		t.Errorf("kept %q, want the live spelling %q — normalization is a COMPARISON "+
			"key, never an output rewrite", got[0], expanded9147)
	}

	// REFERENCE ARM: genuinely different addresses must still both survive.
	// Without it, "dedup" is satisfied by collapsing everything to one value.
	two := mergeUpsertValues([]string{"2001:db8::1"}, "", "2001:db8::2")
	if len(two) != 2 {
		t.Errorf("two DIFFERENT addresses collapsed to %v", two)
	}
	// And a non-IP value (TXT, CNAME target) must be untouched and still
	// deduped byte-exactly — canonicalization must not swallow what it cannot
	// parse.
	txt := mergeUpsertValues([]string{"\"hello world\"", "other"}, "", "\"hello world\"")
	if !reflect.DeepEqual(txt, []string{"\"hello world\"", "other"}) {
		t.Errorf("non-IP values were altered: %v", txt)
	}
}

// removeValue must recognise xpf's own value even if AWS echoed it in a
// different spelling — otherwise DeleteLease's `if !removed { return nil }`
// treats our own record as foreign and leaves it.
func TestRemoveMatchesAcrossSpellings9147(t *testing.T) {
	out, removed := removeValue([]string{expanded9147, "2001:db8::99"}, compressed9147)
	if !removed {
		t.Error("our own value, echoed in a different spelling, was not recognised " +
			"as ours; DeleteLease then treats it as foreign and leaves it")
	}
	if len(out) != 1 || out[0] != "2001:db8::99" {
		t.Errorf("out = %v, want the one foreign value preserved", out)
	}

	// NARROWNESS: a genuinely FOREIGN value must NOT be removed. This is the
	// sole-delete-authority boundary DeleteLease's own doc draws, and it is what
	// stops the fix from becoming a delete-anything primitive.
	out, removed = removeValue([]string{"2001:db8::99"}, compressed9147)
	if removed || len(out) != 1 {
		t.Errorf("a foreign value was removed (removed=%v out=%v)", removed, out)
	}
}

// The idempotency gate must not publish a no-op UPSERT whose only difference is
// an address spelling — that is a write on every tick, forever.
func TestSameValueSetIgnoresSpelling9147(t *testing.T) {
	if !sameValueSet([]string{expanded9147}, []string{compressed9147}) {
		t.Error("the same address in two spellings compared as different sets, so a " +
			"no-op UPSERT is published on every tick")
	}
	// REFERENCE ARM: different sets must still differ, or the gate never
	// publishes anything.
	if sameValueSet([]string{"2001:db8::1"}, []string{"2001:db8::2"}) {
		t.Error("two DIFFERENT addresses compared as the same set; the idempotency " +
			"gate would skip a real change")
	}
	if sameValueSet([]string{"a"}, []string{"a", "b"}) {
		t.Error("sets of different size compared equal")
	}
}

// The key must agree with wireRRClaim's normalization — the repo already owns
// this position on an adjacent path, and two normalizations that disagree are
// worse than one that is missing.
func TestCanonicalKeyAgreesWithWireRRClaim9147(t *testing.T) {
	for _, v := range []string{expanded9147, compressed9147, "192.0.2.1", "::ffff:192.0.2.1"} {
		want := wireRRClaim("host.example.", "AAAA", v, "auth").Rdata
		if got := canonicalRRValueKey9147(v); got != want {
			t.Errorf("canonicalRRValueKey9147(%q) = %q, wireRRClaim gives %q — two "+
				"normalizations of the same data that disagree", v, got, want)
		}
	}
	// Unparseable rdata is kept verbatim by BOTH.
	if got := canonicalRRValueKey9147("not-an-address"); got != "not-an-address" {
		t.Errorf("unparseable rdata was altered: %q", got)
	}
}
