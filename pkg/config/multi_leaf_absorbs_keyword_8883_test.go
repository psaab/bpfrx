package config

import (
	"strings"
	"testing"
)

// #8883: a packed run of a `multi` leaf INJECTED the repeated keyword as a
// value. `system { name-server 1.1.1.1 name-server 8.8.8.8; }` compiled to
// [1.1.1.1 name-server 8.8.8.8] — a DNS resolver whose address is the literal
// string "name-server" — silent at strict commit and on the tolerant ingress.
//
// A `multi` leaf absorbs trailing non-sibling tokens (#2419). Where the
// container does not split the run, the first leaf swallows the NEXT
// statement's keyword as one of its values.
//
// THIS IS THE INJECTION HALF OF A TWO-MODE CLASS; #8880 is the truncation half.
//
//	multi leaf    -> packed has MORE members, one named after the keyword
//	args >= 2 key -> packed has FEWER members
//
// A cell comparing LENGTHS scores injection as increased coverage, which is why
// every assertion below is on CONTENTS.
//
// INJECTION IS WORSE THAN TRUNCATION HERE. A dropped entry breaks whatever
// referenced it and somebody notices; a garbage entry sits in the resolver list
// and is USED, failing lookups intermittently while `show configuration` renders
// what the operator wrote.
//
// THE REMEDY IS PER-READER, AND THAT IS THE PART TO CARRY. `packedStatements`
// on the container is measured insufficient for a multi leaf — the leaf absorbs
// the run before any split. The fix is in the VALUE READER, and there is more
// than one: fixing `firewallMatchValues` corrects `name-server`, `domain-search`,
// `ssh key-exchange` and `bgp export`, and does NOT correct `ntp server` or
// `nat source pool address`, which have their own readers and still inject. So
// a green cell here does not mean the class is fixed, and this cell does not
// claim it.
func TestMultiLeafDoesNotAbsorbItsOwnKeyword8883(t *testing.T) {
	const want = "1.1.1.1 8.8.8.8"

	read := func(t *testing.T, txt string) []string {
		t.Helper()
		tree, perrs := NewParser(txt).Parse()
		if len(perrs) > 0 {
			t.Fatalf("fixture must parse (%q): %v", txt, perrs[0])
		}
		cfg, err := CompileConfigLenient(tree)
		if cfg == nil {
			t.Fatalf("fixture must compile (%q): %v", txt, err)
		}
		return cfg.System.NameServers
	}

	// BOTH braced spellings are controls and both must keep working. They are
	// also the LIVENESS check: if either stopped delivering two servers, the
	// packed assertion below would be comparing against nothing.
	for _, c := range []struct{ name, txt string }{
		{"braced block", `system { name-server { 1.1.1.1; 8.8.8.8; } }`},
		{"braced flat", `system { name-server 1.1.1.1; name-server 8.8.8.8; }`},
	} {
		got := read(t, c.txt)
		if strings.Join(got, " ") != want {
			t.Fatalf("%s control delivered %v, want [%s] — the packed assertion "+
				"below would be measuring a broken fixture rather than the defect",
				c.name, got, want)
		}
	}

	got := read(t, `system { name-server 1.1.1.1 name-server 8.8.8.8; }`)

	// THE SPECIFIC FAILURE, asserted by name. A member equal to the leaf's own
	// keyword can only have come from the packed run: no DNS resolver address is
	// the string "name-server". Asserting the specific token rather than a
	// mismatch means that if this stops failing for an unrelated reason, the
	// weaker assertion does not quietly pass.
	for _, m := range got {
		if m == "name-server" {
			t.Errorf("the packed spelling injected the leaf's own keyword as a "+
				"resolver address: %v. The box would query a DNS server named "+
				"\"name-server\" — every lookup reaching it fails, intermittently, "+
				"while `show configuration` renders what the operator wrote (#8883).",
				got)
		}
	}

	// And the whole list, since injection ADDS members: a length check would
	// score three members as more coverage than two.
	if strings.Join(got, " ") != want {
		t.Errorf("packed spelling produced %v, want [%s] — identical to both "+
			"braced spellings. The packed arm is the only one that differs, so "+
			"the spelling and not the values is what changed the result (#8883).",
			got, want)
	}
}

// The tolerant ingress must accept everything it accepts today: this fix
// tightens nothing, it only stops a value being invented.
func TestPackedNameServerStillLoads8883(t *testing.T) {
	for _, txt := range []string{
		`system { name-server 1.1.1.1 name-server 8.8.8.8; }`,
		`system { name-server 1.1.1.1; }`,
		`system { name-server { 1.1.1.1; 8.8.8.8; } }`,
	} {
		tree, perrs := NewParser(txt).Parse()
		if len(perrs) > 0 {
			t.Fatalf("fixture must parse (%q): %v", txt, perrs[0])
		}
		cfg, err := CompileConfigLenient(tree)
		if err != nil || cfg == nil {
			t.Errorf("the tolerant ingress must still accept %q: %v — a config "+
				"already on disk must keep loading (#1960 no-brick)", txt, err)
		}
	}
}
