package config

import "testing"

// #9151: `protocols rip group` was declared `children: nil` while
// compiler_protocols.go's `case "group"` iterates child.Children and reads
// `neighbor` (-> RIP.Interfaces) and `export` (-> Redistribute).
//
// This cell pins the AGREEMENT between the two, which is what the declaration
// buys. IT DOES NOT CLOSE #9151, and saying so here is the point: a landed
// partial fix removes the reason anyone looks again, so the gap is asserted
// rather than left for someone to rediscover.
func TestRipGroupSchemaMatchesCompiler9151(t *testing.T) {
	rip := setSchema.children["protocols"].children["rip"]
	if rip == nil {
		t.Fatal("protocols rip missing from setSchema")
	}
	grp := rip.children["group"]
	if grp == nil {
		t.Fatal("protocols rip group missing from setSchema")
	}
	// The compiler reads exactly these two under a group. If it grows a third
	// `case`, this cell must grow with it or the schema falls behind again --
	// which is the #9151 defect returning by the same route.
	for _, want := range []string{"neighbor", "export"} {
		c := grp.children[want]
		if c == nil {
			t.Errorf("#9151: compiler_protocols.go's `case \"group\"` reads %q, and the "+
				"schema does not declare it. A schema that declares less than the "+
				"compiler reads leaves the closed-world walk nothing to descend into, "+
				"which is what made the packed spelling admissible.", want)
			continue
		}
		if !c.multi {
			t.Errorf("#9151: %q is read through firewallMatchValues (Keys[1:] AND child "+
				"nodes, #3904), so it must be declared multi or a bracket list is "+
				"truncated to its first entry", want)
		}
	}
	if grp.children == nil {
		t.Error("#9151: group declares no children at all -- the original defect")
	}
}

// TestRipGroupPackedRunStillAdmitted9151 records what the declaration does NOT
// fix, as a live assertion rather than a comment.
//
// `set protocols rip group g1 authentication-key secret1` still commits and
// loses both the group content and the sibling key. Declaring the children
// makes the schema HONEST about what the compiler reads; it does not refuse an
// UNDECLARED trailing statement, because `protocols rip` is open-world. By the
// #9148 conjunction a flat run is accepted iff the container is open-world AND
// the starting leaf is untyped, and this declaration changes neither.
//
// When someone closes #9151 -- by flipping the container closed-world, or by
// teaching the compiler to walk the run -- THIS CELL WILL FAIL, and that
// failure is the signal to delete it rather than a regression.
func TestRipGroupPackedRunStillAdmitted9151(t *testing.T) {
	tr := &ConfigTree{}
	toks, err := ParseSetCommand("set protocols rip group g1 authentication-key secret1")
	if err != nil {
		t.Fatal(err)
	}
	if err := tr.SetPath(toks); err != nil {
		t.Fatal(err)
	}
	if err := SchemaValidateWithDefinitions(tr, tr, nil); err != nil {
		t.Skipf("#9151 IS NOW REFUSED AT THE SCHEMA GATE (%v).\n"+
			"That is the fix landing. Delete this cell and #9151 with it -- it exists "+
			"only to keep the open gap visible while the declaration is in place.", err)
	}
	cfg, err := CompileConfig(tr)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if r := cfg.Protocols.RIP; r != nil && (len(r.Interfaces) > 0 || r.AuthKey.Reveal() != "") {
		t.Errorf("#9151 appears FIXED at the compiler (ifaces=%v authKey=%q). "+
			"Delete this cell and close the issue.", r.Interfaces, r.AuthKey.Reveal())
	}
}
