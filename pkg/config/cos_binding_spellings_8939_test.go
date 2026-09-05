package config

import "testing"

// issue 8939: a class-of-service classifier or rewrite-rule BINDING loses every
// statement after the first, in two spellings and by two mechanisms.
//
//	braced        classifiers { dscp c1; ieee-802.1 c2; }   both bound
//	packed-hier   classifiers dscp c1 ieee-802.1 c2;        ieee-802.1 LOST
//	packed CLI    set … classifiers dscp c1 ieee-802.1 c2   ieee-802.1 LOST
//
// THE LOSS IS THE FALLBACK SHAPE, NOT THE MISSING SHAPE, which is what sets the
// severity. pkg/dataplane/userspace/interfaces.go records what an unpublished
// binding means: "the dataplane sees no classifier and every packet falls
// through to the DEFAULT QUEUE". Traffic is still classified -- into the wrong
// queue -- so nothing is unconfigured and the result is plausible.
//
// And the FIRST binding survives, so the interface visibly carries a working
// classifier while the second silently does nothing. PARTIAL APPLICATION READS
// AS SUCCESS: an operator checking that classification works will find that it
// does.
//
// ALL THREE SPELLINGS IN ONE TABLE, deliberately. The two mechanisms have
// separate fixes -- packedStatements for the packed tail, a chain flatten for
// the SetPath nesting -- and either alone leaves the config broken. A cell per
// mechanism could go green on half the defect.
func TestCoSBindingsAgreeAcrossSpellings8939(t *testing.T) {
	type got struct{ dscpCls, ieeeCls, dscpRw, ieeeRw string }
	read := func(t *testing.T, c *Config) got {
		t.Helper()
		for _, i := range c.ClassOfService.Interfaces {
			for _, u := range i.Units {
				return got{u.DSCPClassifier, u.IEEE8021Classifier, u.DSCPRewriteRule, u.IEEE8021RewriteRule}
			}
		}
		t.Fatal("no class-of-service unit compiled")
		return got{}
	}
	compileSet := func(t *testing.T, cmd string) *Config {
		t.Helper()
		tree := &ConfigTree{}
		p, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(p); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
		cfg, err := CompileConfigLenient(tree)
		if err != nil || cfg == nil {
			t.Fatalf("compile: %v", err)
		}
		return cfg
	}

	for _, tc := range []struct {
		name, braced, packed, set string
		want                      got
	}{
		{
			name:   "classifiers",
			braced: `class-of-service { interfaces ge-0/0/0 { unit 0 { classifiers { dscp c1; ieee-802.1 c2; } } } }`,
			packed: `class-of-service { interfaces ge-0/0/0 { unit 0 { classifiers dscp c1 ieee-802.1 c2; } } }`,
			set:    "set class-of-service interfaces ge-0/0/0 unit 0 classifiers dscp c1 ieee-802.1 c2",
			want:   got{"c1", "c2", "", ""},
		},
		{
			name:   "rewrite-rules",
			braced: `class-of-service { interfaces ge-0/0/0 { unit 0 { rewrite-rules { dscp r1; ieee-802.1 r2; } } } }`,
			packed: `class-of-service { interfaces ge-0/0/0 { unit 0 { rewrite-rules dscp r1 ieee-802.1 r2; } } }`,
			set:    "set class-of-service interfaces ge-0/0/0 unit 0 rewrite-rules dscp r1 ieee-802.1 r2",
			want:   got{"", "", "r1", "r2"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := read(t, compileText(t, tc.braced))
			// POSITIVE CONTROL on the reference arm.
			if b != tc.want {
				t.Fatalf("the BRACED arm delivered %+v, want %+v -- the reference "+
					"arm is wrong, so this cell cannot tell a fixed spelling from a "+
					"broken fixture (#8939)", b, tc.want)
			}
			for _, arm := range []struct {
				name, mechanism string
				got             got
			}{
				{"packed-hier", "packed tail on one node's Keys, split by packedStatements",
					read(t, compileText(t, tc.packed))},
				{"packed CLI", "SetPath nests the bindings; the reader flattens the chain",
					read(t, compileSet(t, tc.set))},
			} {
				if arm.got != b {
					t.Errorf("%s spelling delivers %+v, braced delivers %+v.\n"+
						"  mechanism: %s\n"+
						"  A dropped binding is not an unclassified packet -- the "+
						"dataplane falls through to the DEFAULT QUEUE, so traffic is "+
						"classified into the wrong one while the surviving first "+
						"binding makes the interface look correctly configured (#8939).",
						arm.name, arm.got, b, arm.mechanism)
				}
			}
		})
	}
}
