package config

import (
	"strings"
	"testing"
)

// #7337: the seven class-of-service INTERFACE references were warn-only at
// commit and then failed OPEN in the dataplane — forwarding_build/cos.rs
// resolves each name with a bare `.get(...)` yielding None, so the interface
// materializes no scheduler queues or a classifier arm contributes nothing,
// while the committed config still says the interface is shaped and
// classified.
//
// These cells pin BOTH halves of the #1960 doctrine, which is the part that
// cannot be got wrong: strict commit REJECTS, tolerant load WARNS. A gate that
// rejects on both paths bricks an upgrading node carrying a config an older
// binary accepted; a gate that warns on both paths is not a gate.

func cosRefTree7337(t *testing.T, lines ...string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, ln := range lines {
		path, err := ParseSetCommand(ln)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", ln, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", ln, err)
		}
	}
	return tree
}

// cosRef7337Cases is the reference population. Each entry binds ONE dangling
// reference; the expected fragment names the leaf, so a cell cannot pass by
// matching a sibling's message — the seven messages are otherwise near-
// identical, which is exactly the shape where a copy-paste error survives.
var cosRef7337Cases = []struct {
	name string
	set  string
	want string
}{
	{"scheduler-map", "set class-of-service interfaces ge-0/0/1 unit 0 scheduler-map NOPE", `undefined scheduler-map "NOPE"`},
	{"output-traffic-control-profile", "set class-of-service interfaces ge-0/0/1 unit 0 output-traffic-control-profile NOPE", `undefined output-traffic-control-profile "NOPE"`},
	{"dscp classifier", "set class-of-service interfaces ge-0/0/1 unit 0 classifiers dscp NOPE", `undefined dscp classifier "NOPE"`},
	{"ieee-802.1 classifier", "set class-of-service interfaces ge-0/0/1 unit 0 classifiers ieee-802.1 NOPE", `undefined ieee-802.1 classifier "NOPE"`},
	{"inet-precedence classifier", "set class-of-service interfaces ge-0/0/1 unit 0 classifiers inet-precedence NOPE", `undefined inet-precedence classifier "NOPE"`},
	{"dscp rewrite-rule", "set class-of-service interfaces ge-0/0/1 unit 0 rewrite-rules dscp NOPE", `undefined dscp rewrite-rule "NOPE"`},
	{"ieee-802.1 rewrite-rule", "set class-of-service interfaces ge-0/0/1 unit 0 rewrite-rules ieee-802.1 NOPE", `undefined ieee-802.1 rewrite-rule "NOPE"`},
}

// Strict commit must REJECT every dangling reference, naming the leaf.
func TestCoSInterfaceRefsRejectedAtStrictCommit7337(t *testing.T) {
	for _, tc := range cosRef7337Cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := cosRefTree7337(t,
				"set class-of-service forwarding-classes queue 0 BE",
				"set interfaces ge-0/0/1 unit 0 family inet address 10.0.0.1/24",
				tc.set,
			)
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("a dangling %s reference COMMITTED. The dataplane resolves the name "+
					"to None and the interface silently degrades to best-effort while the "+
					"committed config still claims it is shaped/classified.", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error does not name the offending leaf.\n got: %v\nwant substring: %s\n"+
					"The seven messages are near-identical, so a wrong one here means the gate "+
					"checked a DIFFERENT reference than the one that dangles.", err, tc.want)
			}
		})
	}
}

// The #1960 no-brick half: the SAME configs must LOAD on the tolerant path,
// producing a warning rather than an error. Without this, an upgrading node
// carrying a config its previous binary accepted fails to boot.
func TestCoSInterfaceRefsOnlyWarnOnTolerantPath7337(t *testing.T) {
	for _, tc := range cosRef7337Cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := cosRefTree7337(t,
				"set class-of-service forwarding-classes queue 0 BE",
				"set interfaces ge-0/0/1 unit 0 family inet address 10.0.0.1/24",
				tc.set,
			)
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("a config an older binary ACCEPTED failed to load: %v\n"+
					"This is the #1960 brick: the gate must reject a new edit at commit and "+
					"still boot an already-persisted or peer-synced config.", err)
			}
			joined := strings.Join(cfg.Warnings, "\n")
			if !strings.Contains(joined, "downgraded to warning on tolerant path") {
				t.Errorf("the tolerant path loaded the dangling %s reference SILENTLY; "+
					"warnings=%v\nLoading it is correct, but doing so without saying anything "+
					"leaves the operator with no evidence their QoS is inert.", tc.name, cfg.Warnings)
			}
		})
	}
}

// Over-reach control. Without this the rejection cells are satisfied by a gate
// that refuses every CoS interface binding, dangling or not.
func TestCoSInterfaceRefsThatResolveStillCommit7337(t *testing.T) {
	tree := cosRefTree7337(t,
		"set class-of-service forwarding-classes queue 0 BE",
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.0.1/24",
		"set class-of-service classifiers dscp real-cl forwarding-class BE loss-priority low code-points 000000",
		"set class-of-service rewrite-rules dscp real-rw forwarding-class BE loss-priority low code-point 000000",
		"set class-of-service schedulers s1 transmit-rate percent 50",
		"set class-of-service scheduler-maps real-sm forwarding-class BE scheduler s1",
		"set class-of-service interfaces ge-0/0/1 unit 0 scheduler-map real-sm",
		"set class-of-service interfaces ge-0/0/1 unit 0 classifiers dscp real-cl",
		"set class-of-service interfaces ge-0/0/1 unit 0 rewrite-rules dscp real-rw",
	)
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("a config whose CoS interface references ALL resolve was rejected: %v\n"+
			"The gate must reject dangling names only; rejecting resolvable ones breaks "+
			"every correctly-configured CoS deployment.", err)
	}
}

// An interface-level binding (no `unit`) with NO configured units is folded
// nowhere by applyCoSInterfaceLevelBindings, so it is only reachable if the
// gate checks Level explicitly. Without this cell, dropping the Level check
// reds nothing.
func TestCoSInterfaceLevelRefIsCheckedToo7337(t *testing.T) {
	tree := cosRefTree7337(t,
		"set class-of-service forwarding-classes queue 0 BE",
		"set class-of-service interfaces ge-0/0/9 scheduler-map NOPE",
	)
	err := errFromCompile7337(t, tree)
	if err == nil {
		t.Fatal("an interface-LEVEL dangling scheduler-map reference committed. " +
			"With no configured units there is nothing for the level binding to fold " +
			"into, so it is invisible to a gate that only walks Units.")
	}
	if !strings.Contains(err.Error(), `undefined scheduler-map "NOPE"`) {
		t.Errorf("got %v, want the undefined scheduler-map message", err)
	}
}

func errFromCompile7337(t *testing.T, tree *ConfigTree) error {
	t.Helper()
	_, err := CompileConfig(tree)
	return err
}
