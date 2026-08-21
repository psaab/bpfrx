package config

import (
	"strings"
	"testing"
)

// cosINetPrecedenceBase is the shared prelude: two forwarding classes on
// distinct queues plus an inet-precedence classifier that steers IP precedence
// 5 into `voice`.
func cosINetPrecedenceBase() []string {
	return []string{
		"set class-of-service forwarding-classes queue 0 best-effort",
		"set class-of-service forwarding-classes queue 5 voice",
		"set class-of-service classifiers inet-precedence prec-cl forwarding-class voice loss-priority low code-points 5",
	}
}

// TestCoSINetPrecedenceClassifierCompilesEntriesAndUnitBinding pins the config
// half of #6847: the classifier's code-point ENTRIES compile (not just its
// name, which is all #4316 recorded) and the unit-level binding site exists.
//
// Before #6847 the second assertion could not even be reached — the unit
// `classifiers` schema node had no `inet-precedence` child, so the bind line
// was rejected by the schema and an imported vSRX config failed at that line.
func TestCoSINetPrecedenceClassifierCompilesEntriesAndUnitBinding(t *testing.T) {
	tree := buildTree(t, append(cosINetPrecedenceBase(),
		"set class-of-service interfaces ge-0/0/2 unit 0 classifiers inet-precedence prec-cl",
	))
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile rejected a valid inet-precedence classifier binding: %v", err)
	}
	classifier := cfg.ClassOfService.INetPrecedenceClassifierDefs["prec-cl"]
	if classifier == nil {
		t.Fatalf("inet-precedence classifier prec-cl not compiled; defs=%v",
			cfg.ClassOfService.INetPrecedenceClassifierDefs)
	}
	if len(classifier.Entries) != 1 {
		t.Fatalf("want 1 compiled entry, got %d (%#v)", len(classifier.Entries), classifier.Entries)
	}
	entry := classifier.Entries[0]
	if entry.ForwardingClass != "voice" {
		t.Fatalf("entry forwarding-class = %q, want voice", entry.ForwardingClass)
	}
	if len(entry.Precedences) != 1 || entry.Precedences[0] != 5 {
		t.Fatalf("entry precedences = %v, want [5]", entry.Precedences)
	}
	// Step through the lookup rather than chaining it: a unit whose only
	// binding is inet-precedence used to be dropped by
	// coSInterfaceUnitHasBinding, taking the whole CoS interface with it, and a
	// chained index turns that into a nil-pointer panic that names nothing.
	cosIface := cfg.ClassOfService.Interfaces["ge-0/0/2"]
	if cosIface == nil {
		t.Fatalf("no CoS interface compiled for ge-0/0/2; a unit binding ONLY an inet-precedence classifier was dropped. interfaces=%v",
			cfg.ClassOfService.Interfaces)
	}
	unit := cosIface.Units[0]
	if unit == nil {
		t.Fatalf("no CoS unit 0 compiled for ge-0/0/2; units=%v", cosIface.Units)
	}
	if unit.INetPrecedenceClassifier != "prec-cl" {
		t.Fatalf("unit inet-precedence binding = %q, want prec-cl", unit.INetPrecedenceClassifier)
	}
}

// TestCoSUnitDSCPAndINetPrecedenceConflictFailsCommit is the fail-on-revert
// guard for the #6847 mutual exclusion: a unit that binds BOTH a `dscp` and an
// `inet-precedence` classifier is rejected at commit.
//
// The two read the SAME DS field — IP precedence is its top 3 bits — so this is
// a contradiction with no defined answer, and the dataplane's resolution chain
// consults DSCP first, which would leave the inet-precedence binding silently
// dead. A silently-dead classifier is the quiet-wrong-QoS failure the gate
// exists to stop, so the operator is made to pick one.
func TestCoSUnitDSCPAndINetPrecedenceConflictFailsCommit(t *testing.T) {
	tree := buildTree(t, append(cosINetPrecedenceBase(),
		"set class-of-service classifiers dscp dscp-cl forwarding-class voice loss-priority low code-points 46",
		"set class-of-service interfaces ge-0/0/2 unit 0 classifiers dscp dscp-cl",
		"set class-of-service interfaces ge-0/0/2 unit 0 classifiers inet-precedence prec-cl",
	))
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("expected commit to reject a unit binding both dscp and inet-precedence classifiers")
	}
	// The message must name the interface, the unit, and BOTH classifiers —
	// an operator who has to pick one needs to know which two are in conflict.
	for _, want := range []string{"ge-0/0/2", "unit 0", "dscp-cl", "prec-cl", "bind at most one"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not name %q", err.Error(), want)
		}
	}
}

// TestCoSUnitClassifierConflictLenientDowngradesToWarning asserts the tolerant
// Load / SyncApply path downgrades that rejection to a warning (#1960
// no-brick). This half is what stops the belt bricking a box: the strict gate
// alone would turn a config already on disk — or one arriving over config-sync
// from a peer — into a boot failure with no dataplane at all.
func TestCoSUnitClassifierConflictLenientDowngradesToWarning(t *testing.T) {
	tree := buildTree(t, append(cosINetPrecedenceBase(),
		"set class-of-service classifiers dscp dscp-cl forwarding-class voice loss-priority low code-points 46",
		"set class-of-service interfaces ge-0/0/2 unit 0 classifiers dscp dscp-cl",
		"set class-of-service interfaces ge-0/0/2 unit 0 classifiers inet-precedence prec-cl",
	))
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile must not fail on a dscp+inet-precedence unit conflict: %v", err)
	}
	if !hasWarningContaining(cfg.Warnings, "class-of-service unit classifiers (downgraded to warning on tolerant path)") {
		t.Fatalf("expected a downgraded unit-classifier-conflict warning, got: %v", cfg.Warnings)
	}
	// Both bindings survive the downgrade so the dataplane still receives a
	// well-formed snapshot; DSCP wins at classification time because the BA
	// chain consults it first (tx/cos_classify.rs).
	unit := cfg.ClassOfService.Interfaces["ge-0/0/2"].Units[0]
	if unit.DSCPClassifier != "dscp-cl" || unit.INetPrecedenceClassifier != "prec-cl" {
		t.Fatalf("lenient path must preserve both bindings, got dscp=%q inet-precedence=%q",
			unit.DSCPClassifier, unit.INetPrecedenceClassifier)
	}
}

// TestCoSUnitINetPrecedenceAloneCommitsClean is the anti-over-reject control
// for the conflict gate: binding inet-precedence WITHOUT dscp must commit
// cleanly. Without it a gate that rejected every inet-precedence binding would
// pass the rejection test above.
func TestCoSUnitINetPrecedenceAloneCommitsClean(t *testing.T) {
	tree := buildTree(t, append(cosINetPrecedenceBase(),
		"set class-of-service interfaces ge-0/0/2 unit 0 classifiers inet-precedence prec-cl",
	))
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("strict commit rejected a unit binding only inet-precedence: %v", err)
	}
}

// TestCoSUnitDSCPAndINetPrecedenceOnDifferentUnitsCommitsClean is the scope
// control: the exclusion is PER UNIT, not per interface or per config. Two
// units of the same interface each binding one of the two classifiers is a
// legitimate config (they classify disjoint traffic) and must not be rejected.
func TestCoSUnitDSCPAndINetPrecedenceOnDifferentUnitsCommitsClean(t *testing.T) {
	tree := buildTree(t, append(cosINetPrecedenceBase(),
		"set class-of-service classifiers dscp dscp-cl forwarding-class voice loss-priority low code-points 46",
		"set class-of-service interfaces ge-0/0/2 unit 0 classifiers dscp dscp-cl",
		"set class-of-service interfaces ge-0/0/2 unit 1 classifiers inet-precedence prec-cl",
	))
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("strict commit rejected dscp and inet-precedence on DIFFERENT units: %v", err)
	}
}

// TestCoSINetPrecedenceCodePointOutOfRangeFailsCommit pins the 0..7 domain.
// IP precedence is a 3-bit field; a larger value has no valid table slot, and
// masking it (`& 0x7`) would install the classifier for a DIFFERENT traffic
// class (9 -> 1). Reject at commit; the Rust builder carries the matching
// fail-closed backstop for snapshot drift.
func TestCoSINetPrecedenceCodePointOutOfRangeFailsCommit(t *testing.T) {
	tree := buildTree(t, []string{
		"set class-of-service forwarding-classes queue 5 voice",
		"set class-of-service classifiers inet-precedence prec-cl forwarding-class voice loss-priority low code-points 9",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("expected commit to reject inet-precedence code-point 9 (outside 0..7)")
	}
	if !strings.Contains(err.Error(), "0..7") {
		t.Fatalf("error %q does not state the 0..7 domain", err.Error())
	}
}

// TestCoSINetPrecedenceLossPriorityTypoFailsCommit pins the loss-priority
// typo gate on the inet-precedence classifier.
//
// #6847 made the classifier's loss-priority LIVE: the entry's string crosses
// the wire and the helper maps it with
// `cos_loss_priority_index(&entry.loss_priority).unwrap_or(0)`
// (userspace-dp/src/afxdp/forwarding_build/cos.rs), so an unrecognized value
// silently becomes LOW and the egress rewrite picks the LOW row for that
// forwarding class. Every sibling classifier — dscp, ieee-802.1, and both
// rewrite-rule directions — rejects that typo at commit
// (validateClassOfServiceLossPriorityStrict); without this arm the newly
// enforced classifier was the one hole in that family, and the hole produced
// exactly the accepted-but-silently-substituted drop precedence #6847 wired
// the loss-priority arm to remove.
//
// The typo is asserted with the SAME token the dscp control uses below, so a
// future change that loosens the shared checkEntry reds both.
func TestCoSINetPrecedenceLossPriorityTypoFailsCommit(t *testing.T) {
	tree := buildTree(t, []string{
		"set class-of-service forwarding-classes queue 5 voice",
		"set class-of-service classifiers inet-precedence prec-cl forwarding-class voice loss-priority hgih code-points 5",
		"set class-of-service interfaces ge-0/0/2 unit 0 classifiers inet-precedence prec-cl",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("expected commit to reject inet-precedence loss-priority \"hgih\"")
	}
	if !strings.Contains(err.Error(), "unrecognized loss-priority") ||
		!strings.Contains(err.Error(), "classifiers inet-precedence") {
		t.Fatalf("error %q does not name the inet-precedence classifier loss-priority", err.Error())
	}
}

// TestCoSINetPrecedenceLossPriorityValidValuesCommitClean is the
// anti-over-reject control: all four Junos drop precedences must still commit.
// Without it a gate that rejected EVERY inet-precedence loss-priority would
// pass the typo test above.
func TestCoSINetPrecedenceLossPriorityValidValuesCommitClean(t *testing.T) {
	for _, lp := range []string{"low", "medium-low", "medium-high", "high"} {
		tree := buildTree(t, []string{
			"set class-of-service forwarding-classes queue 5 voice",
			"set class-of-service classifiers inet-precedence prec-cl forwarding-class voice loss-priority " + lp + " code-points 5",
			"set class-of-service interfaces ge-0/0/2 unit 0 classifiers inet-precedence prec-cl",
		})
		if _, err := CompileConfig(tree); err != nil {
			t.Fatalf("strict commit rejected valid inet-precedence loss-priority %q: %v", lp, err)
		}
	}
}

// TestCoSINetPrecedenceLossPriorityTypoLenientDowngrades keeps the #1960
// no-brick posture: a config already persisted (or peer-synced) with the typo
// must still BOOT, with the substitution surfaced as a warning rather than a
// refusal to load. It shares the tolerant-path call site with the dscp /
// ieee-802.1 arms (opts.lenientCoSLossPriority).
func TestCoSINetPrecedenceLossPriorityTypoLenientDowngrades(t *testing.T) {
	tree := buildTree(t, []string{
		"set class-of-service forwarding-classes queue 5 voice",
		"set class-of-service classifiers inet-precedence prec-cl forwarding-class voice loss-priority hgih code-points 5",
		"set class-of-service interfaces ge-0/0/2 unit 0 classifiers inet-precedence prec-cl",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile must not fail on an inet-precedence loss-priority typo: %v", err)
	}
	if !hasWarningContaining(cfg.Warnings, "class-of-service loss-priority (downgraded to warning on tolerant path)") {
		t.Fatalf("expected a downgraded loss-priority warning, got: %v", cfg.Warnings)
	}
}
