package userspace

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// cosINetPrecedenceConfig builds a compiled config with a forwarding class, an
// inet-precedence classifier over it, and (optionally) the unit binding.
func cosINetPrecedenceConfig(bindUnit bool) *config.Config {
	cfg := &config.Config{
		ClassOfService: &config.ClassOfServiceConfig{
			ForwardingClasses: map[string]*config.CoSForwardingClass{
				"voice": {Name: "voice", Queue: 5},
			},
			INetPrecedenceClassifierDefs: map[string]*config.CoSINetPrecedenceClassifier{
				"prec-cl": {
					Name: "prec-cl",
					Entries: []*config.CoSINetPrecedenceClassifierEntry{
						{ForwardingClass: "voice", LossPriority: "high", Precedences: []uint8{5, 6}},
					},
				},
			},
			Interfaces: map[string]*config.CoSInterface{},
		},
	}
	if bindUnit {
		cfg.ClassOfService.Interfaces["ge-0-0-2"] = &config.CoSInterface{
			Name: "ge-0-0-2",
			Units: map[int]*config.CoSInterfaceUnit{
				0: {Unit: 0, INetPrecedenceClassifier: "prec-cl"},
			},
		}
	}
	return cfg
}

// TestBuildClassOfServiceSnapshotPublishesINetPrecedenceClassifier is the
// wire-crossing guard for #6847. The classifier compiled into
// INetPrecedenceClassifierDefs before this change and STOPPED there — nothing
// reached the dataplane, so the classify arm had no table to consult no matter
// how the operator configured it. Assert the entries (not just the name) cross,
// including loss-priority and every code-point.
func TestBuildClassOfServiceSnapshotPublishesINetPrecedenceClassifier(t *testing.T) {
	snap := buildClassOfServiceSnapshot(cosINetPrecedenceConfig(true))
	if snap == nil {
		t.Fatal("expected a CoS snapshot")
	}
	if len(snap.INetPrecedenceClassifiers) != 1 {
		t.Fatalf("want 1 published inet-precedence classifier, got %d (%+v)",
			len(snap.INetPrecedenceClassifiers), snap.INetPrecedenceClassifiers)
	}
	classifier := snap.INetPrecedenceClassifiers[0]
	if classifier.Name != "prec-cl" {
		t.Fatalf("classifier name = %q, want prec-cl", classifier.Name)
	}
	if len(classifier.Entries) != 1 {
		t.Fatalf("want 1 published entry, got %d (%+v)", len(classifier.Entries), classifier.Entries)
	}
	entry := classifier.Entries[0]
	if entry.ForwardingClass != "voice" {
		t.Fatalf("entry forwarding-class = %q, want voice", entry.ForwardingClass)
	}
	if entry.LossPriority != "high" {
		t.Fatalf("entry loss-priority = %q, want high (it selects the egress rewrite)", entry.LossPriority)
	}
	if len(entry.Precedences) != 2 || entry.Precedences[0] != 5 || entry.Precedences[1] != 6 {
		t.Fatalf("entry precedences = %v, want [5 6] (every code-point must cross, not just the first)",
			entry.Precedences)
	}
}

// TestBuildClassOfServiceSnapshotINetPrecedenceWireKeys pins the JSON keys the
// Rust decoder reads (`inet_precedence_classifiers`, `precedences`). A rename
// on either side leaves the field at its serde default — an empty classifier
// list — which is a SILENT loss of classification, not a decode failure.
func TestBuildClassOfServiceSnapshotINetPrecedenceWireKeys(t *testing.T) {
	snap := buildClassOfServiceSnapshot(cosINetPrecedenceConfig(true))
	raw, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, want := range []string{`"inet_precedence_classifiers"`, `"precedences"`, `"loss_priority":"high"`} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("snapshot JSON missing %s: %s", want, raw)
		}
	}
}

// TestBuildClassOfServiceSnapshotSkipsINetPrecedenceUndefinedClass mirrors the
// #2704 skip+warn the dscp / ieee-802.1 classifiers carry: an entry naming a
// forwarding class that does not exist is dropped on the Go side so the loss is
// logged, rather than crossing the wire for the Rust builder to drop silently.
func TestBuildClassOfServiceSnapshotSkipsINetPrecedenceUndefinedClass(t *testing.T) {
	cfg := cosINetPrecedenceConfig(true)
	cfg.ClassOfService.INetPrecedenceClassifierDefs["prec-cl"].Entries = append(
		cfg.ClassOfService.INetPrecedenceClassifierDefs["prec-cl"].Entries,
		&config.CoSINetPrecedenceClassifierEntry{ForwardingClass: "nope", Precedences: []uint8{1}},
	)
	snap := buildClassOfServiceSnapshot(cfg)
	entries := snap.INetPrecedenceClassifiers[0].Entries
	if len(entries) != 1 {
		t.Fatalf("want the undefined-class entry skipped (1 entry), got %d (%+v)", len(entries), entries)
	}
	if entries[0].ForwardingClass != "voice" {
		t.Fatalf("wrong entry survived: %+v", entries[0])
	}
}

// TestBuildInterfaceSnapshotsPublishesINetPrecedenceBinding is the other half
// of the wire crossing: the classifier LIST is useless without the per-unit
// binding that names which one the interface uses.
func TestBuildInterfaceSnapshotsPublishesINetPrecedenceBinding(t *testing.T) {
	cfg := cosINetPrecedenceConfig(true)
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0-0-2": {
			Name:  "ge-0-0-2",
			Units: map[int]*config.InterfaceUnit{0: {Number: 0, Addresses: []string{"10.0.2.10/24"}}},
		},
	}
	snapshots := buildInterfaceSnapshots(cfg)
	var found *InterfaceSnapshot
	for i := range snapshots {
		if snapshots[i].Name == "ge-0-0-2.0" {
			found = &snapshots[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("expected a ge-0-0-2.0 interface snapshot, got %+v", snapshots)
	}
	if found.CoSINetPrecedenceClassifier != "prec-cl" {
		t.Fatalf("cos_inet_precedence_classifier = %q, want prec-cl (the binding never reaches the dataplane without it)",
			found.CoSINetPrecedenceClassifier)
	}
}

// TestBuildClassOfServiceSnapshotINetPrecedenceOnlyConfigIsNotNil pins the
// early-return set-membership: a CoS config whose ONLY content is an
// inet-precedence classifier must still produce a snapshot. Leaving
// INetPrecedenceClassifierDefs out of that emptiness check would return nil and
// publish no CoS block at all.
func TestBuildClassOfServiceSnapshotINetPrecedenceOnlyConfigIsNotNil(t *testing.T) {
	cfg := &config.Config{
		ClassOfService: &config.ClassOfServiceConfig{
			INetPrecedenceClassifierDefs: map[string]*config.CoSINetPrecedenceClassifier{
				"prec-cl": {Name: "prec-cl"},
			},
		},
	}
	if snap := buildClassOfServiceSnapshot(cfg); snap == nil {
		t.Fatal("a config carrying only an inet-precedence classifier must still publish a CoS snapshot")
	}
}
