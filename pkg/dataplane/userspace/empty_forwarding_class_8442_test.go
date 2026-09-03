package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #8442 — THE HARM, on the tolerant path, next to the emitter that produces it.
//
// The strict commit path now refuses an empty forwarding-class name, so it has
// no snapshot left to inspect. The #1960 tolerant path still boots the config,
// and that is where the emission can be examined: it carries the empty name in
// BOTH `forwarding_classes` and the scheduler-map entries — exactly the input
// the Rust `build_cos_iface_config` refuses WHOLE with
// `SchedulerMapUnknownClass { forwarding_class: "" }`.
//
// Without this cell the suite would record THAT an empty name is rejected at
// commit and nothing about what it was rejected for.
func TestEmptyForwardingClassWouldReachTheWire_8442(t *testing.T) {
	tree := &config.ConfigTree{}
	for _, cmd := range []string{
		`set class-of-service forwarding-classes queue 5 ""`,
		"set class-of-service forwarding-classes queue 6 realfc",
		"set class-of-service schedulers s1 transmit-rate 10m",
		`set class-of-service scheduler-maps sm1 forwarding-class "" scheduler s1`,
		"set class-of-service scheduler-maps sm1 forwarding-class realfc scheduler s1",
	} {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("parse %q: %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("the TOLERANT path must still boot (#1960 no-brick), got: %v", err)
	}
	snap := buildClassOfServiceSnapshot(cfg)
	if snap == nil {
		t.Fatalf("fixture produced NO CoS snapshot at all — the authoring spelling " +
			"populated nothing and every assertion below would be vacuous")
	}
	if len(snap.ForwardingClasses) < 2 {
		t.Fatalf("fixture: expected both the empty and the named class to be "+
			"emitted, got %+v", snap.ForwardingClasses)
	}

	sawEmptyClass := false
	for _, fc := range snap.ForwardingClasses {
		if fc.Name == "" {
			sawEmptyClass = true
		}
	}
	if !sawEmptyClass {
		t.Errorf("the emitter must still carry the empty class on the tolerant "+
			"path — that emission is the defect the commit gate exists to keep off "+
			"the wire, got %+v", snap.ForwardingClasses)
	}

	// The scheduler-map half is the one that actually detonates: `class_to_queue`
	// simply lacks the empty key, and it is the ENTRY's lookup that returns
	// SchedulerMapUnknownClass and fails the whole snapshot.
	sawEmptyEntry := false
	for _, sm := range snap.SchedulerMaps {
		for _, e := range sm.Entries {
			if e.ForwardingClass == "" {
				sawEmptyEntry = true
			}
		}
	}
	if !sawEmptyEntry {
		t.Errorf("the emitter must still carry the empty scheduler-map ENTRY — that "+
			"is the lookup that misses in class_to_queue and refuses the snapshot "+
			"whole, got %+v", snap.SchedulerMaps)
	}
}
