package configstore

import (
	"strings"
	"testing"
)

// #8442 — an empty forwarding-class name committed GREEN and then made the
// helper reject the whole snapshot.
//
// The fault is a Go/Rust SET DISAGREEMENT, and each side is reasonable alone:
//
//   - the Go emitter KEEPS an empty class, in `forwarding_classes` AND in the
//     scheduler-map entries;
//   - the Rust `build_cos_classifier_tables` SKIPS an empty class name when
//     building `class_to_queue`, deliberately, as "the legitimate placeholder
//     case".
//
// So the scheduler-map entry's lookup misses and `build_cos_iface_config` fails
// the ENTIRE snapshot closed with `SchedulerMapUnknownClass`. The apply
// preflight keeps the previous live forwarding state, and every forwarding
// change in that commit silently does not apply — while the CLI reports
// success.
//
// Measured at master by dumping the emitted snapshot before any gate existed:
//
//	{"forwarding_classes":[{"name":"","queue":5},{"name":"realfc","queue":6}],
//	 "scheduler_maps":[{"name":"sm1","entries":[{"forwarding_class":""},...]}]}
//
// These cells bind the gate at CheckText, the real operator commit path. The
// BLAST RADIUS half — that the whole snapshot, not just the bad entry, is
// refused — is bound on the Rust side, because that is where the refusal
// happens. The emitted-snapshot half lives in pkg/dataplane/userspace, next to
// the emitter.

const fcBase8442 = `
system { host-name p; }
interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.1.1/24; } } } }
security { zones { security-zone trust { interfaces { ge-0/0/0.0; } } } }
`

func fcCommit8442(cos string) error {
	_, err := CheckText(fcBase8442+"class-of-service {\n"+cos+"\n}\n", 0)
	return err
}

// REJECT. Every slot that names a forwarding class.
func TestEmptyForwardingClassRejected_8442(t *testing.T) {
	for _, tc := range []struct {
		name string
		cos  string
	}{
		{
			"definition slot — forwarding-classes queue <id> \"\"",
			`forwarding-classes { queue 5 ""; }`,
		},
		{
			"scheduler-map entry reference",
			`forwarding-classes { queue 5 realfc; }
			 schedulers { s1 { transmit-rate 10m; } }
			 scheduler-maps { sm1 { forwarding-class "" scheduler s1; } }`,
		},
		{
			"classifier reference",
			`forwarding-classes { queue 5 realfc; }
			 classifiers { dscp c1 { forwarding-class "" { loss-priority low { code-points ef; } } } }`,
		},
		// THE ONE THAT MATTERS FOR ORDERING: the bad name sits BESIDE a valid
		// one. A gate that only looked at "the forwarding-classes stanza has a
		// problem" could pass on the lone-bad-leaf input and still miss this,
		// and this is the shape the issue's own repro uses — the empty class
		// even DENIES the real one ("realfc" conflicts with "").
		{
			"empty name beside a valid one",
			`forwarding-classes { queue 5 ""; queue 6 realfc; }`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := fcCommit8442(tc.cos)
			if err == nil {
				t.Fatalf("an empty forwarding-class name committed CLEAN. It crosses the "+
					"wire, the helper drops it from class_to_queue, and the resulting "+
					"snapshot is refused WHOLE — so every forwarding change in this "+
					"commit silently fails to apply (#8442). cos=%s", tc.cos)
			}
			if !strings.Contains(err.Error(), "forwarding-class") {
				t.Errorf("the rejection must name the offending construct, got: %v", err)
			}
		})
	}
}

// POSITIVE CONTROLS. A gate that rejects everything passes every cell above.
//
// The last row is the paired half of "empty name beside a valid one": the SAME
// shape with both names valid must still commit, so the rejection is attributable
// to the empty name and not to the two-classes-in-one-stanza shape.
func TestValidForwardingClassesStillCommit_8442(t *testing.T) {
	for _, tc := range []struct {
		name string
		cos  string
	}{
		{"a single named class", `forwarding-classes { queue 5 realfc; }`},
		{
			"a class with a scheduler map that references it",
			`forwarding-classes { queue 5 realfc; }
			 schedulers { s1 { transmit-rate 10m; } }
			 scheduler-maps { sm1 { forwarding-class realfc scheduler s1; } }`,
		},
		{
			"a class with a classifier that references it",
			`forwarding-classes { queue 5 realfc; }
			 classifiers { dscp c1 { forwarding-class realfc { loss-priority low { code-points ef; } } } }`,
		},
		{"two valid classes side by side", `forwarding-classes { queue 5 fc-a; queue 6 fc-b; }`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := fcCommit8442(tc.cos); err != nil {
				t.Fatalf("a valid forwarding-class config must still commit, got: %v\ncos=%s",
					err, tc.cos)
			}
		})
	}
}
