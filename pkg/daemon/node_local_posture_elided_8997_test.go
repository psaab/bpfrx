package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #8997: the #7441 cells all built their trees with SetPath, which writes the
// canonical fully-braced spelling — so they exercised the ONE spelling the old
// reader could see. An operator who wrote the posture in either elided spelling
// had it silently overwritten by a peer push.
//
// The failure is not a false negative, it is an AGREEMENT: misreading the local
// node as not having the flag makes both sides false, so the hook `continue`s
// and neither the restore nor the strip branch is reached. Both of #7441's
// directions were affected, which matters because its own rationale says
// preserving one direction leaves the other as a lever.

// elidedPostureTree8997 parses text rather than using SetPath, because SetPath
// is precisely the path that cannot produce the spellings under test.
func elidedPostureTree8997(t *testing.T, text string) *config.ConfigTree {
	t.Helper()
	root, perrs := config.NewParser(text).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse %q: %v", text, perrs)
	}
	return &config.ConfigTree{Children: root.Children}
}

var elidedPostureSpellings8997 = []struct{ name, text string }{
	{"fully braced", `chassis { cluster { cluster-id 22; strict-session-auth; } }`},
	{"cluster brace elided", `chassis { cluster-id 22; cluster strict-session-auth; }`},
	{"fully packed", `chassis cluster strict-session-auth;`},
}

// TestElidedLocalPostureSurvivesAPeerPush8997 is the direction #8997 measured:
// the local node HAS the posture, the pushed tree omits it, and the hook must
// put it back whatever spelling the operator used locally.
func TestElidedLocalPostureSurvivesAPeerPush8997(t *testing.T) {
	for _, sp := range elidedPostureSpellings8997 {
		t.Run(sp.name, func(t *testing.T) {
			local := elidedPostureTree8997(t, sp.text)
			if !chassisClusterFlagSet(local, "strict-session-auth") {
				t.Fatalf("fixture does not construct the state it names: the local tree "+
					"in the %q spelling does not read as having the posture", sp.name)
			}
			incoming := treeWithPosture7441(t, false)
			preserveNodeLocalChassis(local)(incoming)
			if !chassisClusterFlagSet(incoming, "strict-session-auth") {
				t.Errorf("a peer push CLEARED the node-local posture written in the %q "+
					"spelling — the hook read the local tree as not having it, so both "+
					"sides agreed and the restore branch was never reached (#8997)", sp.name)
			}
		})
	}
}

// TestElidedPeerPostureIsStripped8997 is the other direction, which #7441 says
// explicitly is not optional: a peer must not be able to ARM the posture
// either. The pushed tree carries it in an elided spelling; this node does not
// have it.
func TestElidedPeerPostureIsStripped8997(t *testing.T) {
	for _, sp := range elidedPostureSpellings8997 {
		t.Run(sp.name, func(t *testing.T) {
			local := treeWithPosture7441(t, false)
			incoming := elidedPostureTree8997(t, sp.text)
			if !chassisClusterFlagSet(incoming, "strict-session-auth") {
				t.Fatalf("fixture does not construct the state it names")
			}
			preserveNodeLocalChassis(local)(incoming)
			if chassisClusterFlagSet(incoming, "strict-session-auth") {
				t.Errorf("a peer SET the node-local posture on this node by writing it in "+
					"the %q spelling — #7441 says the leaf is not the peer's business in "+
					"EITHER direction (#8997)", sp.name)
			}
		})
	}
}

// TestAgreementIsStillANoOpAcrossSpellings8997 is the control that keeps the
// two cells above from passing for the wrong reason. When both sides genuinely
// have the posture — in DIFFERENT spellings — the hook must leave the incoming
// tree alone rather than rewriting it.
func TestAgreementIsStillANoOpAcrossSpellings8997(t *testing.T) {
	local := elidedPostureTree8997(t, `chassis cluster strict-session-auth;`)
	incoming := elidedPostureTree8997(t, `chassis { cluster { cluster-id 22; strict-session-auth; } }`)
	before := incoming.FormatSet()
	preserveNodeLocalChassis(local)(incoming)
	if got := incoming.FormatSet(); got != before {
		t.Errorf("the hook rewrote an incoming tree that already AGREED with the local "+
			"posture:\n before: %s\n after:  %s", before, got)
	}
	if !chassisClusterFlagSet(incoming, "strict-session-auth") {
		t.Error("agreement no-op dropped the posture")
	}
}
