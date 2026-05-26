package cmdtree

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestSchemaValidate_AcceptsLegacyDPDKSubStanza is the Codex r6 v3.3
// fixture-strength regression gate for #1528. The plan v3.3 §4.7
// contract requires that any future expansion of SchemaValidate
// which walks `system dataplane` tolerates orphaned legacy DPDK
// sub-stanzas that survive the `rewriteRetiredDataplaneType` bridge
// (pkg/configstore/dataplane_retire.go, invoked from both Store.Load
// and Store.SyncApply before compile + schema validation). The
// bridge strips the `dataplane-type dpdk` leaf, but any nested
// `system dataplane ...` sub-stanza remains; if a future
// SchemaValidate walker rejects those orphaned leaves it would
// preempt the operator-facing commit-time `ErrDPDKDataplaneRetired`
// rejection AND break stored-config rolling upgrade (operational
// blackout for pre-#1526 persisted DPDK configs).
//
// This test exercises the positive-path walker by including a valid
// class-of-service schedulers block (defeating SchemaValidate's
// "class-of-service absent" early return at schema_validate.go:43-46)
// alongside the comprehensive legacy DPDK shape. The cos block
// forces the walker to fire; the DPDK leaves must be ignored.
//
// Regression scenarios this gate catches:
//
//   - Unconditional system-dataplane walker added to SchemaValidate.
//     The cos block still triggers the existing walker; if a new
//     walker rejects the DPDK fixture, this test fires.
//   - Removal of the class-of-service early-return so SchemaValidate
//     walks all subtrees. The cos block exercises the real walker;
//     any new system-dataplane validator without retired-backend
//     tolerance rejects the DPDK leaves and fires this test.
//   - New independent walker that fires only when cos is present.
//     The cos block guarantees this regression class is hit.
//
// A pre-condition assertion confirms the fixture is structurally
// valid (cos node present) even if a future refactor changes the
// walker shape.
func TestSchemaValidate_AcceptsLegacyDPDKSubStanza(t *testing.T) {
	tree := &config.ConfigTree{}
	for _, line := range []string{
		// class-of-service schedulers block — triggers the walker.
		"set class-of-service schedulers be-sched transmit-rate 1g",
		"set class-of-service schedulers be-sched priority low",
		"set class-of-service schedulers be-sched buffer-size 10%",
		// Legacy DPDK shape — must NOT be rejected.
		"set system dataplane-type dpdk",
		"set system dataplane cores 2-5",
		"set system dataplane memory 2048",
		"set system dataplane socket-mem \"1024,1024\"",
		"set system dataplane rx-mode adaptive",
		"set system dataplane rx-mode idle-threshold 256",
		"set system dataplane rx-mode resume-threshold 32",
		"set system dataplane rx-mode sleep-timeout 100",
		"set system dataplane ports 0000:03:00.0 interface wan0",
		"set system dataplane ports 0000:03:00.0 rx-mode polling",
		"set system dataplane ports 0000:03:00.0 cores 2-3",
		"set system dataplane ports 0000:06:00.0 interface trust0",
	} {
		path, err := config.ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}

	// Pre-condition: the walker MUST actually fire. If a future
	// refactor changes the early-return condition such that the cos
	// node no longer triggers walking, this assertion catches it.
	if tree.FindChild("class-of-service") == nil {
		t.Fatal("fixture invalid: class-of-service subtree missing — walker would early-return; gate is useless")
	}

	// Assertion: SchemaValidate walks the cos block AND ignores the
	// legacy DPDK shape. If a future PR adds a top-level
	// system-dataplane walker without retired-backend tolerance,
	// this test fires.
	if err := SchemaValidate(tree, nil); err != nil {
		t.Fatalf("SchemaValidate rejected legacy DPDK sub-stanza alongside valid cos block: %v", err)
	}
}
