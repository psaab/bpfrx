package daemon

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #9482 — the HA cold-prime bulk sync never ran, because the exporter the
// snapshot resolver asks for was not on the type the daemon publishes.
//
// WHAT WAS MEASURED, on the loss userspace cluster at origin/master. BOTH nodes,
// once a minute, indefinitely:
//
//	cluster sync: owed cold-prime re-drive failed, will retry
//	  err="bulk sync table-truth snapshot: dataplane does not export owner-RG sessions"
//
// and on every cold-start edge `cluster sync: bulk sync failed` with the same
// cause. A rejoining node received NO bulk window at all — only the incremental
// deltas that happened to arrive afterwards. `doBulkSync` fails CLOSED by design,
// so this was a permanent refusal on every attempt, not a degraded partial.
//
// THE MECHANISM. `userspaceBulkSnapshot` resolves its exporter by RUNTIME TYPE
// ASSERTION against `d.dataplane()`. #9344 changed the single method
// `userspaceSessionExporter` names — from `ExportOwnerRGSessions(rgIDs, max)` to
// `ExportOwnerRGSessionsPaged(rgIDs)` — and added the new method to
// `*dpuserspace.Manager`. But `dpuserspace.Boot()` publishes
// `*LegacyDataPlaneAdapter`, a hand-written forwarding subset of the Manager, and
// the new method was not added to it. The assertion therefore failed on the only
// type it is ever handed.
//
// WHY THE EXISTING COVERAGE COULD NOT SEE IT — and this is the part worth
// carrying forward. Every bulk-snapshot test in this package supplies its OWN
// exporter double: `wiringExporterDP` (#7259) and `recordingExporter` (#6031)
// both declare `ExportOwnerRGSessionsPaged` on themselves. So the whole family
// proves the resolver correct *for a type that satisfies the interface* and says
// nothing whatsoever about the type production publishes. A mutation that deletes
// the adapter's forwarder leaves every one of them green. That is the
// surviving-mutant shape exactly: a package's own cells prove a function correct
// and say nothing about what its caller is handed.
//
// So the binding here is deliberately NOT another fake. It goes through
// `dpuserspace.Boot()` — the real production constructor — and asks the real
// unexported interface about the value it returns.

// TestPublishedUserspaceDataplaneSatisfiesTheBulkExporter9482 is the primary
// binding.
//
// It asserts the DYNAMIC type of what `Boot()` returns, not a named concrete
// type. That matters: the compile-time belt in bulk_snapshot_published_type_9482.go
// names `*LegacyDataPlaneAdapter` and `*Manager`, so if `Boot()` ever returns a
// THIRD type the belt would keep passing about types nobody publishes while this
// cell would red. The two are complements, not duplicates — the belt catches a
// method removed from a named type at BUILD time, this catches the published type
// changing underneath it.
func TestPublishedUserspaceDataplaneSatisfiesTheBulkExporter9482(t *testing.T) {
	var published dataplane.RuntimeDataPlane = dpuserspace.Boot()
	if published == nil {
		t.Fatal("FIXTURE FAILED: dpuserspace.Boot() returned nil, so this cell " +
			"cannot observe anything about the published type")
	}
	if _, ok := published.(userspaceSessionExporter); !ok {
		t.Fatalf("#9482: the dataplane the daemon PUBLISHES for the userspace backend "+
			"(%T, from dpuserspace.Boot()) does not satisfy userspaceSessionExporter, so "+
			"userspaceBulkSnapshot's type assertion fails and the HA cold-prime bulk sync "+
			"never runs on any node. Measured live: both nodes logged \"dataplane does not "+
			"export owner-RG sessions\" once a minute, forever, and a rejoining node "+
			"received no bulk window. Every other bulk-snapshot test in this package "+
			"supplies its own exporter fake, so none of them can see this", published)
	}
}

// TestUserspaceBulkSnapshotAcceptsThePublishedDataplane9482 is the end-to-end
// half: the real resolver, handed the real published value, must get PAST the
// type assertion.
//
// It asserts on WHICH error comes back rather than on success, and that is the
// honest assertion for this fixture. A `Boot()` adapter in a test has no running
// helper, so the export itself must fail — but it must fail for its OWN reason,
// wrapped by `userspaceBulkSnapshotWithConfig` as "export owner-RG sessions: ...",
// NOT with the resolver's refusal "dataplane does not export owner-RG sessions".
// The first says the wiring accepted the type and the call failed downstream; the
// second is the defect. They are the two states this cell exists to separate, and
// an assertion phrased as "err != nil" would pass in both.
func TestUserspaceBulkSnapshotAcceptsThePublishedDataplane9482(t *testing.T) {
	const refusal = "dataplane does not export owner-RG sessions"

	// The MINIMUM that makes ActiveConfig() non-nil. This cell is about the type
	// assertion, not about what the window contains, so the config carries no
	// zones: zone members must name configured interfaces and the extra stanzas
	// would only be fixture surface that can rot independently of the claim.
	store := testStoreWithSetConfig(t, []string{
		"set system host-name bulk9482",
	})
	d := &Daemon{
		store:       store,
		sessionSync: &cluster.SessionSync{IsPrimaryFn: func() bool { return true }},
	}
	d.setDataplane(dpuserspace.Boot())

	if d.store.ActiveConfig() == nil {
		t.Fatal("FIXTURE FAILED: no active config, so userspaceBulkSnapshot returns " +
			"before reaching the type assertion this cell is about")
	}
	if d.getSessionSync() == nil {
		t.Fatal("FIXTURE FAILED: no session sync, so userspaceBulkSnapshot returns " +
			"before reaching the type assertion this cell is about")
	}

	_, err := d.userspaceBulkSnapshot()
	if err != nil && strings.Contains(err.Error(), refusal) {
		t.Fatalf("#9482: userspaceBulkSnapshot REFUSED the dataplane the daemon "+
			"publishes (%T): %v\nThat refusal is the permanent cold-prime failure — "+
			"doBulkSync fails closed on it and frames no window, so a rejoining node "+
			"gets no bulk session state at all", d.dataplane(), err)
	}
	// Positive statement about what DID happen, so a future reader can see the
	// cell reached the export rather than short-circuiting somewhere earlier.
	if err != nil && !strings.Contains(err.Error(), "export owner-RG sessions") {
		t.Errorf("expected either success or a failure from the export itself "+
			"(wrapped \"export owner-RG sessions: ...\"), got %v — if this is a new "+
			"early-return the cell is no longer reaching the type assertion", err)
	}
}

// CONTROL — the refusal branch must still be REACHABLE and must still say what it
// says.
//
// Without this, "make the assertion succeed" is satisfiable by deleting the
// `!ok` branch entirely, and then a genuinely export-incapable dataplane would
// be handed to userspaceBulkSnapshotWithConfig as a nil interface. That path
// returns "userspace session exporter not available" instead — a different
// message, at a different layer, for a condition the resolver is supposed to
// catch. This cell pins that an incapable dataplane is still refused, by the
// resolver, with the resolver's own wording.
func TestUserspaceBulkSnapshotStillRefusesAnIncapableDataplane9482(t *testing.T) {
	const refusal = "dataplane does not export owner-RG sessions"

	store := testStoreWithSetConfig(t, []string{
		"set system host-name bulk9482ctl",
	})
	d := &Daemon{
		store:       store,
		sessionSync: &cluster.SessionSync{IsPrimaryFn: func() bool { return true }},
	}
	// A RuntimeDataPlane with no owner-RG export at all. The nil embed is
	// deliberate: nothing on this path may call through it, and a panic is a
	// louder failure than a wrong verdict.
	d.setDataplane(&noExportDP9482{})

	_, err := d.userspaceBulkSnapshot()
	if err == nil || !strings.Contains(err.Error(), refusal) {
		t.Fatalf("a dataplane that does NOT export owner-RG sessions must still be "+
			"refused by the resolver with %q, got %v. If this stopped holding, the "+
			"incapable case now reaches userspaceBulkSnapshotWithConfig as a nil "+
			"interface and reports a different condition at a different layer", refusal, err)
	}
}

type noExportDP9482 struct {
	dataplane.RuntimeDataPlane
}
