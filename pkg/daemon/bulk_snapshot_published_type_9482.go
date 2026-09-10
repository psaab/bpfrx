package daemon

import (
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #9482 — bind the bulk-snapshot exporter interface to the types the daemon
// ACTUALLY PUBLISHES, at compile time.
//
// WHAT WENT WRONG. `userspaceBulkSnapshot` resolves its exporter by RUNTIME TYPE
// ASSERTION:
//
//	exporter, ok := d.dataplane().(userspaceSessionExporter)
//	if !ok { return ..., errors.New("dataplane does not export owner-RG sessions") }
//
// #9344 changed the single method that interface names, from
// `ExportOwnerRGSessions(rgIDs, max)` to `ExportOwnerRGSessionsPaged(rgIDs)`, and
// added the new method to `*dpuserspace.Manager`. But the value the daemon
// publishes for the userspace backend is `*dpuserspace.LegacyDataPlaneAdapter`
// (`dpuserspace.Boot()` returns `NewLegacyDataPlaneAdapter(New())`), which
// forwards a hand-written subset of the Manager's methods — and the new one was
// not added to it. So the assertion failed on the ONLY type it is ever handed,
// `doBulkSync` correctly failed closed, and the HA cold-prime bulk sync never ran
// on any node.
//
// A runtime type assertion is a SILENT contract: it has no compile-time edge, so
// the two sides can drift and nothing says so until a cluster rejoins in
// production. This file supplies the missing edge, in the same spirit as the
// `sessionCursorIterator` drift guard in `legacy_dataplane.go` — but pointed the
// other way. That one asserts the adapter's own method signatures inside its own
// package; this one asserts them against the ACTUAL interface, which lives here
// and is unexported, so it is the only place the two can be spelled in one
// expression.
//
// WHY BOTH TYPES, and why the pair is the whole population. The population is
// "every concrete type that can be published as the userspace
// `dataplane.RuntimeDataPlane`", and `pkg/dataplane/userspace` declares exactly
// two of them — `var _ dataplane.RuntimeDataPlane = (*Manager)(nil)`
// (manager.go) and `var _ dataplane.RuntimeDataPlane = (*LegacyDataPlaneAdapter)(nil)`
// (legacy_dataplane.go). Asserting only the adapter would fix today's defect
// while leaving the identical hole for the sibling that is already declared
// publishable. The adapter is the one `Boot()` returns and therefore the one that
// broke; the Manager is the one that already satisfied it and would have hidden
// the break if it had been the assertion's subject.
//
// WHAT THIS CANNOT SEE, stated so nobody reads it as more than it is: it is a
// STATIC check on two named types. It does not establish that
// `userspaceBulkSnapshot` is wired into `SessionSync.BulkSnapshotSource` (that is
// #7259's cell), nor that the exported window is correct (#6031's), nor that a
// THIRD type added later gets asserted. The behavioural half — that the resolver
// accepts a real published adapter rather than refusing it — is
// `bulk_snapshot_published_type_9482_test.go`.
var (
	_ userspaceSessionExporter = (*dpuserspace.LegacyDataPlaneAdapter)(nil)
	_ userspaceSessionExporter = (*dpuserspace.Manager)(nil)
)
