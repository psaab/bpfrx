package dataplane

import "log/slog"

// bumpFIBGenerationAfterRecompile performs CompileConfig's post-recompile FIB
// generation bump and REPORTS a failure instead of discarding it (#7149,
// split from #4960).
//
// Why the error matters here. On the live userspace path CompileConfig runs
// against userspaceShimCompileDataplane (loader.go), whose ~55 DataPlane
// overrides are all no-ops -- TestPrePassFakeIsNoMorePermissiveThanProduction_4960
// asserts exactly that. BumpFIBGeneration is one of only three methods the
// compiler calls that the shim does NOT override (the other two, IsLoaded and
// GetPersistentNAT, run before any mutation and return no error), so it
// promotes to the embedded *Manager and performs a real bpffs map write. It is
// therefore the ONE compiler dataplane call on that path that can genuinely
// fail.
//
// And a failure is not cosmetic. userspace/manager_compile.go builds the
// snapshot it is about to hand the helper with m.readFIBGeneration(), which
// re-reads the same fib_gen_map this bump writes. A failed bump leaves the map
// at its old value, so the published snapshot carries the OLD generation, the
// helper's session.fib_gen comparison still matches, and established flows keep
// the cached next-hop (ifindex + DMAC/SMAC) that the recompile may have just
// invalidated -- until they age out, with the apply reporting success
// throughout. (*Manager).BumpFIBGeneration warns on two of its three failure
// branches; the registryFresh / not-armed branch returns ErrDataplaneNotArmed
// with no log at all, so without this the whole thing is silent.
//
// It deliberately does NOT return the error. This runs AFTER compileZones has
// mutated the host and BEFORE the new snapshot is published, so propagating it
// would manufacture a fresh instance of the exact half-applied shape #4960
// exists to prevent: VLANs created and addresses reconciled, the apply aborted,
// the helper left on the old snapshot. Making an apply fail CLOSED after the
// dataplane has been asked is the apply-transaction half of #4960
// (research/4960-apply-txn), not this. The other two production callers each
// pick the treatment their own path can support -- the ip-monitoring actuator
// retries via pendingFIBBump (#1844/#3757 H3), the route-leak commit tail fails
// the commit closed because it has no retry owner (#5696 M19) -- and neither is
// available here.
//
// The message wording is deliberately NOT asserted by any test; what is bound
// is that the error is not discarded (TestCompilerNeverDiscardsTheFIBBumpError_7149,
// a source walk) and that a failing bump produces a WARN carrying it
// (TestFailedFIBBumpIsReported_7149).
func bumpFIBGenerationAfterRecompile(dp DataPlane) {
	if _, err := dp.BumpFIBGeneration(); err != nil {
		slog.Warn("compile: FIB generation bump failed — the snapshot about to be "+
			"published carries the previous generation, so established flows keep "+
			"their cached next-hop until they age out",
			"err", err)
	}
}
