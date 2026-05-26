package daemon

import (
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// Compile-time assertions: every in-tree dataplane backend satisfies
// every daemon-local typed probe declared in runtime_probes.go.
// Together with the assignments to api.Config.DP / grpcapi.Config.DP
// / cli.New(...) at the daemon_run.go call sites, these guards make
// any signature drift between daemon-local probes and downstream
// package-private interfaces a build-time failure rather than a
// runtime nil-deref.
//
// If any of these declarations fails to compile, do NOT skip the
// assertion: fix the corresponding probe definition in
// runtime_probes.go to match the backend's actual method set, or
// fix the backend to satisfy the daemon's narrow contract.

var (
	_ dataplaneReadyProbe = (*dataplane.Manager)(nil)
	_ dataplaneReadyProbe = (*dpuserspace.LegacyDataPlaneAdapter)(nil)

	_ natSeeder = (*dataplane.Manager)(nil)
	_ natSeeder = (*dpuserspace.LegacyDataPlaneAdapter)(nil)

	_ fibSyncStarter = (*dataplane.Manager)(nil)
	_ fibSyncStarter = (*dpuserspace.LegacyDataPlaneAdapter)(nil)

	_ apiDataPlane = (*dataplane.Manager)(nil)
	_ apiDataPlane = (*dpuserspace.LegacyDataPlaneAdapter)(nil)

	_ grpcDataPlane = (*dataplane.Manager)(nil)
	_ grpcDataPlane = (*dpuserspace.LegacyDataPlaneAdapter)(nil)

	_ cliDataPlane = (*dataplane.Manager)(nil)
	_ cliDataPlane = (*dpuserspace.LegacyDataPlaneAdapter)(nil)
)
