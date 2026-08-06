package daemon

import (
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #5275 PR2 — daemon-side mirrors of the RUNTIME type-assertion probes the
// external consumers run against the handle they hold.
//
// WHY THIS FILE EXISTS. Consumers do not reach the dataplane through one wide
// interface. Besides the three assigned mirrors in runtime_probes.go
// (apiDataPlane / grpcDataPlane / cliDataPlane) they run OPTIONAL-CAPABILITY
// probes — `if p, ok := s.dp.(someProvider); ok { ... } else { degrade }` — and
// every one of them degrades SILENTLY when the assertion fails.
//
// That is a hazard specific to the facade. *dataplaneFacade embeds nothing and
// declares an explicit method list, so a method it does not name is simply ABSENT
// from the dynamic type the consumer asserts against. The production backend
// (*dpuserspace.LegacyDataPlaneAdapter) has all of them, so every probe succeeded
// before the facade; a probe the facade forgets fails, the consumer takes its
// fallback branch, the build is green and the suite is green. That is exactly how
// four capabilities were lost in the first cut of this PR (deterministic
// source-NAT on three surfaces, the scheduler-state display on two, and cursor
// session paging on three).
//
// The three mirrors in runtime_probes.go do NOT protect against this. They are
// ASSIGNED into a downstream Config/constructor, so Go checks them at the
// assignment site — the compile error runtime_probes.go promises. A probe
// interface has no assignment site: the consumer asserts a handle it already
// holds, at RUNTIME. Nothing in the compiler or the suite connects the facade's
// method list to it.
//
// WHAT THE ASSERTIONS BELOW PROVE. Each mirror below is a copy of one consumer
// probe SHAPE, and the `var _ mirror = (*dataplaneFacade)(nil)` block at the
// bottom makes "the facade satisfies it" a build-time fact. Dropping a method
// from the facade now fails to compile HERE rather than disabling a command on
// the next boot.
//
// WHAT THEY DO NOT PROVE — read this before trusting the set:
//
//   - COMPLETENESS is not proved by this file. The set was assembled by grepping
//     the three consumer packages for `\.dp\.\(`, so it covers the probes written
//     in that spelling and no others. A consumer that copies s.dp into a local and
//     asserts the local, or that reaches the dataplane through some other field,
//     is outside it. The mechanical half of the completeness argument lives in
//     TestFacadeCoversEveryConsumerProbe (dataplane_facade_probe_coverage_5275_test.go),
//     which re-derives the probe set from consumer source on every run and fails
//     when a probe names a method the facade lacks — so a FIFTH omission cannot
//     ship silently, within the same spelling limit. Neither mechanism can see a
//     probe expressed a way the scan does not recognise; the scan fails loudly on
//     the one alternative form it knows of (an inline `interface{...}` literal is
//     resolved, not skipped).
//
//   - SIGNATURE agreement with the consumer's own declaration is not proved HERE,
//     because these are copies: pkg/api, pkg/cli and pkg/grpcapi keep their probe
//     interfaces package-private and pkg/daemon imports all three, so the daemon
//     cannot name them. It is proved TRANSITIVELY instead. A consumer probe is
//     only useful if the real backend satisfies it, so a signature change to a
//     probe comes with the same change to *dpuserspace.LegacyDataPlaneAdapter —
//     and that breaks `var _ facadeBackend = (*dpuserspace.LegacyDataPlaneAdapter)(nil)`
//     (dataplane_facade.go) plus the facade's own delegating call. A probe whose
//     signature drifts AWAY from the backend is a bug in that consumer, caught by
//     that consumer's tests, not a facade-coverage gap.

// facadeStatusProbe mirrors the userspace-helper status probe. Four call sites
// assert this shape against the handle they hold: pkg/api/nat.go
// (runtimeSourceNATPools) and pkg/api/system.go (systemBuffersHandler) inline,
// pkg/cli's cliUserspaceStatusProvider, and pkg/grpcapi's
// userspaceStatusProvider. Losing it blanks `show system buffers`, the
// source-NAT pool utilisation view, and the userspace show surfaces.
type facadeStatusProbe interface {
	Status() (dpuserspace.ProcessStatus, error)
}

// facadeUserspaceControlProbe mirrors the forwarding-control probe: pkg/cli's
// package-private cliUserspaceControlProvider (pkg/cli/runtime.go) and
// pkg/grpcapi's identically-shaped userspaceControlProvider
// (pkg/grpcapi/runtime.go). Both extend the status probe with the mutators
// behind `request chassis cluster data-plane userspace ...`.
//
// These also must be GATED, not merely present: they are the mutators #5275 §7
// calls directly exploitable on bootstrap-exit, because they never traverse the
// apply gate.
//
// This is the probe whose loss was CAUGHT during this PR rather than reasoned
// about, and the mechanism is worth keeping in view. pkg/cli's
// userspaceDataplaneControl() asserts c.dp — the handle the CLI was CONSTRUCTED
// with — at runtime. A handle that does not satisfy it compiles perfectly; the
// command just reports "userspace dataplane control unavailable" on the next
// boot. The full Go suite stayed green through it, because pkg/cli's tests
// construct a CLI from their own fakes and never from the facade.
//
// TWO BELTS, AND NEITHER IS REDUNDANT. The assertion below proves the FACADE
// still implements the surface. A sibling test in pkg/cli
// (userspace_control_shape_5275_test.go) proves the INTERFACE still has the
// shape this mirror copies. Both are needed because a single cross-package
// assertion is impossible: pkg/daemon imports pkg/cli, so pkg/cli cannot import
// pkg/daemon to assert against the facade directly. Deleting either belt leaves
// one side of the mirror unguarded.
type facadeUserspaceControlProbe interface {
	facadeStatusProbe
	SetForwardingArmed(bool) (dpuserspace.ProcessStatus, error)
	SetQueueState(uint32, bool, bool) (dpuserspace.ProcessStatus, error)
	SetBindingState(uint32, bool, bool) (dpuserspace.ProcessStatus, error)
	InjectPacket(dpuserspace.InjectPacketRequest) (dpuserspace.ProcessStatus, error)
}

// facadeSessionCursorProbe mirrors the cursor-iteration probe: pkg/api's and
// pkg/grpcapi's sessionCursorIterator plus pkg/cli's cliSessionCursor.
//
// Losing it is not a visible outage, which is why it is worth naming. REST
// cursor paging falls back to the offset path its own doc comment says can skip
// or duplicate rows across map mutation (#3421 H4), and the filtered clear paths
// fall back to the bounded fresh-rescan that pkg/grpcapi/server_sessions.go and
// pkg/cli/cli_clear.go both describe as trading the memory DoS for an O(N^2)
// CPU-stall able to starve the HA watchdog (#4719).
type facadeSessionCursorProbe interface {
	IterateSessionsFrom(cursor *dataplane.SessionKey, fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error
	IterateSessionsV6From(cursor *dataplane.SessionKeyV6, fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error
}

// facadeAppliedNATViewProbe mirrors the deterministic source-NAT lookup probe
// (#5794): pkg/grpcapi's appliedNATViewProvider plus the inline assertions in
// pkg/api/nat.go and pkg/cli/cli_show_nat.go. Losing it returns
// Available:false on ALL THREE surfaces, so the feature reports "unavailable"
// everywhere while the dataplane is perfectly healthy.
type facadeAppliedNATViewProbe interface {
	AppliedNATView() dpuserspace.AppliedNATView
}

// facadePolicySchedulerStateProbe mirrors the scheduler active-state probe
// (#3062/#3104): the identically-named policySchedulerStateProvider in
// pkg/cli/cli_show_security_dispatch.go and
// pkg/grpcapi/server_show_policies_text.go.
//
// This is the probe whose failure is FAIL-OPEN at the display, so it deserves
// the sharpest note. Both surfaces gate on ok: when the assertion fails they
// render every policy "enabled" — bit-identical to the pre-#3062 output, which
// is correct for a runtime that genuinely has no scheduler state, and wrong for
// one that has it and is SKIPPING the policy. `show security match-policies`
// takes the same state and, with ok=false, marks every scheduler-bound policy
// inactive, so the two surfaces disagree in opposite directions.
//
// REST is not on this list on purpose: pkg/api takes the same state through
// PolicySchedulerActiveStateFn, a daemon closure over d that re-reads d.dp per
// call (daemon_run_servers.go), not through the handle. That asymmetry is what
// made the loss visible — CLI and gRPC changed while REST did not.
type facadePolicySchedulerStateProbe interface {
	PolicySchedulerActiveState() map[string]bool
}

// Compile-time proof that the facade satisfies every mirrored probe. If a probe
// gains a method the facade does not implement, this fails to compile HERE —
// before anyone can quietly hand a consumer the raw backend again to make it
// build.
var (
	_ facadeStatusProbe               = (*dataplaneFacade)(nil)
	_ facadeUserspaceControlProbe     = (*dataplaneFacade)(nil)
	_ facadeSessionCursorProbe        = (*dataplaneFacade)(nil)
	_ facadeAppliedNATViewProbe       = (*dataplaneFacade)(nil)
	_ facadePolicySchedulerStateProbe = (*dataplaneFacade)(nil)
)
