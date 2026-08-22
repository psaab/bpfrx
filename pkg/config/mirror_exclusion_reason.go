package config

// PortMirroringInstanceExcludedReason reports why the userspace snapshot
// builder drops a `forwarding-options port-mirroring` instance outright, or ""
// when the instance is published.
//
// #6534. The lie this closes is unusually sharp: both renderers print
// `Input rate: all packets` whenever InputRate is not > 0 — so an instance with
// a NEGATIVE rate, which the builder drops entirely (a negative would wrap the
// uint32 cast), reads on screen as the most permissive possible mirror while
// mirroring nothing at all.
//
// SCOPE — read this before assuming the predicate is complete. It covers only
// the conditions decidable from the CONFIG. buildMirrorSnapshots drops an
// instance for two further reasons that depend on the runtime INTERFACE TABLE,
// not on config: an output interface that does not resolve to an ifindex, and
// an ingress interface already claimed by a lower-sorted instance (one output
// per ingress ifindex). A renderer holding only *config.Config cannot reach
// those, so annotating them needs the resolved ifindex map threaded to the
// surface — the one place in this audit where the "give the renderer applied
// state" instinct has real force, rather than the predicate being enough.
//
// Callers: buildMirrorSnapshots (pkg/dataplane/userspace/mirrors.go), and all
// THREE show surfaces — cli.showPortMirroring,
// Server.showForwardingOptionsPortMirroring, and cli.showForwardingOptions.
//
// This comment said TWO until #6534's closure, and the miscount was the bug:
// the first two are byte-identical copies of each other and were annotated
// together, while `show forwarding-options` in cli_show_routing.go — a third
// copy with its own layout, printing MORE per-instance detail than the gRPC
// command of the same name — was not, and kept rendering a dropped instance as
// armed with the suite green. An enumeration in a comment is a claim about a
// population nobody measured; pkg/showaudit measures it now
// (TestSurfaceAnnotationCensusIsExact6534), so a fourth renderer cannot appear
// unannotated and cannot make this sentence wrong again without a red test.
//
// Until these copies are single-sourced the way pkg/natshow and
// pkg/dataplane/userspace/format already are, every one of them must consult
// this predicate: annotating some leaves the rest lying.
func PortMirroringInstanceExcludedReason(inst *PortMirrorInstance) string {
	if inst == nil {
		return ""
	}
	if inst.Output == "" {
		return "no output interface configured"
	}
	if inst.InputRate < 0 {
		return "negative input rate"
	}
	return ""
}
