package grpcapi

import (
	"strings"
	"testing"

	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #7357 §2: the gRPC twin of the CLI wiring binding. Both surfaces have to
// pass the applied verdicts, and #7357 §3's whole history is that an edit
// applied to one copy and not the other passes every test that looks at the
// other.
type mirrorExclGRPCDP struct {
	grpcRuntime
	excl []dpuserspace.MirrorExclusion
}

func (d mirrorExclGRPCDP) MirrorExclusions() []dpuserspace.MirrorExclusion { return d.excl }

func TestGRPCPortMirroringPassesAppliedExclusions7357(t *testing.T) {
	cfg := mirrorSurfaceConfig("ge-0/0/9.0", 100)

	// Control first: nothing reported, no runtime annotation.
	s := &Server{dp: mirrorExclGRPCDP{}}
	var base strings.Builder
	s.showForwardingOptionsPortMirroring(cfg, &base)
	if strings.Contains(base.String(), "has no ifindex") {
		t.Fatalf("a runtime annotation rendered with no exclusions reported:\n%s", base.String())
	}

	s = &Server{dp: mirrorExclGRPCDP{excl: []dpuserspace.MirrorExclusion{
		{Instance: "m1", Reason: "output interface ge-0/0/9.0 has no ifindex"},
	}}}
	var got strings.Builder
	s.showForwardingOptionsPortMirroring(cfg, &got)
	if !strings.Contains(got.String(), "NOT INSTALLED: output interface ge-0/0/9.0 has no ifindex") {
		t.Errorf("the gRPC surface did not pass the applied exclusions to the formatter — "+
			"the readback is wired but inert:\n%s", got.String())
	}

	// A backend without the capability reports nothing rather than panicking.
	s = &Server{}
	var none strings.Builder
	s.showForwardingOptionsPortMirroring(cfg, &none)
	if none.String() != base.String() {
		t.Errorf("a backend with no MirrorExclusions capability changed the render:\n%s", none.String())
	}
}
