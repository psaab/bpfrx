package cli

import (
	"strings"
	"testing"

	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #7357 §2: the SURFACE must actually pass the applied verdicts to the
// formatter.
//
// The formatter tests prove the annotation renders when it is HANDED
// exclusions; none of them can see a call site that passes nil. That is
// precisely the failure mode of this change — the readback landing inert while
// every unit test around it stays green — so the wiring gets its own binding.
type mirrorExclDP struct {
	cliRuntime
	excl []dpuserspace.MirrorExclusion
}

func (d mirrorExclDP) MirrorExclusions() []dpuserspace.MirrorExclusion { return d.excl }

func TestCLIPortMirroringPassesAppliedExclusions7357(t *testing.T) {
	c := &CLI{store: mirrorSurfaceCLIStore(t)}

	// Control FIRST: a backend reporting nothing must produce no runtime
	// annotation. Without it, "the annotation appears" is satisfied by a
	// renderer that always prints one.
	c.dp = mirrorExclDP{}
	base := captureStdout(t, func() { _ = c.showPortMirroring() })
	if strings.Contains(base, "has no ifindex") {
		t.Fatalf("a runtime annotation rendered with no exclusions reported:\n%s", base)
	}

	c.dp = mirrorExclDP{excl: []dpuserspace.MirrorExclusion{
		{Instance: "armed", Reason: "output interface ge-0/0/9.0 has no ifindex"},
	}}
	out := captureStdout(t, func() { _ = c.showPortMirroring() })
	if !strings.Contains(out, "NOT INSTALLED: output interface ge-0/0/9.0 has no ifindex") {
		t.Errorf("the CLI surface did not pass the applied exclusions to the formatter — "+
			"the readback is wired but inert:\n%s", out)
	}

	// A backend WITHOUT the capability must not panic or invent a verdict:
	// the retained BPF shim has no snapshot builder and reports nothing.
	c.dp = nil
	if got := captureStdout(t, func() { _ = c.showPortMirroring() }); got != base {
		t.Errorf("a backend with no MirrorExclusions capability changed the render:\n%s", got)
	}
}
