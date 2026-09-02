package cli

import (
	"fmt"

	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	dpformat "github.com/psaab/xpf/pkg/dataplane/userspace/format"
)

// showPortMirroring displays port mirroring (SPAN) configuration.
//
// #7357: the render lives in dpformat.FormatPortMirroring, shared with the
// gRPC text surface. These two were byte-identical copies with no shared
// formatter, which had already cost #6534 (annotate both, test both) and
// #8166 (fix the instance order in both) — each an edit that could silently
// be applied to only one.
func (c *CLI) showPortMirroring() error {
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("No active configuration")
		return nil
	}
	fmt.Print(dpformat.FormatPortMirroring(cfg, c.mirrorExclusions()))
	return nil
}

// mirrorExclusions reads the #7357 §2 runtime verdicts off the applied
// snapshot, or nil when the backend keeps none.
//
// Capability assertion rather than a method on cliRuntime: a backend without a
// snapshot builder would need a stub returning nil, and a stub returning nil is
// indistinguishable from "nothing was excluded" — which is exactly the lie this
// issue exists to stop. Absent stays absent.
func (c *CLI) mirrorExclusions() []dpuserspace.MirrorExclusion {
	// Through dpProbe(), NOT the stored dp field. #2114: under the live
	// indirection the field holds a wrapper, so a type assertion on it
	// answers "capability absent" for a HEALTHY backend that implements the
	// method — which here would render an armed instance as un-annotated,
	// the exact lie this change exists to stop.
	// TestOptionalCapabilityProbesUseDPProbe is the canary; it caught this.
	if m, ok := c.dpProbe().(interface {
		MirrorExclusions() []dpuserspace.MirrorExclusion
	}); ok {
		return m.MirrorExclusions()
	}
	return nil
}
