package cli

import (
	"fmt"

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
	fmt.Print(dpformat.FormatPortMirroring(cfg))
	return nil
}
