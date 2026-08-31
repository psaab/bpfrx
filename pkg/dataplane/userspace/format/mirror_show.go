package format

// #7357: the single source for `show forwarding-options port-mirroring`.
//
// The CLI (`pkg/cli/show_services_mirror.go`) and the gRPC text surface
// (`pkg/grpcapi/server_show_forwarding.go`) rendered this from two
// byte-identical copies with no shared formatter. That duplication is not
// theoretical debt — it has already cost twice:
//
//   - #6534 had to add the `NOT INSTALLED` annotation to BOTH, and test both,
//     because annotating one leaves the other lying. The in-code comment on
//     the gRPC copy said so in as many words.
//   - #7357 had to fix the nondeterministic instance order in BOTH.
//
// Every future edit paid the same tax and could silently pay only half of it.
// Following the `pkg/natshow` (#1687) and CoS `dpformat` precedent, the render
// now lives here once and both surfaces print what it returns.

import (
	"fmt"
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// FormatPortMirroring renders `show forwarding-options port-mirroring`.
//
// Output is byte-identical to what both call sites produced before, including
// the trailing blank line after each instance — the parity test asserts the
// two surfaces agree, so a change here must move both together by construction.
func FormatPortMirroring(cfg *config.Config) string {
	if cfg == nil {
		return "No port-mirroring instances configured\n"
	}
	// ForwardingOptions is a VALUE, not a pointer — the nil check the two call
	// sites made was on PortMirroring, which is the pointer.
	pm := cfg.ForwardingOptions.PortMirroring
	if pm == nil || len(pm.Instances) == 0 {
		return "No port-mirroring instances configured\n"
	}

	names := make([]string, 0, len(pm.Instances))
	for name := range pm.Instances {
		names = append(names, name)
	}
	// #7357/#8166: a stable order. Ranging the map directly listed instances
	// differently on successive runs of the same command.
	sort.Strings(names)

	var b strings.Builder
	for _, name := range names {
		inst := pm.Instances[name]
		fmt.Fprintf(&b, "Instance: %s\n", name)
		if inst.InputRate > 0 {
			fmt.Fprintf(&b, "  Input rate: 1/%d\n", inst.InputRate)
		} else {
			b.WriteString("  Input rate: all packets\n")
		}
		if len(inst.Input) > 0 {
			fmt.Fprintf(&b, "  Input interfaces: %s\n", strings.Join(inst.Input, ", "))
		}
		if inst.Output != "" {
			fmt.Fprintf(&b, "  Output interface: %s\n", inst.Output)
		}
		// #6534: the builder DROPS such an instance, so nothing above is in
		// effect. Sharpest for a negative input rate, which the branch above
		// renders as the maximally permissive "all packets" while the
		// dataplane mirrors nothing at all. Verdict shared with
		// buildMirrorSnapshots so the two cannot disagree.
		if reason := config.PortMirroringInstanceExcludedReason(inst); reason != "" {
			fmt.Fprintf(&b, "  NOT INSTALLED: %s\n", reason)
		}
		b.WriteString("\n")
	}
	return b.String()
}
