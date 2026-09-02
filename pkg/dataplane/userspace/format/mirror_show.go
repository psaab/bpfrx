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
	userspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// FormatPortMirroring renders `show forwarding-options port-mirroring`.
//
// Output is byte-identical to what both call sites produced before, including
// the trailing blank line after each instance — the parity test asserts the
// two surfaces agree, so a change here must move both together by construction.
//
// #7357 §2: `excluded` carries the runtime verdicts the snapshot builder
// reached at APPLY time — the three drops that depend on the interface table
// (output ifindex unresolved, input ifindex unresolved, ingress already
// mirrored) and which a config-only renderer cannot evaluate. Pass nil when
// the applied snapshot is unavailable; the render then degrades to the
// config-only annotation rather than claiming anything it does not know.
//
// Annotated at the granularity the drop OCCURRED at. An instance-level
// exclusion suppresses the whole instance; an input-level one marks that input
// and leaves the rest of the instance rendering normally, because an instance
// with one claimed input is PARTIALLY installed and a whole-instance
// NOT INSTALLED would lie in the other direction.
func FormatPortMirroring(cfg *config.Config, excluded []userspace.MirrorExclusion) string {
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

	// Index the applied verdicts. Instance-level and input-level are kept
	// apart on purpose — see the granularity note above.
	instExcluded := map[string]string{}
	inputExcluded := map[string]map[string]string{}
	for _, e := range excluded {
		if e.Input == "" {
			instExcluded[e.Instance] = e.Reason
			continue
		}
		if inputExcluded[e.Instance] == nil {
			inputExcluded[e.Instance] = map[string]string{}
		}
		inputExcluded[e.Instance][e.Input] = e.Reason
	}

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
			// The joined one-line form is preserved EXACTLY when nothing about
			// this instance's inputs was excluded, so the common case stays
			// byte-identical to the pre-#7357 output. Only an instance with a
			// dropped input expands to one line per input, which is where the
			// operator needs to see WHICH input and why.
			if len(inputExcluded[name]) == 0 {
				fmt.Fprintf(&b, "  Input interfaces: %s\n", strings.Join(inst.Input, ", "))
			} else {
				b.WriteString("  Input interfaces:\n")
				for _, in := range inst.Input {
					if reason := inputExcluded[name][in]; reason != "" {
						fmt.Fprintf(&b, "    %s  [NOT INSTALLED: %s]\n", in, reason)
					} else {
						fmt.Fprintf(&b, "    %s\n", in)
					}
				}
			}
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
		} else if reason := instExcluded[name]; reason != "" {
			// #7357 §2: a runtime drop the config predicate cannot see. Only
			// reached when the config predicate did NOT fire, so an instance
			// excluded for both reasons prints one line, not two.
			fmt.Fprintf(&b, "  NOT INSTALLED: %s\n", reason)
		}
		b.WriteString("\n")
	}
	return b.String()
}
