package cli

import (
	"testing"

	"github.com/psaab/xpf/pkg/cmdtree"
)

// #2051: activate/deactivate must be offered as config-mode top-level commands
// and complete their path argument with schema parity to delete (paths to
// existing schema nodes), via the shared CompleteSetPathWithValues completer.

func TestConfigTopLevelOffersActivateDeactivate(t *testing.T) {
	for _, verb := range []string{"activate", "deactivate"} {
		if _, ok := cmdtree.ConfigTopLevel[verb]; !ok {
			t.Fatalf("cmdtree.ConfigTopLevel is missing %q", verb)
		}
	}
}

func TestCompleteConfig_DeactivatePathSchemaParity(t *testing.T) {
	c := newTypedLeafCLI(t)
	// `deactivate sys` must resolve to the same schema container `set sys`
	// would (here: system). Asserts deactivate routes through the schema
	// completer, not a dead path.
	cands := c.completeConfigWithDesc([]string{"deactivate"}, "sys")
	if !hasCand(cands, "system") {
		t.Fatalf("expected schema completion `system` for deactivate, got %v", candNames(cands))
	}
}

func TestCompleteConfig_ActivatePathSchemaParity(t *testing.T) {
	c := newTypedLeafCLI(t)
	cands := c.completeConfigWithDesc([]string{"activate"}, "sys")
	if !hasCand(cands, "system") {
		t.Fatalf("expected schema completion `system` for activate, got %v", candNames(cands))
	}
}
