package cmdtree

import (
	"sort"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	dpformat "github.com/psaab/xpf/pkg/dataplane/userspace/format"
)

// #6848: `show class-of-service rewrite-rule` operational-tree wiring.

// TestCoSRewriteRuleTypeChildrenMatchRenderer pins the two halves of a
// cross-package SSOT against each other.
//
// The `type` completion node lives in cmdtree; the set of type values the
// renderer actually filters on lives in format.CoSRewriteRuleTypes. Nothing
// structural keeps them in step — completion could offer a value the renderer
// silently ignores (the operator filters and gets everything), or a family
// could be renderable but uncompletable (the operator cannot find it). Both
// failures are quiet, so assert equality rather than trusting the two lists to
// be edited together.
func TestCoSRewriteRuleTypeChildrenMatchRenderer(t *testing.T) {
	node := operationalNode(t, "show", "class-of-service", "rewrite-rule", "type")

	got := make([]string, 0, len(node.Children))
	for name := range node.Children {
		got = append(got, name)
	}
	want := append([]string(nil), dpformat.CoSRewriteRuleTypes...)
	sort.Strings(got)
	sort.Strings(want)

	if len(got) != len(want) {
		t.Fatalf("cmdtree `type` children = %v, renderer types = %v; the completion "+
			"set and the filter set must be identical", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("cmdtree `type` children = %v, renderer types = %v", got, want)
		}
	}
}

// TestCoSRewriteRuleNameCompletionIncludesInertFamilies pins that completion
// offers rules from ALL four families.
//
// Completing only the enforced dscp rules would hide precisely the rules this
// command exists to surface: an operator who configured an inert ieee-802.1 /
// inet-precedence / exp rule could not tab to it, and so would never see that
// it is inert. The two name-only families are stored as slices rather than
// maps, which is exactly the shape a name-collection helper is most likely to
// forget.
func TestCoSRewriteRuleNameCompletionIncludesInertFamilies(t *testing.T) {
	cfg := &config.Config{ClassOfService: &config.ClassOfServiceConfig{
		DSCPRewriteRules:           map[string]*config.CoSDSCPRewriteRule{"rw-dscp": {Name: "rw-dscp"}},
		IEEE8021RewriteRules:       map[string]*config.CoSIEEE8021RewriteRule{"rw-pcp": {Name: "rw-pcp"}},
		INetPrecedenceRewriteRules: []string{"rw-prec"},
		EXPRewriteRules:            []string{"rw-exp"},
	}}

	node := operationalNode(t, "show", "class-of-service", "rewrite-rule")
	if node.DynamicFn == nil {
		t.Fatal("rewrite-rule node has no DynamicFn; rule names would not complete")
	}
	got := map[string]bool{}
	for _, n := range node.DynamicFn(cfg) {
		got[n] = true
	}
	for _, want := range []string{"rw-dscp", "rw-pcp", "rw-prec", "rw-exp"} {
		if !got[want] {
			t.Errorf("completion omitted rewrite rule %q (have %v); an inert rule the "+
				"operator cannot tab to is one they will never learn is inert", want, got)
		}
	}

	// The `name` filter child must offer the same set — a narrower list there
	// would make `... rewrite-rule name <TAB>` disagree with `... rewrite-rule <TAB>`.
	nameNode := operationalNode(t, "show", "class-of-service", "rewrite-rule", "name")
	if nameNode.DynamicFn == nil {
		t.Fatal("rewrite-rule name node has no DynamicFn")
	}
	if len(nameNode.DynamicFn(cfg)) != len(node.DynamicFn(cfg)) {
		t.Errorf("`rewrite-rule name` completion (%v) differs from `rewrite-rule` completion (%v)",
			nameNode.DynamicFn(cfg), node.DynamicFn(cfg))
	}
}

// TestCoSRewriteRuleNameCompletionNilSafe covers the pre-config / cold-boot
// call, where the completer runs before any config exists.
func TestCoSRewriteRuleNameCompletionNilSafe(t *testing.T) {
	node := operationalNode(t, "show", "class-of-service", "rewrite-rule")
	if got := node.DynamicFn(nil); len(got) != 0 {
		t.Errorf("nil config completion = %v, want empty", got)
	}
	if got := node.DynamicFn(&config.Config{}); len(got) != 0 {
		t.Errorf("config with no ClassOfService = %v, want empty", got)
	}
}

// operationalNode walks the operational tree to path, failing the test if any
// segment is missing.
func operationalNode(t *testing.T, path ...string) *Node {
	t.Helper()
	nodes := OperationalTree
	var node *Node
	for i, seg := range path {
		n, ok := nodes[seg]
		if !ok {
			t.Fatalf("operational tree has no node at %v (missing %q)", path[:i+1], seg)
		}
		node = n
		nodes = n.Children
	}
	return node
}
