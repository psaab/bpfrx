package cmdtree

import (
	"testing"
)

// #5196 (A3-b1-F3): the completion walker used to gate every dynamic
// provider behind `cfg != nil`, so config-independent providers that
// intentionally supply defaults for a nil active config were suppressed.
// A nil active config is a real operator state (fresh boot before the
// first commit, compile-failure recovery), and the shared providers are
// nil-safe by contract (every DynamicFn / ContextDynamicFn either guards
// `cfg == nil` or ignores cfg). These tests drive the real completers
// with a nil config; restoring the `&& cfg != nil` caller gate makes the
// config-independent providers return nothing (RED on revert).

func TestRouteTableCompletionNilConfigOffersMainTables(t *testing.T) {
	// `show route table` DynamicFn returns the built-in main tables even
	// for a nil config (per-instance tables are appended only when a
	// config is present). The walker must still invoke it.
	cands := CompleteFromTree(OperationalTree, []string{"show", "route", "table"}, "", nil)
	for _, want := range []string{"inet.0", "inet6.0"} {
		if !contains(cands, want) {
			t.Fatalf("show route table (nil cfg): expected %q, got %v", want, cands)
		}
	}
}

func TestRouteProtocolCompletionNilConfigOffersProtocols(t *testing.T) {
	// `show route protocol` DynamicFn ignores cfg entirely and returns a
	// static protocol list; it must survive a nil config.
	cands := CompleteFromTree(OperationalTree, []string{"show", "route", "protocol"}, "", nil)
	for _, want := range []string{"static", "ospf", "bgp"} {
		if !contains(cands, want) {
			t.Fatalf("show route protocol (nil cfg): expected %q, got %v", want, cands)
		}
	}
}

func TestRouteTableCompletionNilConfigWithPrefix(t *testing.T) {
	// Partial-prefix completion must also reach the nil-config provider.
	cands := CompleteFromTree(OperationalTree, []string{"show", "route", "table"}, "inet6", nil)
	if !contains(cands, "inet6.0") {
		t.Fatalf("show route table inet6 (nil cfg): expected inet6.0, got %v", cands)
	}
	if contains(cands, "inet.0") {
		t.Fatalf("show route table inet6 (nil cfg): inet.0 should be filtered by prefix, got %v", cands)
	}
}

func TestRouteTableCompletionWithDescNilConfig(t *testing.T) {
	// The description-bearing walker (`?` help surface) must also invoke
	// nil-config-aware providers.
	cands := CompleteFromTreeWithDesc(OperationalTree, []string{"show", "route", "table"}, "", nil)
	var names []string
	for _, c := range cands {
		names = append(names, c.Name)
	}
	for _, want := range []string{"inet.0", "inet6.0"} {
		if !contains(names, want) {
			t.Fatalf("show route table (nil cfg, desc): expected %q, got %v", want, names)
		}
	}
}
