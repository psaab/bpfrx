package config

import (
	"strings"
	"testing"
)

// #2461 — per-flow-server NetFlow v9 / IPFIX template cross-reference gate.
//
// A flow-server `version9 { template <name> }` (or the flat
// `version9-template <name>`) / `version-ipfix { template <name> }`
// reference to a template not defined under `services flow-monitoring` must
// be hard-rejected on commit / commit-check (the live exporter would
// otherwise silently use an arbitrary template), but downgraded to a warning
// on the tolerant load / peer-sync path so an already-persisted config still
// boots (#1960).

func flowMonV9OnlyDefinedSet() []string {
	return []string{
		"set services flow-monitoring version9 template good-tmpl flow-active-timeout 60",
	}
}

// TestFlowServerDanglingV9TemplateRejected: a flow-server referencing an
// undefined v9 template is hard-rejected at commit.
func TestFlowServerDanglingV9TemplateRejected(t *testing.T) {
	cmds := append(flowMonV9OnlyDefinedSet(),
		"set forwarding-options sampling instance s family inet output flow-server 10.0.0.1 version9 template missing-tmpl",
	)
	tree := buildTreeFromSet(t, cmds)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig accepted a flow-server referencing an undefined version9 template; expected rejection")
	}
	for _, want := range []string{"10.0.0.1", "missing-tmpl", "version9"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q", err.Error(), want)
		}
	}
}

// TestFlowServerDanglingIPFIXTemplateRejected: same for IPFIX.
func TestFlowServerDanglingIPFIXTemplateRejected(t *testing.T) {
	cmds := []string{
		"set services flow-monitoring version-ipfix template good-tmpl flow-active-timeout 60",
		"set forwarding-options sampling instance s family inet output flow-server 10.0.0.2 version-ipfix template nope-tmpl",
	}
	tree := buildTreeFromSet(t, cmds)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig accepted a flow-server referencing an undefined version-ipfix template; expected rejection")
	}
	for _, want := range []string{"10.0.0.2", "nope-tmpl", "version-ipfix"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q", err.Error(), want)
		}
	}
}

// TestFlowServerDefinedTemplateAccepted: a flow-server referencing a DEFINED
// template compiles cleanly (no over-gate).
func TestFlowServerDefinedTemplateAccepted(t *testing.T) {
	cmds := append(flowMonV9OnlyDefinedSet(),
		"set forwarding-options sampling instance s family inet output flow-server 10.0.0.1 version9 template good-tmpl",
	)
	tree := buildTreeFromSet(t, cmds)
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("CompileConfig rejected a flow-server referencing a DEFINED template: %v", err)
	}
}

// TestFlowServerNoTemplateRefAccepted: a flow-server with no per-server
// template reference compiles cleanly (the common single-template case).
func TestFlowServerNoTemplateRefAccepted(t *testing.T) {
	cmds := append(flowMonV9OnlyDefinedSet(),
		"set forwarding-options sampling instance s family inet output flow-server 10.0.0.1 port 2055",
	)
	tree := buildTreeFromSet(t, cmds)
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("CompileConfig rejected a flow-server with no template reference: %v", err)
	}
}

// TestFlowServerDanglingTemplateLenientWarns: on the tolerant load /
// peer-sync path the dangling reference is downgraded to a warning so the
// config still boots (#1960).
func TestFlowServerDanglingTemplateLenientWarns(t *testing.T) {
	cmds := append(flowMonV9OnlyDefinedSet(),
		"set forwarding-options sampling instance s family inet output flow-server 10.0.0.1 version9 template missing-tmpl",
	)
	tree := buildTreeFromSet(t, cmds)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient must NOT hard-reject a dangling flow-server template ref: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "flow-server template reference") && strings.Contains(w, "missing-tmpl") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("lenient compile must emit a downgraded warning for the dangling ref; warnings=%v", cfg.Warnings)
	}
}
