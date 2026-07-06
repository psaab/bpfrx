package config

import (
	"strings"
	"testing"
)

// #4107 PR-A: the chassis cluster control-channel PSK (authentication-key)
// compiles into a Secret and is redacted on every render path.

func TestClusterAuthKeyCompilesToSecret(t *testing.T) {
	tree := buildTree(t, []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster node 0",
		"set chassis cluster authentication-key SUPER-SECRET-PSK-4107",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if cfg.Chassis.Cluster == nil {
		t.Fatal("chassis cluster not compiled")
	}
	if got := cfg.Chassis.Cluster.ControlLinkAuthKey.Reveal(); got != "SUPER-SECRET-PSK-4107" {
		t.Fatalf("ControlLinkAuthKey = %q, want cleartext PSK via Reveal()", got)
	}
	// The Secret String() must redact, so %v/%s/slog never leak it.
	if s := cfg.Chassis.Cluster.ControlLinkAuthKey.String(); strings.Contains(s, "SUPER-SECRET-PSK-4107") {
		t.Fatalf("Secret.String() leaked the PSK: %q", s)
	}
}

func TestClusterAuthKeyAbsentIsEmpty(t *testing.T) {
	tree := buildTree(t, []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster node 0",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if got := cfg.Chassis.Cluster.ControlLinkAuthKey.Reveal(); got != "" {
		t.Fatalf("absent authentication-key must compile empty, got %q", got)
	}
}

// TestClusterAuthKeyRedactedInASTRender proves the value token is masked as
// ##SECRET-DATA## in the raw-AST display paths (the leaf keyword is
// authentication-key, already in secretIndices). RED on revert if the
// authentication-key redaction ever regresses for the cluster path.
func TestClusterAuthKeyRedactedInASTRender(t *testing.T) {
	tree := buildTree(t, []string{
		"set chassis cluster authentication-key LEAK-CLUSTER-PSK-4107",
	})
	red := tree.RedactedClone()
	renders := map[string]string{
		"Format":    red.Format(),
		"FormatSet": red.FormatSet(),
		"FormatXML": red.FormatXML(),
	}
	for name, out := range renders {
		if strings.Contains(out, "LEAK-CLUSTER-PSK-4107") {
			t.Errorf("%s leaked the cluster PSK cleartext:\n%s", name, out)
		}
		if !strings.Contains(out, SecretDataPlaceholder) {
			t.Errorf("%s did not mask the cluster PSK with %s:\n%s", name, SecretDataPlaceholder, out)
		}
	}
	// The live tree must still carry cleartext (config-sync / persistence SSOT).
	if !strings.Contains(tree.FormatSet(), "LEAK-CLUSTER-PSK-4107") {
		t.Error("RedactedClone mutated the source tree — config-sync would lose the PSK")
	}
}
