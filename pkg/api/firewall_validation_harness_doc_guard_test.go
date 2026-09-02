package api

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestFirewallValidationHarnessDocGuard binds docs/firewall-validation-harness-design.md
// to the codebase so the design specification cannot silently drift from live runtime invariants.
func TestFirewallValidationHarnessDocGuard(t *testing.T) {
	root := filepath.Join("..", "..")

	// 1. Doc must exist and be cited in docs/README.md
	docRel := filepath.Join("docs", "firewall-validation-harness-design.md")
	docPath := filepath.Join(root, docRel)
	docBytes, err := os.ReadFile(docPath)
	if err != nil {
		t.Fatalf("design doc %s missing: %v", docPath, err)
	}
	doc := string(docBytes)

	readmeBytes, err := os.ReadFile(filepath.Join(root, "docs", "README.md"))
	if err != nil {
		t.Fatalf("docs/README.md missing: %v", err)
	}
	if !strings.Contains(string(readmeBytes), "firewall-validation-harness-design.md") {
		t.Errorf("docs/README.md must cite %s", docRel)
	}

	// 2. Required anchors in the design doc
	requiredAnchors := []string{
		"#68 Fail-Closed Mandate",
		"Clustering Cold-Boot Overlap",
		"DEFAULT_MAX_SESSIONS = 131,072",
		"UmemInflightFrames",
		"/tmp/xpf-cluster.lock",
		"The Positive-Evidence Precondition",
		"Exit `77`",
		"Gate 1: Out-of-Process On-Wire Properties",
		"Gate 2: Two-Plane Observability Parity",
		"Gate 3: Live Link Carrier Flap Recovery",
		"Gate 4: Single-IP NAT Port Exhaustion Under Load",
		"Gate 5: Owed Connection-Rate Benchmark",
	}
	for _, anchor := range requiredAnchors {
		if !strings.Contains(doc, anchor) {
			t.Errorf("design doc missing required anchor %q", anchor)
		}
	}

	// 3. Bind claim: DEFAULT_MAX_SESSIONS must match Rust session constant (131072)
	sessionModPath := filepath.Join(root, "userspace-dp", "src", "session", "mod.rs")
	sessionBytes, err := os.ReadFile(sessionModPath)
	if err != nil {
		t.Fatalf("cannot read %s: %v", sessionModPath, err)
	}
	const expectedMaxSessions = 131072
	needle := "const DEFAULT_MAX_SESSIONS: usize = " + strconv.Itoa(expectedMaxSessions) + ";"
	if !strings.Contains(string(sessionBytes), needle) {
		t.Errorf("%s does not define %q", sessionModPath, needle)
	}

	// 4. Bind claim: Buffer model field UmemInflightFrames exists in protocol_binding.go
	bindingPath := filepath.Join(root, "pkg", "dataplane", "userspace", "protocol_binding.go")
	bindingBytes, err := os.ReadFile(bindingPath)
	if err != nil {
		t.Fatalf("cannot read %s: %v", bindingPath, err)
	}
	if !strings.Contains(string(bindingBytes), "UmemInflightFrames") {
		t.Errorf("%s missing UmemInflightFrames field", bindingPath)
	}

	// 5. Bind claim: Cluster lock path is /tmp/xpf-cluster.lock
	lockScriptPath := filepath.Join(root, "test", "incus", "cluster-lock.sh")
	lockBytes, err := os.ReadFile(lockScriptPath)
	if err != nil {
		t.Fatalf("cannot read %s: %v", lockScriptPath, err)
	}
	if !strings.Contains(string(lockBytes), "/tmp/xpf-cluster.lock") {
		t.Errorf("%s missing default lock path /tmp/xpf-cluster.lock", lockScriptPath)
	}

	// 6. Bind claim: Interface rename pattern is ge-0-0-
	linksetupPath := filepath.Join(root, "pkg", "daemon", "linksetup.go")
	linksetupBytes, err := os.ReadFile(linksetupPath)
	if err != nil {
		t.Fatalf("cannot read %s: %v", linksetupPath, err)
	}
	if !strings.Contains(string(linksetupBytes), "ge-0-0-") {
		t.Errorf("%s missing ge-0-0- renaming pattern", linksetupPath)
	}
}
