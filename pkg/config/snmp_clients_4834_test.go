package config

import (
	"strings"
	"testing"
)

// TestSNMPClients_RestrictTypoRejected is the RED-on-revert guard for #4834.
//
// A mistyped "restrict" keyword (here "restric") detaches from the
// preceding broad prefix, so `0.0.0.0/0 restric` produces TWO client
// entries: an unrestricted `0.0.0.0/0` allow and an unparseable
// `restric` entry. Before the fix, compileClientNets silently dropped the
// unparseable "restric" entry and left `0.0.0.0/0` as a plain allow — a
// silent fail-open (the community becomes answerable from ANY source
// with no commit warning). The fix rejects the commit outright, naming
// the bad token, so the operator catches the typo before it can produce
// an unrestricted community.
func TestSNMPClients_RestrictTypoRejected(t *testing.T) {
	_, err := compileSNMPLines(t, []string{
		"set snmp community mon authorization read-only",
		"set snmp community mon clients 0.0.0.0/0 restric",
		"set snmp community mon clients 10.0.0.0/8",
	})
	if err == nil {
		t.Fatal("typoed 'restrict' keyword ('restric') compiled without error (#4834 fail-open regression)")
	}
	if !strings.Contains(err.Error(), "restric") {
		t.Fatalf("error %q does not name the offending token 'restric'", err)
	}
}

// TestSNMPClients_MalformedPrefixRejected pins the companion case: a plain
// prefix typo (not a "restrict" near-miss) is also rejected at commit,
// rather than being silently dropped from the allowlist.
func TestSNMPClients_MalformedPrefixRejected(t *testing.T) {
	_, err := compileSNMPLines(t, []string{
		"set snmp community mon authorization read-only",
		"set snmp community mon clients 10.0.0.0/99",
	})
	if err == nil {
		t.Fatal("malformed clients prefix '10.0.0.0/99' compiled without error")
	}
	if !strings.Contains(err.Error(), "10.0.0.0/99") {
		t.Fatalf("error %q does not name the offending prefix", err)
	}
}

// TestSNMPClients_RestrictTypoLenientWarns pins the no-brick contract
// (#1960 doctrine): the malformed token the STRICT path rejects is
// tolerated on the lenient load/peer-sync path, downgraded to a warning
// so an already-persisted config an older binary accepted still boots.
// compileClientNets keeps silently dropping the unparseable entry on this
// path, matching pre-#4834 runtime behavior exactly (the warning is the
// only new signal).
func TestSNMPClients_RestrictTypoLenientWarns(t *testing.T) {
	tree := &ConfigTree{}
	lines := []string{
		"set snmp community mon authorization read-only",
		"set snmp community mon clients 0.0.0.0/0 restric",
		"set snmp community mon clients 10.0.0.0/8",
	}
	for _, line := range lines {
		path, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient must not fail on a typoed clients token (brick-on-restart): %v", err)
	}
	if !hasWarningSubstr(cfg.Warnings, "restric") {
		t.Fatalf("expected a downgraded clients-token warning naming 'restric', warnings=%v", cfg.Warnings)
	}
}

// TestSNMPClients_ValidAccepted confirms the fix does not over-reject: a
// well-formed clients allowlist (CIDR, bare IP, correctly-spelled
// restrict) still compiles clean.
func TestSNMPClients_ValidAccepted(t *testing.T) {
	cfg, err := compileSNMPLines(t, []string{
		"set snmp community mon authorization read-only",
		"set snmp community mon clients 0.0.0.0/0 restrict",
		"set snmp community mon clients 10.0.0.0/8",
		"set snmp community mon clients 192.168.1.5",
	})
	if err != nil {
		t.Fatalf("valid clients allowlist failed to compile: %v", err)
	}
	comm := cfg.System.SNMP.Communities["mon"]
	if comm == nil {
		t.Fatal("community 'mon' missing from compiled config")
	}
	if len(comm.Clients) != 3 {
		t.Fatalf("expected 3 client entries, got %+v", comm.Clients)
	}
}
