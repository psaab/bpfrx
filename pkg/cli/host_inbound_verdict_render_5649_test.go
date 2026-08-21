package cli

import (
	"path/filepath"
	"strings"
	"testing"
)

// #5649 (C181-C20): a MATCHED to-zone junos-host fine policy still needs the
// coarse host-inbound-traffic admission gate named beside it — LocalDelivery
// evaluates BOTH (the fine policy action never overrides a coarse deny), and
// before this fix neither the local `show security match-policies` renderer
// nor the remote/`request` `test policy` renderer printed
// Result.HostInbound.Describe() for a MATCHED result; `test policy`'s
// HostInboundUnmatched branch didn't call it either (`show security
// match-policies` already did, #3627 B1a).
//
// hostInboundJunosHostStore builds a zone "trust" carrying a host-inbound-
// traffic ssh admission and a `to-zone junos-host` policy that separately
// permits the same tuple at the fine-policy layer, so a query against it is
// Matched=true (fine permit) AND res.HostInbound.Status ==
// HostInboundTokenAdmit (coarse ssh admit) simultaneously.
func hostInboundJunosHostStore(t *testing.T) *CLI {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
security {
    zones {
        security-zone trust {
            host-inbound-traffic {
                system-services { ssh; }
            }
        }
        security-zone untrust {
            host-inbound-traffic {
                system-services { ssh; }
            }
        }
    }
    policies {
        from-zone trust to-zone junos-host {
            policy allow-ssh {
                match { source-address any; destination-address any; application any; }
                then { permit; }
            }
        }
    }
}
`); err != nil {
		t.Fatalf("LoadOverride() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	return &CLI{store: store}
}

// TestShowMatchPoliciesMatchedHostInboundDescribe pins the local `show
// security match-policies` renderer (cli_show_security.go showMatchPolicies).
//
// FAIL-ON-REVERT: dropping the `if res.HostInbound != nil { ... Describe() }`
// block from the matched-verdict branch removes the "host-inbound-traffic"
// line, failing the Contains assertion below.
func TestShowMatchPoliciesMatchedHostInboundDescribe(t *testing.T) {
	c := hostInboundJunosHostStore(t)
	out := captureStdout(t, func() {
		if err := c.showMatchPolicies(c.store.ActiveConfig(), []string{
			"from-zone", "trust", "to-zone", "junos-host",
			"protocol", "tcp", "destination-port", "22",
		}); err != nil {
			t.Fatalf("showMatchPolicies() error = %v", err)
		}
	})
	if !strings.Contains(out, "Matching policy") {
		t.Fatalf("want a matched fine policy verdict, got: %s", out)
	}
	if !strings.Contains(out, "host-inbound-traffic") || !strings.Contains(out, "ssh") {
		t.Errorf("matched junos-host verdict missing the coarse host-inbound-traffic admission line (#5649); out = %s", out)
	}
}

// TestTestPolicyMatchedHostInboundDescribe covers the sibling remote/`request
// test policy` renderer (cli_request_testcmd.go testPolicy), which was
// missing Describe() on BOTH its HostInboundUnmatched and matched branches.
//
// FAIL-ON-REVERT: dropping either Describe() block reintroduces a matched (or
// unmatched) junos-host verdict with no host-inbound-traffic context.
func TestTestPolicyMatchedHostInboundDescribe(t *testing.T) {
	c := hostInboundJunosHostStore(t)
	out := captureStdout(t, func() {
		if err := c.testPolicy([]string{
			"from-zone", "trust", "to-zone", "junos-host",
			"protocol", "tcp", "destination-port", "22",
		}); err != nil {
			t.Fatalf("testPolicy() error = %v", err)
		}
	})
	if !strings.Contains(out, "Policy match") {
		t.Fatalf("want a matched fine policy verdict, got: %s", out)
	}
	if !strings.Contains(out, "Host-inbound:") || !strings.Contains(out, "ssh") {
		t.Errorf("matched junos-host verdict missing the coarse host-inbound-traffic admission line (#5649); out = %s", out)
	}
}

// TestTestPolicyUnmatchedHostInboundDescribe covers the HostInboundUnmatched
// branch of testPolicy: "untrust" carries the same ssh host-inbound-traffic
// admission as "trust" but has NO to-zone junos-host fine policy authored, so
// the verdict falls straight to the coarse gate.
func TestTestPolicyUnmatchedHostInboundDescribe(t *testing.T) {
	c := hostInboundJunosHostStore(t)
	out := captureStdout(t, func() {
		if err := c.testPolicy([]string{
			"from-zone", "untrust", "to-zone", "junos-host",
			"protocol", "tcp", "destination-port", "22",
		}); err != nil {
			t.Fatalf("testPolicy() error = %v", err)
		}
	})
	if !strings.Contains(out, "No matching to-zone junos-host policy") {
		t.Fatalf("want HostInboundUnmatched (no fine policy authored for untrust), got: %s", out)
	}
	if !strings.Contains(out, "host-inbound-traffic") || !strings.Contains(out, "ssh") {
		t.Errorf("unmatched junos-host verdict missing the host-inbound-traffic admission line (#5649); out = %s", out)
	}
}
