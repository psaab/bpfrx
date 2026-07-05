package config

import (
	"strings"
	"testing"
)

// #4288 (fable-review-167 I-1): VRRP authentication-type / authentication-key
// are parsed, stored on the VRRPGroup, and copied into the VRRP instance
// (pkg/vrrp/vrrp.go), but the packet build/receive path never enforces them —
// the native dataplane is RFC 5798 VRRPv3, which REMOVED authentication.
// Silently accepting the config lets an operator believe adverts are
// authenticated when they are not (a rogue host can hijack mastership). The
// honest posture is to REJECT the dead-security statement at strict commit and
// WARN (not brick) on the tolerant load / peer-sync path.

// Strict commit rejects authentication-type (flat-set shape). RED-on-revert:
// dropping the #4288 gate makes CompileConfig return nil (the inert auth config
// is silently accepted — the false-security posture).
func TestVRRPAuthenticationTypeRejectedFlatSet(t *testing.T) {
	tree := replaySetLines(t, []string{
		"set interfaces reth0 unit 0 family inet address 10.0.61.10/24 vrrp-group 1 virtual-address 10.0.61.1/24",
		"set interfaces reth0 unit 0 family inet address 10.0.61.10/24 vrrp-group 1 authentication-type md5",
		"set interfaces reth0 unit 0 family inet address 10.0.61.10/24 vrrp-group 1 authentication-key secret123",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig: expected rejection of VRRP authentication, got nil")
	}
	if !strings.Contains(err.Error(), "authentication") || !strings.Contains(err.Error(), "#4288") {
		t.Fatalf("unexpected error text: %v", err)
	}
}

const vrrpAuthHier = `interfaces {
    reth0 {
        unit 0 {
            family inet {
                address 10.0.61.10/24 {
                    vrrp-group 1 {
                        virtual-address 10.0.61.1/24;
                        priority 200;
                        authentication-type md5;
                        authentication-key secret123;
                    }
                }
            }
        }
    }
}`

// Strict commit rejects authentication in the hierarchical (braced) shape too.
func TestVRRPAuthenticationRejectedHierarchical(t *testing.T) {
	_, err := CompileConfig(parseHier(t, vrrpAuthHier))
	if err == nil {
		t.Fatal("CompileConfig: expected rejection of VRRP authentication (hier), got nil")
	}
	if !strings.Contains(err.Error(), "authentication") || !strings.Contains(err.Error(), "#4288") {
		t.Fatalf("unexpected error text: %v", err)
	}
}

// Lenient (load / peer-sync): the reject downgrades to a warning so an
// already-persisted or peer-synced config an older binary silently accepted
// still boots. RED-on-revert: without the gate there is no warning.
func TestVRRPAuthenticationLenientWarns(t *testing.T) {
	cfg, err := CompileConfigLenient(parseHier(t, vrrpAuthHier))
	if err != nil {
		t.Fatalf("CompileConfigLenient: VRRP auth must downgrade to a warning, got error: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "authentication") && strings.Contains(w, "#4288") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected a #4288 VRRP authentication warning on the lenient path, got: %v", cfg.Warnings)
	}
	// The config still boots — the vrrp-group is compiled (auth is simply inert).
	vg := firstVRRPGroupWithVIP(t, cfg, "10.0.61.1/24")
	if vg == nil {
		t.Fatal("lenient path: vrrp-group must still compile (boot, do not brick)")
	}
}

// authentication-key WITHOUT authentication-type is also rejected — either
// statement is the misleading dead-security config.
func TestVRRPAuthenticationKeyOnlyRejected(t *testing.T) {
	tree := replaySetLines(t, []string{
		"set interfaces reth0 unit 0 family inet address 10.0.61.10/24 vrrp-group 1 virtual-address 10.0.61.1/24",
		"set interfaces reth0 unit 0 family inet address 10.0.61.10/24 vrrp-group 1 authentication-key onlykey",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig: expected rejection of VRRP authentication-key, got nil")
	}
	if !strings.Contains(err.Error(), "authentication-key") || !strings.Contains(err.Error(), "#4288") {
		t.Fatalf("unexpected error text: %v", err)
	}
}

// A normal vrrp-group WITHOUT authentication commits cleanly — the gate must
// not over-reject legitimate VRRP configs.
func TestVRRPNoAuthenticationCommits(t *testing.T) {
	tree := replaySetLines(t, []string{
		"set interfaces reth0 unit 0 family inet address 10.0.61.10/24 vrrp-group 1 virtual-address 10.0.61.1/24",
		"set interfaces reth0 unit 0 family inet address 10.0.61.10/24 vrrp-group 1 priority 200",
		"set interfaces reth0 unit 0 family inet address 10.0.61.10/24 vrrp-group 1 preempt",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: a vrrp-group without authentication must commit cleanly, got: %v", err)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#4288") {
			t.Fatalf("unexpected #4288 warning on a vrrp-group without authentication: %q", w)
		}
	}
	if vg := firstVRRPGroupWithVIP(t, cfg, "10.0.61.1/24"); vg == nil {
		t.Fatal("expected the vrrp-group to compile")
	}
}
