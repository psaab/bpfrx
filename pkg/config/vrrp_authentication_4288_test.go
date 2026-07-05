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

// SECURITY (Copilot fable-167 review): the reject error / lenient warning must
// NOT echo the authentication-key VALUE (it is a secret). In the Keys-packed
// hierarchical leaf spelling `vrrp-group 1 authentication-key <secret>;` the
// value rides on the vrrp-group node's Keys run, so a message built from the
// full Keys would leak it into logs + CLI. The message must carry only the
// group IDENTITY (`vrrp-group 1`). RED-on-revert: building the path from n.Keys
// puts the secret into the error string.
const vrrpAuthSecret = "SUPERSECRETVRRPKEY"

func TestVRRPAuthenticationRejectDoesNotLeakSecret_KeysPacked(t *testing.T) {
	// Hierarchical leaf form packs the value onto the vrrp-group node's Keys.
	tree := parseHier(t, `interfaces {
    reth0 {
        unit 0 {
            family inet {
                address 10.0.61.10/24 {
                    vrrp-group 1 authentication-key `+vrrpAuthSecret+`;
                }
            }
        }
    }
}`)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("expected rejection of Keys-packed VRRP authentication-key, got nil")
	}
	if strings.Contains(err.Error(), vrrpAuthSecret) {
		t.Fatalf("reject error LEAKED the authentication-key secret: %v", err)
	}
	// It must still identify the offending group without any leaf value.
	if !strings.Contains(err.Error(), "vrrp-group 1") || !strings.Contains(err.Error(), "#4288") {
		t.Fatalf("reject error must name the group identity + #4288, got: %v", err)
	}
}

func TestVRRPAuthenticationRejectDoesNotLeakSecret_FlatSet(t *testing.T) {
	tree := replaySetLines(t, []string{
		"set interfaces reth0 unit 0 family inet address 10.0.61.10/24 vrrp-group 1 virtual-address 10.0.61.1/24",
		"set interfaces reth0 unit 0 family inet address 10.0.61.10/24 vrrp-group 1 authentication-key " + vrrpAuthSecret,
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("expected rejection of flat-set VRRP authentication-key, got nil")
	}
	if strings.Contains(err.Error(), vrrpAuthSecret) {
		t.Fatalf("reject error LEAKED the authentication-key secret: %v", err)
	}
	if !strings.Contains(err.Error(), "vrrp-group 1") || !strings.Contains(err.Error(), "#4288") {
		t.Fatalf("reject error must name the group identity + #4288, got: %v", err)
	}
}

// The lenient warning must also be value-free.
func TestVRRPAuthenticationWarnDoesNotLeakSecret_KeysPacked(t *testing.T) {
	tree := parseHier(t, `interfaces {
    reth0 {
        unit 0 {
            family inet {
                address 10.0.61.10/24 {
                    vrrp-group 1 authentication-key `+vrrpAuthSecret+`;
                }
            }
        }
    }
}`)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	sawWarn := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#4288") {
			sawWarn = true
			if strings.Contains(w, vrrpAuthSecret) {
				t.Fatalf("lenient warning LEAKED the authentication-key secret: %q", w)
			}
		}
	}
	if !sawWarn {
		t.Fatalf("expected a #4288 lenient warning, got: %v", cfg.Warnings)
	}
}
