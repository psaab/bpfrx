package grpcapi

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #3670: the structured GetPolicies RPC synthesizes a "-"/"-" default-policy
// catch-all row (#3363), but that row omitted the implicit default-policy's own
// RT_FLOW log state (default-policy-log session-init | session-close, compiled
// to Security.DefaultPolicyLogSessionInit/Close and threaded to the dataplane
// via ConfigSnapshot.DefaultLogSessionInit/Close in the #3534 builder). Every
// configured rule sets Log/LogSessionInit/LogSessionClose (#3336); the default
// row did not, so structured automation read the most security-relevant
// boundary as UNLOGGED while the dataplane emitted the records.
//
// RED-on-revert: drop the log-field population on the synthetic defRule and the
// assertions below fail (GetLog false, GetLogSessionInit/Close false).

func defaultPolicyLogGRPCStore(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
security {
    zones {
        security-zone trust;
        security-zone untrust;
    }
    policies {
        // #7422 row 13: the default verdict is now PERMIT-ALL, and that is
        // load-bearing rather than incidental. The session-init/session-close
        // records fire only for a default-PERMIT (the only verdict that
        // installs a session), so under the previous implicit deny-all these
        // flags were accepted-but-inert (#3534) and the row below asserted a
        // log posture the dataplane never enforced. #3670's property — audit
        // tooling must not read the boundary as unlogged while the dataplane
        // IS emitting — is preserved exactly, on the config where it is true.
        // The deny-all suppression is covered by
        // TestDefaultPolicyLogSuppressedUnderDenyDefault7422.
        default-policy {
            permit-all;
        }
        default-policy-log {
            session-init;
            session-close;
        }
        from-zone trust to-zone untrust {
            policy allow-first {
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
	return store
}

func TestGetPoliciesDefaultPolicyRowExposesLogState(t *testing.T) {
	store := defaultPolicyLogGRPCStore(t)

	// Sanity: the compiled config carries both default-policy log modes.
	cfg := store.ActiveConfig()
	if cfg == nil {
		t.Fatal("ActiveConfig() = nil")
	}
	if !cfg.Security.DefaultPolicyLogSessionInit || !cfg.Security.DefaultPolicyLogSessionClose {
		t.Fatalf("fixture no longer sets both default-policy log modes: init=%v close=%v",
			cfg.Security.DefaultPolicyLogSessionInit, cfg.Security.DefaultPolicyLogSessionClose)
	}

	s := &Server{store: store}
	resp, err := s.GetPolicies(context.Background(), &pb.GetPoliciesRequest{})
	if err != nil {
		t.Fatalf("GetPolicies() error = %v", err)
	}

	var defRule *pb.PolicyRule
	for _, pi := range resp.GetPolicies() {
		for _, r := range pi.GetRules() {
			if r.GetName() == dataplane.DefaultPolicyName {
				defRule = r
			}
		}
	}
	if defRule == nil {
		t.Fatalf("GetPolicies() missing synthetic default-policy row (Name=%q)",
			dataplane.DefaultPolicyName)
	}

	if !defRule.GetLog() {
		t.Fatalf("default-policy row Log=false, want true (#3670 regression: the " +
			"synthetic row does not reflect the configured default-policy-log intent)")
	}
	if !defRule.GetLogSessionInit() {
		t.Fatalf("default-policy row LogSessionInit=false, want true (#3670 regression)")
	}
	if !defRule.GetLogSessionClose() {
		t.Fatalf("default-policy row LogSessionClose=false, want true (#3670 regression)")
	}
}
