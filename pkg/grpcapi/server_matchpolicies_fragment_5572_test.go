package grpcapi

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// fragMatchStore builds the #5572 fixture: a source-scoped `deny junos-https`
// (TCP/443) before `permit any`, so a non-first fragment overlapping the deny
// inherits it while a plain omitted-port packet permits.
func fragMatchStore(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
security {
    address-book {
        global {
            address trust-net 10.0.0.0/8;
        }
    }
    zones {
        security-zone trust;
        security-zone untrust;
    }
    policies {
        default-policy deny-all;
        from-zone trust to-zone untrust {
            policy block-https {
                match { source-address trust-net; destination-address any; application junos-https; }
                then { deny; }
            }
            policy permit-all {
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

// TestGRPCMatchPoliciesNonFirstFragment5572 pins the gRPC MatchPolicies plumbing
// of the #5572 non_first_fragment request field end to end (the remote `show
// security match-policies` path): the same tuple returns PERMIT as a normal
// packet but the enforcing DENY (with the advisory) when non_first_fragment is
// set.
func TestGRPCMatchPoliciesNonFirstFragment5572(t *testing.T) {
	s := &Server{store: fragMatchStore(t)}

	base := &pb.MatchPoliciesRequest{
		FromZone: "trust", ToZone: "untrust",
		SourceIp: "10.1.2.3", DestinationIp: "203.0.113.9",
		Protocol: "tcp",
	}

	// Normal packet: permit via permit-all.
	normal, err := s.MatchPolicies(context.Background(), base)
	if err != nil {
		t.Fatalf("MatchPolicies(normal) error = %v", err)
	}
	if !normal.Matched || normal.Action != "permit" || normal.PolicyName != "permit-all" {
		t.Fatalf("normal packet must permit via permit-all; got %+v", normal)
	}
	if normal.GetFragmentAssociatedDeny() {
		t.Fatalf("normal packet must not carry fragment_associated_deny; got %+v", normal)
	}

	// Fragment: inherit the overlapping port-bearing deny.
	fragReq := &pb.MatchPoliciesRequest{
		FromZone: "trust", ToZone: "untrust",
		SourceIp: "10.1.2.3", DestinationIp: "203.0.113.9",
		Protocol: "tcp", NonFirstFragment: true,
	}
	frag, err := s.MatchPolicies(context.Background(), fragReq)
	if err != nil {
		t.Fatalf("MatchPolicies(fragment) error = %v", err)
	}
	if !frag.Matched || frag.Action != "deny" || frag.PolicyName != "block-https" {
		t.Fatalf("non-first fragment must inherit block-https deny; got %+v", frag)
	}
	if !frag.GetFragmentAssociatedDeny() || frag.GetFragmentDenyNote() == "" {
		t.Fatalf("fragment deny must set the advisory fields; got %+v", frag)
	}
}
