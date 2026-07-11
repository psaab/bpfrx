package grpcapi

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// fragTextPolicyStore builds the #5572 fixture for the gRPC ShowText
// "test-policy:" bridge (the remote `test policy` backend): a source-scoped
// `deny junos-https` before `permit any`.
func fragTextPolicyStore(t *testing.T) *Server {
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
	return &Server{store: store}
}

// TestShowTestPolicyNonFirstFragment5572 pins the ShowText "test-policy:"
// `frag=1` plumbing (the remote CLI `test policy` path): the same tuple permits
// as a normal packet but reports the enforcing DENY plus the advisory when
// frag=1 is supplied.
//
// FAIL-ON-REVERT: dropping the `frag` case / the NonFirstFragment field on the
// Query makes the fragment topic evaluate as a plain port-0 packet, so the
// verdict falls through to permit-all and the want-deny assertion fails.
func TestShowTestPolicyNonFirstFragment5572(t *testing.T) {
	s := fragTextPolicyStore(t)

	normalTopic := "test-policy:from=trust,to=untrust,src=10.1.2.3,dst=203.0.113.9,proto=tcp"
	normal, err := s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: normalTopic})
	if err != nil {
		t.Fatalf("ShowText(normal) error = %v", err)
	}
	if !strings.Contains(normal.Output, "permit-all") {
		t.Fatalf("normal packet must permit via permit-all; output: %q", normal.Output)
	}

	fragTopic := normalTopic + ",frag=1"
	frag, err := s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: fragTopic})
	if err != nil {
		t.Fatalf("ShowText(fragment) error = %v", err)
	}
	if !strings.Contains(frag.Output, "block-https") || !strings.Contains(frag.Output, "deny") {
		t.Fatalf("non-first fragment must report the block-https deny; output: %q", frag.Output)
	}
	if !strings.Contains(frag.Output, "fragment-associated deny advisory:") {
		t.Fatalf("fragment deny must render the advisory; output: %q", frag.Output)
	}
}

// TestShowTestPolicyRejectsInvalidFrag5572 pins the fail-closed parse: a
// non-canonical frag value is a reported error, not a silent normal-packet
// query.
func TestShowTestPolicyRejectsInvalidFrag5572(t *testing.T) {
	s := fragTextPolicyStore(t)
	resp, err := s.ShowText(context.Background(),
		&pb.ShowTextRequest{Topic: "test-policy:from=trust,to=untrust,frag=maybe"})
	if err != nil {
		t.Fatalf("ShowText error = %v", err)
	}
	if !strings.Contains(resp.Output, "invalid frag") {
		t.Fatalf("malformed frag must report an error; output: %q", resp.Output)
	}
}
