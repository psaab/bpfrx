package grpcapi

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// srcPortPolicyStore builds a committed store whose only permit policy uses a
// source-port-constrained application (tcp, source-port 5000, destination-port
// 80) with a deny-all default, so a verdict requires BOTH ports to match.
func srcPortPolicyStore(t *testing.T) *Server {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
applications {
    application srcport-app {
        protocol tcp;
        source-port 5000;
        destination-port 80;
    }
}
security {
    policies {
        default-policy deny-all;
        from-zone trust to-zone untrust {
            policy allow-srcport {
                match { source-address any; destination-address any; application srcport-app; }
                then { permit; }
            }
        }
    }
    zones {
        security-zone trust;
        security-zone untrust;
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

// TestShowTestPolicySourcePort asserts the #3107 contract on the ShowText
// "test-policy:" simulator (the operational `test policy` served via gRPC, the
// remote `cli` backend): the `srcport=` topic key threads into
// policymatch.Query.SrcPort, so the verdict reflects a source-port-constrained
// policy.
//
// FAIL-ON-REVERT: dropping the srcport parse / the SrcPort field on the Query
// makes SrcPort always 0 ("any port"), so the wrong-port case would PERMIT
// (overmatch) and "wrong src port" flips red.
func TestShowTestPolicySourcePort(t *testing.T) {
	s := srcPortPolicyStore(t)

	cases := []struct {
		name      string
		topic     string
		wantMatch bool
	}{
		{"correct src port", "test-policy:from=trust,to=untrust,proto=tcp,srcport=5000,port=80", true},
		{"wrong src port", "test-policy:from=trust,to=untrust,proto=tcp,srcport=6000,port=80", false},
		{"absent src port", "test-policy:from=trust,to=untrust,proto=tcp,port=80", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: tc.topic})
			if err != nil {
				t.Fatalf("ShowText(%q) error = %v", tc.topic, err)
			}
			matched := strings.Contains(resp.Output, "Policy match")
			if matched != tc.wantMatch {
				t.Fatalf("ShowText(%q) matched = %v, want %v\noutput: %q", tc.topic, matched, tc.wantMatch, resp.Output)
			}
		})
	}
}

// TestShowTestPolicyRejectsInvalidSourcePort asserts a malformed/out-of-range
// srcport surfaces an "invalid source-port" diagnostic (#3116 validation) and
// must NOT produce a "Policy match" line.
//
// FAIL-ON-REVERT: replacing the ParsePort call with a silent coercion makes
// "abc"/"70000" become 0 with no diagnostic, flipping the want-bad cases red.
func TestShowTestPolicyRejectsInvalidSourcePort(t *testing.T) {
	s := srcPortPolicyStore(t)

	cases := []struct {
		name    string
		topic   string
		wantBad bool
	}{
		{"malformed", "test-policy:from=trust,to=untrust,srcport=abc", true},
		{"out of range", "test-policy:from=trust,to=untrust,srcport=70000", true},
		{"valid", "test-policy:from=trust,to=untrust,proto=tcp,srcport=5000,port=80", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: tc.topic})
			if err != nil {
				t.Fatalf("ShowText(%q) error = %v", tc.topic, err)
			}
			if tc.wantBad {
				if !strings.Contains(resp.Output, "invalid source-port") {
					t.Fatalf("%s: output = %q, want an invalid source-port diagnostic", tc.name, resp.Output)
				}
				if strings.Contains(resp.Output, "Policy match") {
					t.Fatalf("%s: invalid source-port produced a policy match (silent wildcard): %q", tc.name, resp.Output)
				}
			}
		})
	}
}
