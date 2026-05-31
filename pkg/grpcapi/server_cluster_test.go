package grpcapi

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// matchPoliciesTestStore builds a config with a single trust->untrust
// policy whose source/destination terms reference a RESTRICTED
// address-book entry (10.0.1.0/24), not "any". This shape proves the
// #1711 false-positive: with the bug a malformed IP collapses to nil
// and matchPolicyAddr returns true even though 10.0.1.0/24 should not
// match arbitrary input.
func matchPoliciesTestStore(t *testing.T) *configstore.Store {
	t.Helper()

	store := configstore.New(filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
security {
    address-book {
        global {
            address trust-net 10.0.1.0/24;
        }
    }
    zones {
        security-zone trust;
        security-zone untrust;
    }
    policies {
        from-zone trust to-zone untrust {
            policy restricted-allow {
                match { source-address trust-net; destination-address trust-net; application any; }
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

func TestMatchPoliciesRejectsInvalidSourceIP(t *testing.T) {
	s := &Server{store: matchPoliciesTestStore(t)}

	resp, err := s.MatchPolicies(context.Background(), &pb.MatchPoliciesRequest{
		FromZone: "trust",
		ToZone:   "untrust",
		SourceIp: "10.0.0.999", // non-empty but unparseable
	})
	if err == nil {
		t.Fatalf("MatchPolicies(invalid source-ip) returned no error; resp = %+v (false-positive #1711)", resp)
	}
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("status code = %v, want InvalidArgument", status.Code(err))
	}
	if resp != nil {
		t.Fatalf("resp = %+v, want nil on InvalidArgument", resp)
	}
}

func TestMatchPoliciesRejectsInvalidDestinationIP(t *testing.T) {
	s := &Server{store: matchPoliciesTestStore(t)}

	resp, err := s.MatchPolicies(context.Background(), &pb.MatchPoliciesRequest{
		FromZone:      "trust",
		ToZone:        "untrust",
		DestinationIp: "not-an-ip",
	})
	if err == nil {
		t.Fatalf("MatchPolicies(invalid destination-ip) returned no error; resp = %+v", resp)
	}
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("status code = %v, want InvalidArgument", status.Code(err))
	}
	if resp != nil {
		t.Fatalf("resp = %+v, want nil on InvalidArgument", resp)
	}
}

// TestMatchPoliciesRejectsCIDRInIPField guards the resolved open
// question: a CIDR in the single-IP field is malformed input and must
// be rejected, not silently wildcarded.
func TestMatchPoliciesRejectsCIDRInIPField(t *testing.T) {
	s := &Server{store: matchPoliciesTestStore(t)}

	_, err := s.MatchPolicies(context.Background(), &pb.MatchPoliciesRequest{
		FromZone: "trust",
		ToZone:   "untrust",
		SourceIp: "10.0.0.0/24",
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("CIDR in source-ip: status code = %v, want InvalidArgument", status.Code(err))
	}
}

// TestMatchPoliciesEmptyIPsMatchAny proves the legitimate Junos "any"
// semantics survive: with both IP fields empty the simulator matches
// the (restricted-term) policy because an unspecified tuple field is
// treated as "any". This is the behavior the #1711 fix must NOT break.
func TestMatchPoliciesEmptyIPsMatchAny(t *testing.T) {
	s := &Server{store: matchPoliciesTestStore(t)}

	resp, err := s.MatchPolicies(context.Background(), &pb.MatchPoliciesRequest{
		FromZone: "trust",
		ToZone:   "untrust",
		// SourceIp / DestinationIp intentionally empty.
	})
	if err != nil {
		t.Fatalf("MatchPolicies(empty IPs) error = %v, want nil", err)
	}
	if !resp.Matched {
		t.Fatalf("empty-IP query did not match; the empty-means-any path regressed")
	}
	if resp.Action != "permit" {
		t.Fatalf("action = %q, want permit", resp.Action)
	}
}

// TestMatchPoliciesValidIPMatches proves the valid path is unaffected:
// a real IP inside the restricted 10.0.1.0/24 term matches.
func TestMatchPoliciesValidIPMatches(t *testing.T) {
	s := &Server{store: matchPoliciesTestStore(t)}

	resp, err := s.MatchPolicies(context.Background(), &pb.MatchPoliciesRequest{
		FromZone:      "trust",
		ToZone:        "untrust",
		SourceIp:      "10.0.1.5",
		DestinationIp: "10.0.1.6",
	})
	if err != nil {
		t.Fatalf("MatchPolicies(valid IPs) error = %v, want nil", err)
	}
	if !resp.Matched || resp.PolicyName != "restricted-allow" {
		t.Fatalf("valid IP inside term did not match expected policy; resp = %+v", resp)
	}
}

// TestMatchPoliciesValidIPOutsideTermNoFalsePositive confirms the
// matcher is actually constrained by the term: a valid IP OUTSIDE
// 10.0.1.0/24 does not match (proving the term restriction is live, so
// the malformed-input rejection closes a real gap rather than masking a
// matcher that always returns true).
func TestMatchPoliciesValidIPOutsideTermNoFalsePositive(t *testing.T) {
	s := &Server{store: matchPoliciesTestStore(t)}

	resp, err := s.MatchPolicies(context.Background(), &pb.MatchPoliciesRequest{
		FromZone:      "trust",
		ToZone:        "untrust",
		SourceIp:      "192.168.99.1",
		DestinationIp: "192.168.99.2",
	})
	if err != nil {
		t.Fatalf("MatchPolicies(valid out-of-term IPs) error = %v, want nil", err)
	}
	if resp.Matched {
		t.Fatalf("out-of-term IP unexpectedly matched; restricted term not enforced: resp = %+v", resp)
	}
}

// TestShowTestPolicyRejectsInvalidIP covers the ShowText "test-policy:"
// simulator (the operational `test policy` command served via gRPC),
// which is a separate copy of the matcher (matchShowPolicyAddr). A
// non-empty malformed IP must not produce a "Policy match" line.
func TestShowTestPolicyRejectsInvalidIP(t *testing.T) {
	s := &Server{store: matchPoliciesTestStore(t)}

	resp, err := s.ShowText(context.Background(), &pb.ShowTextRequest{
		Topic: "test-policy:from=trust,to=untrust,src=10.0.0.999",
	})
	if err != nil {
		t.Fatalf("ShowText(test-policy invalid src) error = %v", err)
	}
	if strings.Contains(resp.Output, "Policy match") {
		t.Fatalf("invalid src produced a policy match (false-positive #1711): %q", resp.Output)
	}
	if !strings.Contains(resp.Output, "invalid src") {
		t.Fatalf("output = %q, want an invalid-src diagnostic", resp.Output)
	}
}

// TestShowTestPolicyEmptyIPMatches proves the ShowText simulator still
// treats empty IPs as "any" (matches the restricted-term policy).
func TestShowTestPolicyEmptyIPMatches(t *testing.T) {
	s := &Server{store: matchPoliciesTestStore(t)}

	resp, err := s.ShowText(context.Background(), &pb.ShowTextRequest{
		Topic: "test-policy:from=trust,to=untrust",
	})
	if err != nil {
		t.Fatalf("ShowText(test-policy empty IPs) error = %v", err)
	}
	if !strings.Contains(resp.Output, "Policy match") || !strings.Contains(resp.Output, "restricted-allow") {
		t.Fatalf("empty-IP test-policy did not match; empty-means-any regressed: %q", resp.Output)
	}
}
