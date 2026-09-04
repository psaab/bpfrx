package main

import (
	"context"
	"strings"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc"
)

// #8484: bind what the operator SEES, not what the daemon computed.
//
// Every advisory cell in the tree asserts `cfg.Warnings`, and #6515's cell
// asserts the RPC response carries them. Nothing asserted that the remote CLI
// RENDERS them, which is the only artifact an operator actually reads — so
// "the advisory is wired" was verifiable at three layers and unverifiable at
// the fourth, and #8484 was filed against that gap.
//
// The accept-side control is the load-bearing half: a commit with NO warnings
// must print NO warning line. An unconditional print would satisfy every
// positive cell here while inventing advisories on clean configs.

// advisoryClient stubs the three commit RPCs with a fixed warning set.
type advisoryClient struct {
	pb.BpfrxServiceClient
	warnings []string
}

func (a *advisoryClient) Commit(_ context.Context, _ *pb.CommitRequest, _ ...grpc.CallOption) (*pb.CommitResponse, error) {
	return &pb.CommitResponse{Summary: "1 statement(s) changed", Warnings: a.warnings}, nil
}

func (a *advisoryClient) CommitCheck(_ context.Context, _ *pb.CommitCheckRequest, _ ...grpc.CallOption) (*pb.CommitCheckResponse, error) {
	return &pb.CommitCheckResponse{Warnings: a.warnings}, nil
}

func (a *advisoryClient) CommitConfirmed(_ context.Context, _ *pb.CommitConfirmedRequest, _ ...grpc.CallOption) (*pb.CommitConfirmedResponse, error) {
	return &pb.CommitConfirmedResponse{Warnings: a.warnings}, nil
}

func (a *advisoryClient) GetStatus(_ context.Context, _ *pb.GetStatusRequest, _ ...grpc.CallOption) (*pb.GetStatusResponse, error) {
	return &pb.GetStatusResponse{}, nil
}

// warningLines returns the rendered "warning: ..." lines, matched at line
// start so a warning mentioned inside some other sentence cannot count.
func warningLines(out string) []string {
	var got []string
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "warning: ") {
			got = append(got, strings.TrimPrefix(line, "warning: "))
		}
	}
	return got
}

// Every commit form that can carry advisories must render them.
func TestRemoteCommitRendersAdvisories_8484(t *testing.T) {
	// Two warnings, so a renderer that prints only the first is caught.
	warnings := []string{
		"interface gr-0/0/0 has unit(s) gr-0/0/0.1 in no security zone (#7509)",
		"interface ge-0/0/9 has units in more than one security zone (dmz, lan) (#8402)",
	}

	for _, tc := range []struct{ name, line string }{
		{"bare commit", "commit"},
		{"commit check", "commit check"},
		{"commit comment", `commit comment "why"`},
		{"commit confirmed", "commit confirmed 5"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := configModeCtl(&advisoryClient{warnings: warnings})
			out, err := captureDispatch(t, c, tc.line)
			if err != nil {
				t.Fatalf("%q must succeed, got: %v", tc.line, err)
			}
			got := warningLines(out)
			if len(got) != len(warnings) {
				t.Fatalf("%q rendered %d advisory line(s), want %d.\n"+
					"An advisory the daemon computed and the RPC delivered is invisible to the\n"+
					"operator unless this path prints it — which is exactly #8484.\ngot output:\n%s",
					tc.line, len(got), len(warnings), out)
			}
			for i, w := range warnings {
				if got[i] != w {
					t.Errorf("%q advisory %d rendered as %q, want %q", tc.line, i, got[i], w)
				}
			}
		})
	}
}

// ACCEPT-SIDE CONTROL. A commit that raises nothing must stay silent. Without
// this, a renderer that printed a fixed line unconditionally would pass every
// assertion above.
func TestRemoteCommitStaysSilentWithNoAdvisories_8484(t *testing.T) {
	for _, tc := range []struct {
		name, line string
		warnings   []string
	}{
		{"bare commit, nil warnings", "commit", nil},
		{"bare commit, empty warnings", "commit", []string{}},
		{"commit check, nil warnings", "commit check", nil},
		{"commit confirmed, nil warnings", "commit confirmed 5", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := configModeCtl(&advisoryClient{warnings: tc.warnings})
			out, err := captureDispatch(t, c, tc.line)
			if err != nil {
				t.Fatalf("%q must succeed, got: %v", tc.line, err)
			}
			if got := warningLines(out); len(got) != 0 {
				t.Fatalf("%q raised no advisory but rendered %d warning line(s): %v\n"+
					"A path that prints unconditionally satisfies every delivery cell while\n"+
					"inventing advisories on clean configs.\noutput:\n%s", tc.line, len(got), got, out)
			}
			// The command must still report its own success.
			if !strings.Contains(out, "commit complete") &&
				!strings.Contains(out, "configuration check succeeds") &&
				!strings.Contains(out, "rolled back") {
				t.Fatalf("%q printed neither an advisory nor its success marker; "+
					"silence here would be indistinguishable from a dropped response.\noutput:\n%s",
					tc.line, out)
			}
		})
	}
}
