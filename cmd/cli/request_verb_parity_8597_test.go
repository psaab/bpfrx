// #8597 K47: the remote `cli` refused two `request` verbs the SSOT command tree
// advertises and the local console implements —
// `request security policies check` and
// `request system configuration rescue save|delete`. Tab completion is served
// by that same tree, so completion offered a command the dispatcher then
// answered with "unknown request security target: policies".
//
// These cells assert the WIRING: the dispatcher issues the right RPC with the
// right argument, refuses the malformed forms without issuing one, and prints
// what the server returned. The analysis and rendering behind the policy lint
// are tested where they live (pkg/policymatch); the local/remote agreement is
// pinned in pkg/cli.

package main

import (
	"context"
	"strings"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc"
)

// requestParityRecorder records the two RPCs these verbs use.
type requestParityRecorder struct {
	pb.BpfrxServiceClient

	showTopics []string
	actions    []string
}

func (f *requestParityRecorder) ShowText(
	_ context.Context, in *pb.ShowTextRequest, _ ...grpc.CallOption,
) (*pb.ShowTextResponse, error) {
	f.showTopics = append(f.showTopics, in.GetTopic())
	return &pb.ShowTextResponse{Output: "Policy check complete: no shadowed or redundant policies detected.\n"}, nil
}

func (f *requestParityRecorder) SystemAction(
	_ context.Context, in *pb.SystemActionRequest, _ ...grpc.CallOption,
) (*pb.SystemActionResponse, error) {
	f.actions = append(f.actions, in.GetAction())
	return &pb.SystemActionResponse{Message: "Rescue configuration saved"}, nil
}

func TestRemoteRequestSecurityPoliciesCheck_8597(t *testing.T) {
	fake := &requestParityRecorder{}
	c := &ctl{client: fake}
	// The whole verb, through the same entry point main() uses, so the
	// "policies" target really is reached rather than the sub-handler being
	// called directly.
	if err := c.handleRequestSecurity([]string{"policies", "check"}); err != nil {
		t.Fatalf("request security policies check: %v", err)
	}
	if len(fake.showTopics) != 1 || fake.showTopics[0] != "policies-check" {
		t.Fatalf("topics = %v, want exactly [policies-check]. Before #8597 K47 this "+
			"returned `unknown request security target: policies` and issued no RPC",
			fake.showTopics)
	}
}

// A stray trailing token must not be dropped silently — the same discipline
// `request security ipsec sa clear` applies to its own selector.
func TestRemotePoliciesCheckRefusesArguments_8597(t *testing.T) {
	fake := &requestParityRecorder{}
	c := &ctl{client: fake}
	if err := c.handleRequestSecurity([]string{"policies", "check", "verbose"}); err == nil {
		t.Fatal("a trailing argument must be refused, not dropped")
	}
	if len(fake.showTopics) != 0 {
		t.Fatalf("an RPC was issued for a malformed form: %v", fake.showTopics)
	}
}

// A bare `request security policies` prints help rather than erroring, matching
// the local console and every other partial `request` path here.
func TestRemotePoliciesWithoutCheckPrintsHelp_8597(t *testing.T) {
	fake := &requestParityRecorder{}
	c := &ctl{client: fake}
	if err := c.handleRequestSecurity([]string{"policies"}); err != nil {
		t.Fatalf("a bare `request security policies` must print help, not error: %v", err)
	}
	if len(fake.showTopics) != 0 {
		t.Fatalf("help must not issue an RPC: %v", fake.showTopics)
	}
}

func TestRemoteRequestSystemConfigurationRescue_8597(t *testing.T) {
	for _, tc := range []struct {
		args   []string
		action string
	}{
		{[]string{"system", "configuration", "rescue", "save"}, "rescue-save"},
		{[]string{"system", "configuration", "rescue", "delete"}, "rescue-delete"},
	} {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			fake := &requestParityRecorder{}
			c := &ctl{client: fake}
			// Entered at handleRequest so the `system` -> `configuration`
			// dispatch is exercised, not just the leaf handler.
			if err := c.handleRequest(tc.args); err != nil {
				t.Fatalf("request %s: %v", strings.Join(tc.args, " "), err)
			}
			if len(fake.actions) != 1 || fake.actions[0] != tc.action {
				t.Fatalf("actions = %v, want exactly [%s]. Before #8597 K47 this "+
					"returned `unknown request system command: configuration`",
					fake.actions, tc.action)
			}
		})
	}
}

// save and delete must not collapse onto one verb: the wrong one either
// discards the rescue config the operator meant to write, or writes one they
// meant to remove.
func TestRescueSaveAndDeleteAreDistinctVerbs_8597(t *testing.T) {
	fake := &requestParityRecorder{}
	c := &ctl{client: fake}
	if err := c.handleRequest([]string{"system", "configuration", "rescue", "save"}); err != nil {
		t.Fatal(err)
	}
	if err := c.handleRequest([]string{"system", "configuration", "rescue", "delete"}); err != nil {
		t.Fatal(err)
	}
	if len(fake.actions) != 2 || fake.actions[0] == fake.actions[1] {
		t.Fatalf("actions = %v; save and delete must map to different verbs", fake.actions)
	}
}

func TestRemoteRescueRefusesMalformedForms_8597(t *testing.T) {
	for _, args := range [][]string{
		{"system", "configuration", "backup"},                  // unknown sub-command
		{"system", "configuration", "rescue", "restore"},       // unknown rescue verb
		{"system", "configuration", "rescue", "save", "extra"}, // stray argument
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			fake := &requestParityRecorder{}
			c := &ctl{client: fake}
			if err := c.handleRequest(args); err == nil {
				t.Fatalf("handleRequest(%v) = nil; want a usage error", args)
			}
			if len(fake.actions) != 0 {
				t.Fatalf("a malformed form issued %v — this verb REPLACES the saved "+
					"rescue configuration, so a dropped token must not run it",
					fake.actions)
			}
		})
	}
}

// The partial forms print help and issue nothing, like the local console.
func TestRemoteRescuePartialFormsPrintHelp_8597(t *testing.T) {
	for _, args := range [][]string{
		{"system", "configuration"},
		{"system", "configuration", "rescue"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			fake := &requestParityRecorder{}
			c := &ctl{client: fake}
			if err := c.handleRequest(args); err != nil {
				t.Fatalf("handleRequest(%v) must print help, not error: %v", args, err)
			}
			if len(fake.actions) != 0 {
				t.Fatalf("help issued an RPC: %v", fake.actions)
			}
		})
	}
}
