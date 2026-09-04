package cli

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/grpcapi"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #8597 K47. `request security policies check` existed only on the local
// console; the remote `cli` answered "unknown request security target:
// policies" for a verb the SSOT command tree advertises and completion offers.
//
// It is now served over gRPC by the `policies-check` ShowText topic. These
// cells assert AGREEMENT between the two surfaces rather than pinning either to
// a literal — the #8183 lesson, where the copy three golden files trusted was
// the broken one. The analysis and its RENDERING are both single-sourced in
// pkg/policymatch, so agreement here is a property of the wiring: it fails if
// either surface stops routing through the shared renderer.

// policyCheckSurfaces8597 commits one config and returns the two renderers that
// read it, sharing a single store so the comparison cannot drift on the input.
func policyCheckSurfaces8597(t *testing.T, body string) (*grpcapi.Server, *CLI) {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := store.LoadOverride(body); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	return grpcapi.NewServer("", grpcapi.Config{Store: store}), &CLI{store: store}
}

// cliRenderPolicyCheck captures what the LOCAL cli prints for the verb.
func cliRenderPolicyCheck(t *testing.T, c *CLI) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w
	err = c.handleRequestSecurity([]string{"policies", "check"})
	_ = w.Close()
	os.Stdout = old
	if err != nil {
		t.Fatalf("handleRequestSecurity: %v", err)
	}
	b, rerr := io.ReadAll(r)
	if rerr != nil {
		t.Fatalf("read captured stdout: %v", rerr)
	}
	return string(b)
}

func grpcRenderPolicyCheck(t *testing.T, s *grpcapi.Server) string {
	t.Helper()
	resp, err := s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: "policies-check"})
	if err != nil {
		t.Fatalf("ShowText(policies-check): %v", err)
	}
	return resp.GetOutput()
}

// shadowingConfig8597 has a wide `any/any` permit ahead of a narrow deny, which
// the analysis reports as a SHADOWED policy — the operationally dangerous kind.
const shadowingConfig8597 = `
security {
    zones {
        security-zone trust { }
        security-zone untrust { }
    }
    policies {
        from-zone trust to-zone untrust {
            policy allow-all {
                match { source-address any; destination-address any; application any; }
                then { permit; }
            }
            policy block-web {
                match { source-address any; destination-address any; application junos-http; }
                then { deny; }
            }
        }
    }
}
`

// cleanConfig8597 has one policy, so nothing shadows anything.
const cleanConfig8597 = `
security {
    zones {
        security-zone trust { }
        security-zone untrust { }
    }
    policies {
        from-zone trust to-zone untrust {
            policy allow-web {
                match { source-address any; destination-address any; application junos-http; }
                then { permit; }
            }
        }
    }
}
`

func TestPolicyCheckRendersIdenticallyOnBothSurfaces_8597(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  string
		want string // a substring that must appear, so neither surface is vacuously empty
	}{
		{"a shadowed policy", shadowingConfig8597, "issue(s) detected"},
		{"nothing to report", cleanConfig8597, "no shadowed or redundant policies detected"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, c := policyCheckSurfaces8597(t, tc.cfg)
			local := cliRenderPolicyCheck(t, c)
			remote := grpcRenderPolicyCheck(t, srv)

			// Non-vacuity FIRST: two empty strings agree.
			if !strings.Contains(local, tc.want) {
				t.Fatalf("the local render does not contain %q, so the comparison "+
					"below would pass on an empty fixture:\n%s", tc.want, local)
			}
			if local != remote {
				t.Errorf("the two surfaces disagree for the SAME committed config.\n"+
					"local:\n%s\nremote:\n%s\n"+
					"Both must route through policymatch.RenderPolicyCheck; a second "+
					"copy of the header line or the empty-result sentence is how this "+
					"drifts (#8597 K47)", local, remote)
			}
		})
	}
}

// The shadowed-policy case must actually FIND the shadow, or the agreement
// above is agreement about an analysis that never ran.
func TestTheShadowFixtureActuallyReportsAShadow_8597(t *testing.T) {
	srv, _ := policyCheckSurfaces8597(t, shadowingConfig8597)
	out := grpcRenderPolicyCheck(t, srv)
	if !strings.Contains(out, "block-web") {
		t.Errorf("the fixture's shadowed policy is not named in the output; the "+
			"agreement cells would then compare two renderings of an empty finding "+
			"set:\n%s", out)
	}
}

// A box with nothing COMMITTED answers rather than erroring, on both surfaces.
//
// The reachable case is a real store with a nil ActiveConfig, not a nil store:
// showText dereferences s.store at its first statement, so a nil-store fixture
// panics for every topic and would be measuring the harness rather than this
// handler. That was the first version of this cell.
func TestPolicyCheckWithNothingCommittedAgrees_8597(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if cfg := store.ActiveConfig(); cfg != nil {
		t.Skipf("this store commits a default config on open, so the "+
			"nothing-committed branch is not reachable from here: %T", cfg)
	}
	srv := grpcapi.NewServer("", grpcapi.Config{Store: store})
	c := &CLI{store: store}

	out, err := srv.ShowText(context.Background(), &pb.ShowTextRequest{Topic: "policies-check"})
	if err != nil {
		t.Fatalf("an unconfigured box must answer, not error: %v", err)
	}
	if !strings.Contains(out.GetOutput(), "no active configuration") {
		t.Errorf("want the console's own wording for an unconfigured box, got %q",
			out.GetOutput())
	}
	if local := cliRenderPolicyCheck(t, c); local != out.GetOutput() {
		t.Errorf("the surfaces disagree with nothing committed.\nlocal:  %q\nremote: %q",
			local, out.GetOutput())
	}
}
