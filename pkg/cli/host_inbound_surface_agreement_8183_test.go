package cli

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/grpcapi"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #8183: `show interfaces` has TWO independent renderers of the host-inbound
// admission set, and they disagreed.
//
// # The defect
//
// `pkg/grpcapi/server_show_interfaces.go` rendered
// `li.zone.HostInboundTraffic.SystemServices` VERBATIM, while its local-CLI twin
// in `pkg/cli/cli_show_interfaces.go` routed the same render through
// `zone.InterfaceHostInboundEffective(ref)`. Since #6515 a per-interface
// `host-inbound-traffic` stanza REPLACES the zone stanza on that interface, so
// for any interface declaring one the two surfaces printed DIFFERENT admission
// sets for the same interface — and the gRPC one printed a set that is not
// enforced. Measured before the fix, on the fixture below: the local CLI said
// `ping`, the gRPC surface said `ssh telnet`.
//
// The gRPC copy is the one that mattered most: `cmd/cli/show_interfaces.go`
// prints `resp.GetOutput()` verbatim, so the REMOTE cli — the surface most
// operators use — inherited it.
//
// # Why this asserts AGREEMENT and not a literal
//
// Pinning either surface to an expected string encodes which copy is trusted,
// and on this issue the trusted copy (the one three golden files already pinned)
// was the broken one. So the cells compare the two renderers against EACH OTHER.
//
// Agreement alone is not enough either: two surfaces broken identically agree.
// So each case also anchors both to `config.InterfaceHostInboundEffective`, the
// resolver the enforcement path uses — which is a third party, not a literal.
// Three-way, so a future edit cannot satisfy the cell by breaking both renders
// the same way.
//
// RED ON REVERT: restore `hit := li.zone.HostInboundTraffic` in the gRPC
// renderer and `narrowed`, `widened` and `protocols_only` all fail — the two
// surfaces disagree and the gRPC side disagrees with the resolver.

// hostInboundBlock extracts the host-inbound lines from a rendered
// `show interfaces` block, in order. Comparing the BLOCK rather than one line
// is deliberate: the override annotation and the default-deny posture line are
// part of what the surface claims, and a fix that got the set right while
// dropping "this is an override" would still leave an operator unable to tell
// where the set came from.
func hostInboundBlock(out string) []string {
	var got []string
	for _, l := range strings.Split(out, "\n") {
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "Allowed host-inbound") || strings.HasPrefix(t, "Host-inbound:") {
			got = append(got, t)
		}
	}
	return got
}

// surfaces8183 builds ONE committed config and returns the two renderers that
// read it — the gRPC server and the local CLI — sharing a single store, so the
// comparison cannot drift on the input.
func surfaces8183(t *testing.T, body string) (*grpcapi.Server, *CLI, *config.Config) {
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
	return grpcapi.NewServer("", grpcapi.Config{Store: store}),
		&CLI{store: store},
		store.ActiveConfig()
}

// cliRenderInterfaces captures what the LOCAL cli's `show interfaces` prints.
// It writes with fmt.Printf, so stdout is redirected for the call.
func cliRenderInterfaces(t *testing.T, c *CLI) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w
	err = c.showInterfaces(nil)
	_ = w.Close()
	os.Stdout = old
	if err != nil {
		t.Fatalf("showInterfaces: %v", err)
	}
	b, rerr := io.ReadAll(r)
	if rerr != nil {
		t.Fatalf("read captured stdout: %v", rerr)
	}
	return string(b)
}

// cfg8183 builds a one-zone config on `lo` — chosen because it is the only
// interface guaranteed to exist on any host including CI, and BOTH renderers
// enumerate real kernel netdevs (a `ge-0/0/0` fixture renders "Not present" on
// both and the comparison would be vacuously equal).
func cfg8183(zoneStanza, ifaceStanza string) string {
	return cfg8183WithChassis("", zoneStanza, ifaceStanza)
}

// cfg8183WithChassis lets a case make `lo` a LIFELINE interface, which
// HostInboundLifelineSet derives from the chassis-cluster control/fabric
// interfaces (plus fxp0 unconditionally).
func cfg8183WithChassis(chassis, zoneStanza, ifaceStanza string) string {
	return chassis + `
interfaces {
    lo {
        unit 0 { family inet { address 127.0.0.1/8; } }
    }
}
security {
    zones {
        security-zone trust {
` + zoneStanza + `
            interfaces {
                lo.0 {
` + ifaceStanza + `
                }
            }
        }
    }
}
`
}

func TestShowInterfacesHostInboundSurfacesAgree8183(t *testing.T) {
	const zoneSSHTelnet = "            host-inbound-traffic { system-services { ssh; telnet; } }"

	for _, tc := range []struct {
		name    string
		chassis string
		zone    string
		iface   string
	}{
		{
			// The issue's headline case, and the dangerous direction: the zone
			// admits ssh, the interface narrows to ping. Rendering the zone set
			// reads as an exposure the box does not have.
			name:  "narrowed",
			zone:  zoneSSHTelnet,
			iface: "                    host-inbound-traffic { system-services { ping; } }",
		},
		{
			// The inverse: the interface admits MORE than the zone. A surface
			// reading the zone set under-reports, which is the #5619 doctrine's
			// other half — an operator is told they are tighter than they are.
			name:  "widened",
			zone:  "            host-inbound-traffic { system-services { ping; } }",
			iface: "                    host-inbound-traffic { system-services { ssh; telnet; ping; } }",
		},
		{
			// ACCEPT-SIDE CONTROL. No interface stanza at all: the zone set IS
			// the effective set, so both surfaces must still render it. Without
			// this, a "fix" that renders nothing, or renders an empty set for
			// every interface, satisfies every other case here.
			name:  "no_override_still_shows_the_zone_set",
			zone:  zoneSSHTelnet,
			iface: "",
		},
		{
			// The most COMMON shape, and the one this change adds output to:
			// an interface in a zone with no host-inbound stanza anywhere. Both
			// surfaces must render the explicit default-deny posture line, so a
			// blank section is never misread as "not enforced" (#5619). Before
			// #8183 the gRPC surface printed nothing at all here.
			name:  "no_host_inbound_anywhere_says_default_deny",
			zone:  "",
			iface: "",
		},
		{
			// #3682: a LIFELINE interface is exempt from host-inbound deny
			// scoping, so it must render the exemption and NOT the deny line —
			// the two are mutually exclusive. A surface printing both tells an
			// operator their management interface is denied when it is not.
			name: "lifeline_says_exempt_not_deny",
			chassis: "chassis { cluster { node 0; cluster-id 1; control-interface lo; " +
				"authentication-key \"dGVzdC1vbmx5LW5vdC1hLXJlYWwta2V5MDAwMA==\"; } }",
			zone:  "",
			iface: "",
		},
		{
			// Protocols travel the same path as services and have their own
			// line; a fix that routed only the services list would pass the
			// cases above.
			name:  "protocols_only",
			zone:  "            host-inbound-traffic { protocols { ospf; } }",
			iface: "                    host-inbound-traffic { protocols { bgp; } }",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, c, cfg := surfaces8183(t, cfg8183WithChassis(tc.chassis, tc.zone, tc.iface))

			resp, err := s.ShowInterfacesDetail(context.Background(),
				&pb.ShowInterfacesDetailRequest{Filter: "lo"})
			if err != nil {
				t.Fatalf("ShowInterfacesDetail: %v", err)
			}
			grpcBlock := hostInboundBlock(resp.GetOutput())
			cliBlock := hostInboundBlock(cliRenderInterfaces(t, c))

			// 1. THE AGREEMENT. Neither side is pinned to a literal; they are
			//    pinned to each other.
			if strings.Join(grpcBlock, "|") != strings.Join(cliBlock, "|") {
				t.Errorf("the two `show interfaces` surfaces disagree about what "+
					"lo.0 admits.\n  gRPC (what the REMOTE cli prints): %q"+
					"\n  local CLI: %q", grpcBlock, cliBlock)
			}

			// 2. ANTI-VACUITY. Two surfaces broken identically agree, so both
			//    are anchored to the resolver the enforcement path uses. This is
			//    a third party, not a literal.
			zone := cfg.Security.Zones["trust"]
			if zone == nil {
				t.Fatal("fixture did not build the trust zone")
			}
			svc, proto, _ := zone.InterfaceHostInboundEffective("lo.0")
			for _, tok := range svc {
				if !blockMentions(grpcBlock, tok) {
					t.Errorf("gRPC omits admitted service %q; resolver says svc=%v, block=%q",
						tok, svc, grpcBlock)
				}
			}
			for _, tok := range proto {
				if !blockMentions(grpcBlock, tok) {
					t.Errorf("gRPC omits admitted protocol %q; resolver says proto=%v, block=%q",
						tok, proto, grpcBlock)
				}
			}
			// 3. And it must not claim anything the resolver does NOT admit —
			//    the direction the issue calls worse, because the operator's
			//    remedy for a phantom service changes nothing.
			for _, ghost := range []string{"ssh", "telnet", "ping", "ospf", "bgp"} {
				if inTokens(svc, ghost) || inTokens(proto, ghost) {
					continue
				}
				if blockMentions(grpcBlock, ghost) {
					t.Errorf("gRPC claims %q is admitted on lo.0, but the resolver "+
						"does not admit it (svc=%v proto=%v). block=%q",
						ghost, svc, proto, grpcBlock)
				}
			}
			if len(grpcBlock) == 0 {
				t.Error("no host-inbound lines rendered at all — the comparison " +
					"above would be vacuously equal")
			}
			// The deny case renders a posture line and no Allowed line; assert
			// the posture is STATED rather than left blank, which is the whole
			// point of rendering it.
			lifeline := blockMentions(grpcBlock, "lifeline-exempt")
			if lifeline && blockMentions(grpcBlock, "deny") {
				t.Errorf("a LIFELINE interface renders BOTH the exemption and a "+
					"default-deny line; they are mutually exclusive and printing "+
					"both tells an operator their management interface is denied "+
					"when it is not (#3682). block=%q", grpcBlock)
			}
			if !lifeline && len(svc) == 0 && len(proto) == 0 && !blockMentions(grpcBlock, "deny") {
				t.Errorf("nothing is admitted on lo.0 and the surface does not "+
					"say so — a blank section reads as \"not enforced\" (#5619). block=%q",
					grpcBlock)
			}
		})
	}
}

func blockMentions(block []string, tok string) bool {
	for _, l := range block {
		for _, f := range strings.Fields(l) {
			if f == tok {
				return true
			}
		}
	}
	return false
}

func inTokens(toks []string, want string) bool {
	for _, t := range toks {
		if t == want {
			return true
		}
	}
	return false
}

// The REMOTE cli inherits the gRPC render rather than having its own, so the
// #8183 fix reaches it for free. That inheritance is load-bearing and invisible
// — if `cmd/cli` ever re-rendered host-inbound locally it would become a THIRD
// copy able to drift, and nothing in this package would see it.
//
// A source guard because `cmd/cli` needs a live gRPC connection. It is matched
// line-wise on a trimmed start so a commented-out or merely mentioned call does
// not satisfy it, with the over-reach control below.
func TestRemoteCLIInheritsTheGRPCInterfaceRender8183(t *testing.T) {
	src := remoteShowInterfacesSrc(t)
	if lineStartsWith(src, remoteRenderNeedle8183) < 0 {
		t.Fatalf("cmd/cli/show_interfaces.go no longer prints the gRPC Output "+
			"verbatim (%q not found as a statement). If it now renders "+
			"host-inbound itself, it is a THIRD copy of the #8183 render and "+
			"needs to be added to the agreement cell above", remoteRenderNeedle8183)
	}
	if strings.Contains(src, "Allowed host-inbound") {
		t.Error("cmd/cli/show_interfaces.go renders host-inbound itself — it is " +
			"no longer a pure passthrough of the gRPC output, so the #8183 fix " +
			"no longer reaches the remote cli for free")
	}
}

const remoteRenderNeedle8183 = "fmt.Print(resp.Output)"

// remoteShowInterfacesSrc reads cmd/cli's show-interfaces source. Relative to
// this package's directory, which is where `go test` runs.
func remoteShowInterfacesSrc(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("../../cmd/cli/show_interfaces.go")
	if err != nil {
		t.Fatalf("read cmd/cli/show_interfaces.go: %v", err)
	}
	return string(b)
}

func lineStartsWith(src, needle string) int {
	for i, l := range strings.Split(src, "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), needle) {
			return i
		}
	}
	return -1
}

// OVER-REACH CONTROL for the inheritance guard: a commented-out or merely
// mentioned call must not satisfy it, and the matcher must still match a real
// one — so it cannot pass by matching nothing ever.
func TestRemoteCLIInheritanceGuardRejectsAMention8183(t *testing.T) {
	if got := lineStartsWith("\t// "+remoteRenderNeedle8183+"\n", remoteRenderNeedle8183); got >= 0 {
		t.Error("the inheritance guard accepts a COMMENTED-OUT call, so removing " +
			"the passthrough by commenting it out would still report it wired")
	}
	if got := lineStartsWith("\t// see "+remoteRenderNeedle8183+" below\n", remoteRenderNeedle8183); got >= 0 {
		t.Error("the inheritance guard accepts a prose MENTION of the call")
	}
	if got := lineStartsWith("\t"+remoteRenderNeedle8183+"\n", remoteRenderNeedle8183); got < 0 {
		t.Error("the inheritance guard does not match even a body that plainly " +
			"contains the real call — it would pass nothing, ever")
	}
}
