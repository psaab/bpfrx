package grpcapi

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #3667: the gRPC-rendered `show security policies detail` text surface
// (showPoliciesDetail, server_show_policies_text.go) had drifted from the local
// CLI detail renderer. It dropped:
//
//   - H01 (correctness): the address-exclusion "(except)" marker, so an
//     inverted (source-address-excluded / destination-address-excluded) rule
//     rendered with the OPPOSITE security meaning — it printed the listed
//     addresses as if they were the match set instead of the excepted set.
//   - H04: the independent session-init / session-close log modes, collapsed
//     into a bare "log".
//   - H05: the runtime policy Index, needed to map an RT_FLOW / policy-deny log
//     line back to the detail row.
//
// This is the fail-on-revert guard. The config below covers an excluded SOURCE
// set, an excluded DESTINATION set (zone-pair AND global blocks), session-init
// only, session-close only, and both, plus the Index column.

func exclusion3667GRPCStore(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
security {
    address-book {
        global {
            address bad-src 203.0.113.0/24;
            address bad-dst 198.51.100.0/24;
            address mgmt-net 10.0.0.0/8;
        }
    }
    zones {
        security-zone trust;
        security-zone untrust;
    }
    policies {
        from-zone trust to-zone untrust {
            policy excl-src {
                match {
                    source-address bad-src;
                    source-address-excluded;
                    destination-address any;
                    application any;
                }
                then {
                    deny;
                    log { session-init; }
                }
            }
            policy excl-dst {
                match {
                    source-address any;
                    destination-address bad-dst;
                    destination-address-excluded;
                    application any;
                }
                then {
                    deny;
                    log { session-close; }
                }
            }
            policy both-log {
                match { source-address any; destination-address any; application any; }
                then {
                    permit;
                    log { session-init; session-close; }
                }
            }
        }
        global {
            policy g-excl {
                match {
                    source-address any;
                    destination-address mgmt-net;
                    destination-address-excluded;
                    application any;
                }
                then {
                    deny;
                    log { session-init; session-close; }
                }
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

// lineContaining returns the first output line containing needle.
func lineContaining(t *testing.T, out, needle string) string {
	t.Helper()
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, needle) {
			return line
		}
	}
	t.Fatalf("no line containing %q in output:\n%s", needle, out)
	return ""
}

func TestGRPCShowPoliciesDetailTextExclusionLogAndIndex(t *testing.T) {
	s := &Server{store: exclusion3667GRPCStore(t)}

	var buf strings.Builder
	s.showPoliciesDetail("", &buf)
	out := buf.String()

	// H01 (correctness): the inverted source set is annotated "(except)".
	// On revert (printAddrs drops the excluded branch) the header prints the
	// plain "Source addresses:" and the listed address reads as the match set —
	// the OPPOSITE security meaning — so this goes RED.
	if !strings.Contains(out, "Source addresses (except):") {
		t.Fatalf("gRPC detail dropped the (except) source-exclusion marker "+
			"(H01 correctness — inverted rule rendered as its opposite):\n%s", out)
	}
	// H01: the inverted destination set is annotated "(except)". Two policies
	// use it (zone-pair excl-dst + global g-excl), proving BOTH blocks render
	// the marker.
	if got := strings.Count(out, "Destination addresses (except):"); got < 2 {
		t.Fatalf("gRPC detail rendered %d destination (except) markers, want >=2 "+
			"(zone-pair + global blocks — H01 correctness):\n%s", got, out)
	}
	// The global block specifically must carry the destination (except) marker.
	if _, after, ok := strings.Cut(out, "Global policies:"); !ok ||
		!strings.Contains(after, "Destination addresses (except):") {
		t.Fatalf("global-policy block dropped the destination (except) marker (H01):\n%s", out)
	}

	// H04: session-init / session-close render as distinct modes, not a bare
	// "log". On revert (bare "log") none of these appear -> RED.
	if !strings.Contains(out, "Session log: at-create\n") {
		t.Fatalf("gRPC detail missing session-init-only mode (H04):\n%s", out)
	}
	if !strings.Contains(out, "Session log: at-close\n") {
		t.Fatalf("gRPC detail missing session-close-only mode (H04):\n%s", out)
	}
	if !strings.Contains(out, "Session log: at-create, at-close\n") {
		t.Fatalf("gRPC detail missing both-modes session log (H04):\n%s", out)
	}
	// The collapsed bare "log" line must be gone entirely.
	if strings.Contains(out, "\n      log\n") {
		t.Fatalf("gRPC detail still emits the collapsed bare \"log\" line (H04):\n%s", out)
	}

	// H05: the header carries the runtime Index (the numeric ID the RT_FLOW /
	// policy-deny path logs), from the RuntimePolicyIDs SSOT. Verify both the
	// presence and that the value matches the SSOT, for a zone-pair AND a
	// global policy. On revert (no Index) -> RED.
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		t.Fatal("active config is nil")
	}
	runtimeIDs := dpuserspace.RuntimePolicyIDs(cfg)
	wantZP := dpuserspace.RuntimePolicyIndex(runtimeIDs, 0, 0)     // excl-src: set 0, slice 0
	wantGlobal := dpuserspace.RuntimePolicyIndex(runtimeIDs, 1, 0) // g-excl: global set (== len(Policies)), slice 0
	zpLine := lineContaining(t, out, "Policy: excl-src, action-type:")
	if !strings.Contains(zpLine, fmt.Sprintf(", Index: %d", wantZP)) {
		t.Fatalf("zone-pair policy header %q missing runtime Index %d (H05)", zpLine, wantZP)
	}
	gLine := lineContaining(t, out, "Policy: g-excl, action-type:")
	if !strings.Contains(gLine, fmt.Sprintf(", Index: %d", wantGlobal)) {
		t.Fatalf("global policy header %q missing runtime Index %d (H05)", gLine, wantGlobal)
	}
}
