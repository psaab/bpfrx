package cli

import (
	"path/filepath"
	"strings"
	"testing"
)

// #3327: the local-CLI screen/zones text renderers hand-built their own screen
// inventory lists and silently omitted port-scan, ip-sweep,
// limit-session-source, limit-session-destination, and icmp-fragment even
// though the compiler and userspace dataplane fully enforce them — the same
// drift the structured REST/gRPC inventory (and then the gRPC text renderers)
// were fixed for. This test drives every CLI screen/zones renderer with a
// maximal profile (every check enabled) and asserts each of the five
// previously-omitted checks appears in the output.
//
// RED-on-revert: routing showScreen / the "Enabled checks" zones line back
// through a hand-built list (dropping the config.ScreenEnabledCheckList
// delegation), or deleting the completed rows from showScreenIdsOption /
// showScreenIdsOptionDetail, fails the matching sub-assertion below.

// maximalScreenCLIStore commits a profile that enables every screen check the
// compiler models, including the five #3327 previously-omitted checks, bound to
// a zone so the `show security zones` detail renderer reaches it.
func maximalScreenCLIStore(t *testing.T) *CLI {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
security {
    zones {
        security-zone trust {
            screen maxp;
        }
        security-zone untrust;
    }
    policies {
        from-zone trust to-zone untrust {
            policy p1 {
                match { source-address any; destination-address any; application any; }
                then { permit; }
            }
        }
    }
    screen {
        ids-option maxp {
            icmp { ping-death; fragment; flood; }
            ip { source-route-option; tear-drop; ip-sweep; }
            tcp { land; syn-fin; no-flag; fin-no-ack; winnuke; syn-frag; syn-flood; port-scan; }
            udp { flood; }
            limit-session { source-ip-based 100; destination-ip-based 200; }
        }
    }
}
`); err != nil {
		t.Fatalf("LoadOverride() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	cfg := store.ActiveConfig()
	if cfg == nil || cfg.Security.Screen["maxp"] == nil {
		t.Fatalf("fixture missing screen profile maxp")
	}
	// Guard the fixture actually enabled the five omitted checks, so a parse
	// regression cannot make the renderer assertions vacuously pass.
	p := cfg.Security.Screen["maxp"]
	if !p.ICMP.Fragment || p.TCP.PortScanThreshold <= 0 || p.IP.IPSweepThreshold <= 0 ||
		p.LimitSession.SourceIPBased <= 0 || p.LimitSession.DestinationIPBased <= 0 {
		t.Fatalf("fixture did not enable all five omitted checks: %+v", p)
	}
	return &CLI{store: store} // dp nil: skip counter reads, exercise the inventory walk
}

// the five checks #3327 previously omitted, asserted as canonical-name
// substrings present in every renderer (bare, "(token)", or "token(threshold:N)").
var screenOmittedChecks3327 = []string{
	"port-scan",
	"ip-sweep",
	"limit-session-source",
	"limit-session-destination",
	"icmp-fragment",
}

func assertOmittedChecksPresent3327(t *testing.T, renderer, out string) {
	t.Helper()
	for _, want := range screenOmittedChecks3327 {
		if !strings.Contains(out, want) {
			t.Errorf("%s output omits previously-dropped screen check %q\noutput:\n%s",
				renderer, want, out)
		}
	}
}

func TestCLIShowScreenInventoryNoOmission3327(t *testing.T) {
	t.Run("show-security-screen", func(t *testing.T) {
		c := maximalScreenCLIStore(t)
		out := captureStdout(t, func() {
			if err := c.showScreen(); err != nil {
				t.Fatalf("showScreen: %v", err)
			}
		})
		assertOmittedChecksPresent3327(t, "show security screen", out)
	})

	t.Run("show-security-screen-ids-option", func(t *testing.T) {
		c := maximalScreenCLIStore(t)
		out := captureStdout(t, func() {
			if err := c.showScreenIdsOption("maxp"); err != nil {
				t.Fatalf("showScreenIdsOption: %v", err)
			}
		})
		assertOmittedChecksPresent3327(t, "show security screen ids-option", out)
	})

	t.Run("show-security-screen-ids-option-detail", func(t *testing.T) {
		c := maximalScreenCLIStore(t)
		out := captureStdout(t, func() {
			if err := c.showScreenIdsOptionDetail("maxp"); err != nil {
				t.Fatalf("showScreenIdsOptionDetail: %v", err)
			}
		})
		assertOmittedChecksPresent3327(t, "show security screen ids-option detail", out)
	})

	t.Run("show-security-zones-detail", func(t *testing.T) {
		c := maximalScreenCLIStore(t)
		out := captureStdout(t, func() {
			if err := c.showZonesDisplay(c.store.ActiveConfig(), true, ""); err != nil {
				t.Fatalf("showZonesDisplay(detail): %v", err)
			}
		})
		assertOmittedChecksPresent3327(t, "show security zones detail", out)
	})
}
