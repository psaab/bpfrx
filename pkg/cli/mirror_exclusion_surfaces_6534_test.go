package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
)

// #6534, port-mirroring — the LOCAL CLI half, both of its render paths.
//
// pkg/grpcapi/mirror_exclusion_surfaces_6534_test.go binds the gRPC copy and
// states that the CLI copy is bound "by asserting the TEXT both are required to
// produce". That is a claim about a surface the test cannot reach, and it was
// wrong in a way the claim could not expose: there are THREE renderers of a
// port-mirroring instance, not two, and the third — `show forwarding-options`
// in cli_show_routing.go — printed the full per-instance detail with no
// annotation at all.
//
// It is also the copy most likely to be believed. The gRPC `show
// forwarding-options` emits only a pointer line ("see 'show forwarding-options
// port-mirroring' for details"), so the remote CLI cannot show a dropped
// instance's rate and interfaces; the local CLI's version of the same command
// shows all of them.
//
// Reachability is worse than the lenient-load backstop the NAT family needs.
// Nothing in the strict commit gates rejects an instance with no `output
// interface` — compilePortMirroring rejects only a negative or non-integer
// rate, and there is no strict validator for a missing output — so
// `no output interface configured` is reachable through an ORDINARY commit,
// which is what the fixture below performs.

// mirrorSurfaceCLIStore commits one healthy and one dropped instance through
// the ordinary commit path.
//
// Two instances, not one, on purpose: with a single dropped instance a
// renderer that unconditionally printed the annotation would pass every cell.
// The healthy instance is the negative control that makes "annotates" mean
// "annotates the right one".
func mirrorSurfaceCLIStore(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
forwarding-options {
    port-mirroring {
        instance armed {
            input {
                rate 100;
                ingress {
                    interface ge-0/0/1.0;
                }
            }
            output {
                interface ge-0/0/9.0;
            }
        }
        instance dropped {
            input {
                rate 100;
                ingress {
                    interface ge-0/0/2.0;
                }
            }
        }
    }
}
`); err != nil {
		t.Fatalf("LoadOverride() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v — the fixture's premise is that a "+
			"port-mirroring instance with no output interface commits cleanly; "+
			"if a strict gate now rejects it, this test is exercising a state "+
			"the operator can no longer reach and must be rewritten against the "+
			"lenient Load/SyncApply path instead", err)
	}
	cfg := store.ActiveConfig()
	if cfg == nil {
		t.Fatal("ActiveConfig() = nil")
	}
	pm := cfg.ForwardingOptions.PortMirroring
	if pm == nil || len(pm.Instances) != 2 {
		t.Fatalf("compiled port-mirroring instances = %v, want exactly 2", pm)
	}
	// Ground truth. Without this pin a predicate that stopped recognising the
	// shape would make every assertion below agree on "installed" and the
	// whole file would pass over an empty set.
	if got := config.PortMirroringInstanceExcludedReason(pm.Instances["dropped"]); got != "no output interface configured" {
		t.Fatalf("fixture no longer constructs a dropped instance: reason = %q", got)
	}
	if got := config.PortMirroringInstanceExcludedReason(pm.Instances["armed"]); got != "" {
		t.Fatalf("fixture's healthy instance is not healthy: reason = %q", got)
	}
	return store
}

// instanceBlock returns the render lines belonging to one instance, so an
// assertion cannot be satisfied by an annotation printed against the OTHER
// instance. Matching "NOT INSTALLED" anywhere in the whole output would pass
// for a renderer that annotated the healthy instance and not the dropped one.
func instanceBlock(t *testing.T, out, name string) string {
	t.Helper()
	lines := strings.Split(out, "\n")
	start := -1
	for i, l := range lines {
		if strings.Contains(l, "Instance: "+name) {
			start = i
			break
		}
	}
	if start < 0 {
		t.Fatalf("instance %q absent from render:\n--- output ---\n%s", name, out)
	}
	end := len(lines)
	for i := start + 1; i < len(lines); i++ {
		if strings.Contains(lines[i], "Instance: ") {
			end = i
			break
		}
	}
	return strings.Join(lines[start:end], "\n")
}

// TestCLIPortMirroringSurfacesAnnotateTheDroppedInstance6534 drives BOTH local
// CLI render paths over one config and requires the same verdict from each.
//
// `show forwarding-options` is the path this test was written for. Deleting the
// annotation from either renderer reds exactly one subtest, so a failure names
// the surface that resumed lying rather than "port-mirroring broke".
func TestCLIPortMirroringSurfacesAnnotateTheDroppedInstance6534(t *testing.T) {
	store := mirrorSurfaceCLIStore(t)
	c := &CLI{store: store}

	surfaces := []struct {
		name   string
		render func() error
	}{
		{"show_forwarding-options_port-mirroring", c.showPortMirroring},
		{"show_forwarding-options", c.showForwardingOptions},
	}

	for _, s := range surfaces {
		t.Run(s.name, func(t *testing.T) {
			out := captureStdout(t, func() {
				if err := s.render(); err != nil {
					t.Fatalf("%s: %v", s.name, err)
				}
			})

			dropped := instanceBlock(t, out, "dropped")
			if !strings.Contains(dropped, "NOT INSTALLED") {
				t.Fatalf("%s renders an instance the snapshot builder DROPS as if "+
					"it were armed — the operator sees a mirror that captures "+
					"nothing.\n--- dropped instance block ---\n%s", s.name, dropped)
			}
			if !strings.Contains(dropped, "no output interface configured") {
				t.Fatalf("%s annotated the dropped instance without naming the "+
					"reason, so the operator cannot tell WHICH condition "+
					"disarmed it.\n--- dropped instance block ---\n%s", s.name, dropped)
			}

			armed := instanceBlock(t, out, "armed")
			if strings.Contains(armed, "NOT INSTALLED") {
				t.Fatalf("%s annotated a healthy instance — crying wolf on a "+
					"mirror that works.\n--- armed instance block ---\n%s", s.name, armed)
			}

			// The premise of the whole class: these renderers print the
			// instance's operational detail. If a future change reduced this
			// surface to a pointer line (as the gRPC `show forwarding-options`
			// already is), it could no longer lie and this cell would be
			// asserting an annotation on output nobody reads for enforcement.
			if !strings.Contains(dropped, "ge-0/0/2.0") {
				t.Fatalf("%s no longer renders the dropped instance's ingress "+
					"interface, so this cell no longer exercises the #6534 shape "+
					"it was written for.\n--- dropped instance block ---\n%s",
					s.name, dropped)
			}
		})
	}
}
