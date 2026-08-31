package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #6565 row 8 / #7422 — `show firewall` rendered `then dscp <token>` for a
// rewrite the snapshot builder had DROPPED, so the operator read a CoS marking
// the dataplane was not applying.
//
// Reachability. The strict commit gate (config.validateFilterDSCPStrict, #3309)
// hard-rejects an unresolvable dscp/traffic-class token, so an ORDINARY commit
// cannot reach this state and a Commit()-based fixture would be asserting
// against output nobody can produce. The state is reached through the tolerant
// path (#1960 no-brick): Store.SyncApply — HA peer config-sync from a
// possibly-un-upgraded primary — downgrades the strict validators, and the
// config goes ACTIVE with the bad token intact. The fixture below performs
// exactly that ingest, which is also the situation an operator is most likely
// to be reading `show firewall` in: a standby that took a config from its peer
// and is not marking traffic the config says it marks.

// filterDSCPSyncStore ingests, through the LENIENT peer-sync path, one filter
// carrying two terms: `armed` with a resolvable rewrite and `dropped` with an
// unresolvable one.
//
// Two terms, not one, on purpose: with only the dropped term a renderer that
// annotated unconditionally would pass every cell below. The armed term is the
// negative control that makes "annotates" mean "annotates the right one".
func filterDSCPSyncStore(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	cfg, err := store.SyncApply(`
firewall {
    family inet {
        filter mark {
            term armed {
                from {
                    protocol tcp;
                }
                then {
                    dscp ef;
                    accept;
                }
            }
            term dropped {
                from {
                    protocol udp;
                }
                then {
                    dscp not-a-code-point;
                    accept;
                }
            }
        }
    }
}
`, nil)
	if err != nil {
		t.Fatalf("SyncApply() error = %v — the fixture's premise is that the "+
			"LENIENT peer-sync path admits an unresolvable `then dscp` token "+
			"(the strict commit gate rejects it). If sync now rejects it too, "+
			"this row is unreachable and the test must be rewritten, not "+
			"loosened", err)
	}
	// Ground truth, both directions. Without these pins a compiler that stopped
	// storing DSCPRewrite at all would make every assertion below agree on
	// "nothing to annotate" and the file would pass over an empty set.
	f := cfg.Firewall.FiltersInet["mark"]
	if f == nil || len(f.Terms) != 2 {
		t.Fatalf("compiled filter = %v, want 2 terms", f)
	}
	byName := map[string]*config.FirewallFilterTerm{}
	for _, term := range f.Terms {
		byName[term.Name] = term
	}
	if got := byName["dropped"].DSCPRewrite; got != "not-a-code-point" {
		t.Fatalf("dropped term DSCPRewrite = %q, want the unresolvable token "+
			"verbatim — the fixture no longer constructs the defect's input", got)
	}
	if got := byName["armed"].DSCPRewrite; got != "ef" {
		t.Fatalf("armed term DSCPRewrite = %q, want %q", got, "ef")
	}
	if _, ok := dataplane.ResolveFilterDSCP("not-a-code-point"); ok {
		t.Fatal("the fixture's `unresolvable` token now resolves; pick another")
	}
	if _, ok := dataplane.ResolveFilterDSCP("ef"); !ok {
		t.Fatal("the fixture's `armed` token no longer resolves")
	}
	return store
}

// TestBuilderDropsTheRewriteTheRendererIsAskedAbout7422 is the premise the
// annotation rests on: the snapshot builder really does discard this rewrite.
//
// Asserting it here rather than in prose is what keeps the CLI cells honest —
// an annotation whose builder half quietly started installing the token would
// be crying wolf, and no cell in this file could tell.
func TestBuilderDropsTheRewriteTheRendererIsAskedAbout7422(t *testing.T) {
	store := filterDSCPSyncStore(t)
	snaps := dpuserspace.BuildFirewallFilterSnapshots(store.ActiveConfig())
	var seen int
	for _, fs := range snaps {
		for _, term := range fs.Terms {
			switch term.Name {
			case "armed":
				seen++
				if term.DSCPRewrite == nil {
					t.Error("builder dropped the RESOLVABLE `then dscp ef` rewrite; " +
						"the renderer's annotation would now be correct for the " +
						"wrong reason")
				}
			case "dropped":
				seen++
				if term.DSCPRewrite != nil {
					t.Errorf("builder now installs `then dscp not-a-code-point` "+
						"as %d — the show annotation this file guards has become "+
						"a lie in the other direction", *term.DSCPRewrite)
				}
			}
		}
	}
	if seen != 2 {
		t.Fatalf("found %d of the 2 fixture terms in the snapshot; the builder "+
			"stopped emitting them and every cell above asserted nothing", seen)
	}
}

// TestCLIFirewallFilterSurfacesAnnotateTheDroppedRewrite7422 drives BOTH local
// `show firewall` render paths over one config and requires the same verdict
// from each.
//
// Two call sites, not one: showFirewallFilters (all filters) and
// showFirewallFilter (one named filter) each printed the rewrite line
// independently, which is exactly how the renderer and the builder came to
// disagree in the first place. Deleting the annotation from either reds its own
// subtest, so a failure names the surface that resumed lying.
func TestCLIFirewallFilterSurfacesAnnotateTheDroppedRewrite7422(t *testing.T) {
	store := filterDSCPSyncStore(t)
	c := &CLI{store: store}

	surfaces := []struct {
		name   string
		render func() error
	}{
		{"show_firewall", c.showFirewallFilters},
		{"show_firewall_filter_mark", func() error { return c.showFirewallFilter("mark", "") }},
	}

	for _, s := range surfaces {
		t.Run(s.name, func(t *testing.T) {
			out := captureStdout(t, func() {
				if err := s.render(); err != nil {
					t.Fatalf("%s: %v", s.name, err)
				}
			})

			dropped := termBlock7422(t, out, "dropped")
			if !strings.Contains(dropped, "not-a-code-point") {
				t.Fatalf("%s no longer renders the configured rewrite at all. "+
					"Hiding it makes `show firewall` disagree with `show "+
					"configuration`; the contract is to render it AND say it is "+
					"not installed.\n--- term block ---\n%s", s.name, dropped)
			}
			if !strings.Contains(dropped, "NOT INSTALLED") {
				t.Fatalf("%s renders a `then dscp` the snapshot builder DROPS as "+
					"if it were applied — the operator reads a CoS marking that "+
					"never happens.\n--- term block ---\n%s", s.name, dropped)
			}
			if !strings.Contains(dropped, "the term still matches and acts") {
				t.Fatalf("%s annotated the dropped rewrite without saying the "+
					"term is otherwise ENFORCED. `NOT INSTALLED` alone reads as "+
					"'this term does nothing', which is the opposite of the "+
					"truth and would send the operator after the wrong "+
					"fault.\n--- term block ---\n%s", s.name, dropped)
			}

			armed := termBlock7422(t, out, "armed")
			if !strings.Contains(armed, "then dscp ef") {
				t.Fatalf("%s stopped rendering the armed term's rewrite:\n%s", s.name, armed)
			}
			if strings.Contains(armed, "NOT INSTALLED") {
				t.Fatalf("%s annotated a rewrite the dataplane DOES install — "+
					"crying wolf on a working term.\n--- term block ---\n%s", s.name, armed)
			}
		})
	}
}

// termBlock7422 returns the render lines belonging to one term, so an assertion
// cannot be satisfied by an annotation printed against the OTHER term. Matching
// "NOT INSTALLED" anywhere in the whole output would pass for a renderer that
// annotated the armed term and not the dropped one.
func termBlock7422(t *testing.T, out, name string) string {
	t.Helper()
	lines := strings.Split(out, "\n")
	start := -1
	for i, l := range lines {
		if strings.Contains(l, "Term: "+name) {
			start = i
			break
		}
	}
	if start < 0 {
		t.Fatalf("term %q absent from render:\n--- output ---\n%s", name, out)
	}
	end := len(lines)
	for i := start + 1; i < len(lines); i++ {
		if strings.Contains(lines[i], "Term: ") {
			end = i
			break
		}
	}
	return strings.Join(lines[start:end], "\n")
}
