package api

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/natshow"
)

// #6565: the REST show-text NAT views must produce BYTE-IDENTICAL output to the
// shared pkg/natshow renderers — the same renderers the CLI
// (cli_show_nat.go:860,900) and gRPC (server_show_nat.go:31,37) call.
//
// This is the third leg of the #1687 invariant. CLI and gRPC have had a
// byte-equality test against the shared renderer for a long time
// (cli_show_nat_shared_test.go, server_show_nat_shared_test.go). REST never
// did — and REST is the surface that drifted. It reimplemented both views,
// printing every rule straight from config, so the fail-closed annotations
// became a per-surface lottery:
//
//   - #5323 taught two surfaces to say NOT INSTALLED for a rule the userspace
//     snapshot builder drops; REST kept rendering it as live.
//   - #6534 taught two surfaces a further set of exclusion reasons; REST again
//     kept rendering the dropped rule as live.
//
// Each fix landed on a strict subset of the three copies — which is the very
// failure mode the #6565 cohort was filed about, reproduced by the cohort's own
// fixes. Tying every surface to one renderer catches the NEXT one too, which is
// why this is worth more than annotating any individual row: with REST
// delegating, it inherits every annotation natshow has now and every one it
// gains later, for free and by construction.
//
// FAIL-ON-REVERT: reinstate the hand-rolled `case "nat-static"` /
// `case "nat-nptv6"` bodies in show_text.go and the byte-equality subtests go
// red on the very first rule.

// stageTolerantNATConfig drives the TOLERANT ingress (Store.SyncApply — the HA
// peer-sync path, which shares compileTreeLenient with Store.Load) and returns
// a Server bound to the resulting active config.
//
// It has to be the tolerant path. Every exclusion `staticRuleNotInstalledReason`
// reports is ALSO hard-rejected by a strict commit gate (`then static-nat inet`
// by #5859; the NPTv6 scope forms by #5818), so an excluded rule cannot reach
// `ActiveConfig` through a commit at all — a fixture staged with LoadSet+Commit
// contains no exclusion, both renderers agree byte-for-byte, and the whole test
// passes on the UNFIXED code. (Measured: with a commit-staged fixture the
// verbatim pre-fix mutation did not red.)
//
// An excluded rule reaches ActiveConfig only on the tolerant ingress — a
// persisted config loaded at boot, or a section synced from a cluster peer —
// where those gates downgrade to warnings under the #1960 no-brick doctrine.
// That is a real boot path and a real cluster path, and it is exactly the one
// on which the REST surface was lying.
func stageTolerantNATConfig(t *testing.T, src string) *Server {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if _, err := store.SyncApply(src, nil); err != nil {
		t.Fatalf("SyncApply (tolerant ingress): %v", err)
	}
	return &Server{store: store}
}

// tolerantNATSrc carries BOTH an installable rule and one the userspace
// snapshot builder DROPS, in each view, so the renderers can only agree by
// agreeing about the annotation.
const tolerantNATSrc = `security {
    nat {
        static {
            rule-set rs-static {
                from {
                    zone trust;
                }
                rule s-ok {
                    match {
                        destination-address 192.0.2.10/32;
                    }
                    then {
                        static-nat {
                            prefix 10.0.1.10/32;
                        }
                    }
                }
                rule s-inet {
                    match {
                        destination-address 192.0.2.11/32;
                    }
                    then {
                        static-nat {
                            inet;
                        }
                    }
                }
                rule n-ok {
                    match {
                        destination-address 2001:db8:a::/64;
                    }
                    then {
                        static-nat {
                            nptv6-prefix fd00:a::/64;
                        }
                    }
                }
                rule n-drop {
                    match {
                        destination-address 2001:db8:b::/64;
                        source-address 2001:db8:c::/64;
                    }
                    then {
                        static-nat {
                            nptv6-prefix fd00:b::/64;
                        }
                    }
                }
            }
        }
    }
}
`

func TestRESTNATViewsMatchSharedRenderers(t *testing.T) {
	s := stageTolerantNATConfig(t, tolerantNATSrc)
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		t.Fatal("no active config staged")
	}
	// Guard the premise: the fixture must actually carry an exclusion, or the
	// two renderers agree trivially and this test cannot fail.
	rs := cfg.Security.NAT.Static[0]
	staticExcluded, nptv6Excluded := 0, 0
	for _, r := range rs.Rules {
		if r.IsNPTv6 {
			if config.NPTv6ScopeUnsupported(rs, r) {
				nptv6Excluded++
			}
		} else if config.StaticNATRuleExcludedReason(r) != "" {
			staticExcluded++
		}
	}
	// Each VIEW needs its own excluded rule. With only a static exclusion the
	// nptv6 subtest compares two renderings that agree trivially and passes on
	// the unfixed code — measured, on the first draft of this test.
	if staticExcluded == 0 || nptv6Excluded == 0 {
		t.Fatalf("premise: fixture needs an excluded rule in BOTH views "+
			"(static=%d nptv6=%d), else a subtest agrees trivially",
			staticExcluded, nptv6Excluded)
	}

	cases := []struct {
		name  string
		topic string
		want  func(*strings.Builder)
	}{
		{"static", "nat-static", func(b *strings.Builder) { natshow.RenderStatic(b, cfg) }},
		{"nptv6", "nat-nptv6", func(b *strings.Builder) { natshow.RenderNPTv6(b, cfg) }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := renderShowTextBody(t, s, tc.topic)
			var want strings.Builder
			tc.want(&want)
			if got != want.String() {
				t.Errorf("REST topic %q diverges from the shared natshow "+
					"renderer — REST is an independent third copy again, and "+
					"every future fail-closed annotation will miss it\n"+
					"--- REST ---\n%s\n--- natshow ---\n%s",
					tc.topic, got, want.String())
			}
			// Guard the premise: byte-equality between two EMPTY strings would
			// pass while proving nothing.
			if !strings.Contains(got, "rs-static") {
				t.Fatalf("topic %q rendered nothing recognisable — the fixture "+
					"no longer exercises the view:\n%s", tc.topic, got)
			}
		})
	}
}

// TestSharedRendererAnnotatesANotInstalledRule pins the other half of the
// property. Byte-equality alone would still hold if BOTH REST and the shared
// renderer stopped annotating, so this asserts the annotation exists in the
// renderer REST now delegates to — which is what makes the delegation worth
// having.
//
// The fixture is hand-built rather than committed on purpose. Every exclusion
// `staticRuleNotInstalledReason` reports is ALSO hard-rejected by a strict
// commit gate (`then static-nat inet` by #5859; the NPTv6 scope forms by
// #5818), so an excluded rule cannot reach `ActiveConfig` through a commit at
// all. It reaches it only on the TOLERANT ingress — `Store.Load` of an
// already-persisted config and HA `SyncApply` from a peer — where those gates
// downgrade to warnings by the #1960 no-brick doctrine. That is a real boot
// path and a real cluster path, and it is the one on which REST was lying.
func TestSharedRendererAnnotatesANotInstalledRule(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.NAT.Static = []*config.StaticNATRuleSet{
		{
			Name: "rs-static", FromZone: "trust",
			Rules: []*config.StaticNATRule{
				{Name: "s-ok", Match: "192.0.2.10", Then: "10.0.1.10"},
				{Name: "s-inet", Match: "192.0.2.11", Then: "inet"},
			},
		},
	}
	rs := cfg.Security.NAT.Static[0]
	// Premises, so a fixture that stopped exercising the drop cannot make this
	// vacuous in either direction.
	if config.StaticNATRuleExcludedReason(rs.Rules[1]) == "" {
		t.Fatal("premise: s-inet is no longer an excluded static-NAT rule")
	}
	if config.StaticNATRuleExcludedReason(rs.Rules[0]) != "" {
		t.Fatal("premise: s-ok is no longer installable")
	}

	var b strings.Builder
	natshow.RenderStatic(&b, cfg)
	out := b.String()
	if !strings.Contains(out, "NOT INSTALLED") {
		t.Errorf("the shared renderer does not annotate a rule the snapshot "+
			"builder DROPS — an operator reads it as live when nothing is "+
			"programmed:\n%s", out)
	}
	// Negative control: the annotation must not fire on the installable rule.
	// An annotation on every rule would satisfy the assertion above while
	// telling the operator nothing.
	okIdx := strings.Index(out, "s-ok")
	inetIdx := strings.Index(out, "s-inet")
	if okIdx < 0 || inetIdx < 0 {
		t.Fatalf("both rules must render:\n%s", out)
	}
	between := out[okIdx:inetIdx]
	if strings.Contains(between, "NOT INSTALLED") {
		t.Errorf("the installable rule s-ok was annotated NOT INSTALLED:\n%s", out)
	}
}
