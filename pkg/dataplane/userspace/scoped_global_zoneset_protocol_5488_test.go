package userspace

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// preV4SnapshotProtocolVersion is the version a pre-#4626 helper advertises and
// accepts — the value CONFIG_SNAPSHOT_PROTOCOL_VERSION held when the plural
// match_from_zones/match_to_zones fields were added as purely ADDITIVE JSON
// without a bump. It is deliberately a LITERAL, not `ProtocolVersion - 1`: the
// point of #5488 is that the current version must no longer collide with the
// version whose readers cannot see the plural fields, so the test must pin the
// historical value rather than track the constant it is checking.
const preV4SnapshotProtocolVersion = 3

// preV4HelperAcceptsSnapshot models the version gate a pre-v4 helper applies.
// It mirrors the EXACT-equality check both mutating verbs run before touching
// any dataplane state (userspace-dp/src/server/handlers/snapshot.rs, `apply` and
// `bump_fib`):
//
//	if snapshot.version != CONFIG_SNAPSHOT_PROTOCOL_VERSION { reject }
//
// Exact equality (not `<=`) is what makes the bump load-bearing: an old helper
// refuses a NEWER snapshot outright instead of decoding it under its own,
// narrower contract.
func preV4HelperAcceptsSnapshot(version int) bool {
	return version == preV4SnapshotProtocolVersion
}

// preV4HelperEffectiveScope models how a pre-#4626 helper resolves a global
// policy's zone scope: it knows only the SINGULAR match_from_zone /
// match_to_zone field, so an unknown plural field is dropped by serde's
// deny-nothing decode and never consulted. An empty singular means "any zone".
func preV4HelperEffectiveScope(singular string) []string {
	if singular == "" {
		return nil
	}
	return []string{singular}
}

func multiZoneScopedGlobalDenyConfig() *config.Config {
	return &config.Config{
		Security: config.SecurityConfig{
			GlobalPolicies: []*config.Policy{
				{
					Name: "g-deny-multi",
					Match: config.PolicyMatch{
						SourceAddresses:      []string{"any"},
						DestinationAddresses: []string{"any"},
						Applications:         []string{"any"},
						FromZones:            []string{"dmz", "trust"},
						ToZones:              []string{"untrust"},
					},
					Action: config.PolicyDeny,
				},
			},
		},
	}
}

// TestScopedGlobalMultiZoneDenyIsNotNarrowableByPreV4Helper is the #5488
// regression.
//
// #4626 lowers a multi-zone scoped global deny with the singular
// match_from_zone carrying only the FIRST zone (config.ScopeSingular) and the
// full set in the additive plural match_from_zones. That degradation is only
// safe if a reader that cannot see the plural field is never handed the
// snapshot. Before #5488 CONFIG_SNAPSHOT_PROTOCOL_VERSION was still 3 — the
// same value a pre-#4626 helper advertises and accepts — so the version
// handshake said "we agree" while the two sides disagreed about what the
// message meant: the old helper read `dmz` alone and NARROWED a global deny
// scoped `[dmz trust] -> untrust` to `dmz -> untrust`, letting trust-sourced
// traffic the operator denied fall through to lower-precedence rules
// (a rolling-upgrade fail-OPEN).
func TestScopedGlobalMultiZoneDenyIsNotNarrowableByPreV4Helper(t *testing.T) {
	cfg := multiZoneScopedGlobalDenyConfig()

	snap, err := buildSnapshotWithSchedulerStateAndNATCounters(
		cfg, deriveUserspaceConfig(cfg), 1, 0, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	if len(snap.Policies) != 1 {
		t.Fatalf("expected 1 lowered rule, got %d", len(snap.Policies))
	}
	rule := snap.Policies[0]

	// Preconditions: the emission really is narrowable when read singular-only.
	// This is the hazard the version now fences off — #4626's degradation is
	// deliberately UNCHANGED by this fix, so if these stop holding the test is
	// no longer exercising the fail-open it guards.
	if want := []string{"dmz", "trust"}; !equalStrings(rule.MatchFromZones, want) {
		t.Fatalf("plural MatchFromZones = %q, want %q", rule.MatchFromZones, want)
	}
	preV4Scope := preV4HelperEffectiveScope(rule.MatchFromZone)
	if len(preV4Scope) >= len(rule.MatchFromZones) {
		t.Fatalf("precondition failed: singular scope %q is not narrower than the configured set %q; "+
			"this test no longer exercises the #5488 fail-open", preV4Scope, rule.MatchFromZones)
	}

	// THE GUARD. The daemon stamps its own ProtocolVersion onto every snapshot.
	// A pre-v4 helper must REFUSE that snapshot, so it can never reach the
	// narrowing decode above.
	if preV4HelperAcceptsSnapshot(snap.Version) {
		t.Errorf("a pre-#4626 helper ACCEPTS the snapshot at version %d: it reads only the singular "+
			"match_from_zone %q and narrows the global deny to %q instead of the configured %q "+
			"(rolling-upgrade fail-OPEN — CONFIG_SNAPSHOT_PROTOCOL_VERSION must not collide with %d)",
			snap.Version, rule.MatchFromZone, preV4Scope, rule.MatchFromZones, preV4SnapshotProtocolVersion)
	}

	// The bump alone only makes the old helper refuse the snapshot — it keeps
	// forwarding its previous-good image with the new deny never installed. The
	// required-protocol gate turns that into a fail-CLOSED disarm plus an
	// aborted commit.
	m := New()
	m.lastStatus.ConfigSnapshotProtocolVersion = preV4SnapshotProtocolVersion
	gateErr := m.ensureRequiredSnapshotProtocolLocked(gateSnapshot(t, cfg))
	if !errors.Is(gateErr, ErrScopedGlobalZoneSetProtocolIncompatible) {
		t.Errorf("ensureRequiredSnapshotProtocolLocked against a pre-v4 helper = %v, "+
			"want ErrScopedGlobalZoneSetProtocolIncompatible (helper must be disarmed, not fed a "+
			"snapshot whose multi-zone deny it will narrow)", gateErr)
	}
	// #2138: a gate that disarms but is missing from the abort set promotes the
	// commit against a disarmed dataplane.
	if !IsRequiredProtocolGateError(gateErr) {
		t.Errorf("IsRequiredProtocolGateError(%v) = false, want true — the #5488 gate must abort the commit", gateErr)
	}

	// A helper at the current version is not gated.
	m2 := New()
	m2.lastStatus.ConfigSnapshotProtocolVersion = ProtocolVersion
	if err := m2.ensureRequiredSnapshotProtocolLocked(gateSnapshot(t, cfg)); err != nil {
		t.Errorf("current-version helper gated: %v, want nil", err)
	}
}

// TestScopedGlobalSingleZoneAndUnscopedPolicyNotGated is the negative control.
// A one-element scope lowers to singular == the one zone (bit-identical in both
// shapes, never narrowed), and an unscoped global / ordinary zone-pair policy
// carries no scope at all. None of them can be misread by a singular-only
// reader, so none may trip the #5488 gate — otherwise the fix disarms the
// common case.
func TestScopedGlobalSingleZoneAndUnscopedPolicyNotGated(t *testing.T) {
	cases := []struct {
		name        string
		cfg         *config.Config
		wantFrom    []string
		wantTo      []string
		wantSingFrm string
		wantSingTo  string
	}{
		{
			name: "single-zone scoped global deny",
			cfg: &config.Config{Security: config.SecurityConfig{
				GlobalPolicies: []*config.Policy{{
					Name: "g-deny-one",
					Match: config.PolicyMatch{
						SourceAddresses:      []string{"any"},
						DestinationAddresses: []string{"any"},
						Applications:         []string{"any"},
						FromZones:            []string{"dmz"},
						ToZones:              []string{"untrust"},
					},
					Action: config.PolicyDeny,
				}},
			}},
			wantFrom: []string{"dmz"}, wantTo: []string{"untrust"},
			wantSingFrm: "dmz", wantSingTo: "untrust",
		},
		{
			name: "unscoped global permit",
			cfg: &config.Config{Security: config.SecurityConfig{
				GlobalPolicies: []*config.Policy{{
					Name: "g-permit-any",
					Match: config.PolicyMatch{
						SourceAddresses:      []string{"any"},
						DestinationAddresses: []string{"any"},
						Applications:         []string{"any"},
					},
					Action: config.PolicyPermit,
				}},
			}},
			wantFrom: nil, wantTo: nil, wantSingFrm: "", wantSingTo: "",
		},
		{
			name: "ordinary zone-pair permit",
			cfg: &config.Config{Security: config.SecurityConfig{
				Policies: []*config.ZonePairPolicies{{
					FromZone: "trust", ToZone: "untrust",
					Policies: []*config.Policy{{
						Name: "zp-permit",
						Match: config.PolicyMatch{
							SourceAddresses:      []string{"any"},
							DestinationAddresses: []string{"any"},
							Applications:         []string{"any"},
						},
						Action: config.PolicyPermit,
					}},
				}},
			}},
			wantFrom: nil, wantTo: nil, wantSingFrm: "", wantSingTo: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			snaps, err := buildPolicySnapshots(tc.cfg)
			if err != nil {
				t.Fatalf("buildPolicySnapshots: %v", err)
			}
			if len(snaps) != 1 {
				t.Fatalf("expected 1 lowered rule, got %d", len(snaps))
			}
			s := snaps[0]
			if !equalStrings(s.MatchFromZones, tc.wantFrom) || !equalStrings(s.MatchToZones, tc.wantTo) {
				t.Errorf("plural scope = %q->%q, want %q->%q",
					s.MatchFromZones, s.MatchToZones, tc.wantFrom, tc.wantTo)
			}
			if s.MatchFromZone != tc.wantSingFrm || s.MatchToZone != tc.wantSingTo {
				t.Errorf("singular scope = %q->%q, want %q->%q",
					s.MatchFromZone, s.MatchToZone, tc.wantSingFrm, tc.wantSingTo)
			}
			// A singular-only reader resolves the SAME scope as a plural-aware
			// one, so there is nothing for the version to fence off.
			if got := preV4HelperEffectiveScope(s.MatchFromZone); !equalStrings(got, s.effectiveMatchFromZones()) {
				t.Errorf("pre-v4 from-zone scope %q != effective %q — this shape IS narrowable and must be gated",
					got, s.effectiveMatchFromZones())
			}
			if got := preV4HelperEffectiveScope(s.MatchToZone); !equalStrings(got, s.effectiveMatchToZones()) {
				t.Errorf("pre-v4 to-zone scope %q != effective %q — this shape IS narrowable and must be gated",
					got, s.effectiveMatchToZones())
			}

			// The gate must stay silent even against the oldest helper.
			m := New()
			m.lastStatus.ConfigSnapshotProtocolVersion = preV4SnapshotProtocolVersion
			if err := m.ensureScopedGlobalZoneSetProtocolLocked(tc.cfg); err != nil {
				t.Errorf("gate fired on a non-narrowable config: %v, want nil", err)
			}
		})
	}
}

// TestScopedGlobalZoneSetGateCoversBothScopeSides pins BOTH halves of
// policyScopeIsMultiZone (`len(FromZones) > 1 || len(ToZones) > 1`) to a
// reachable config, and the predicate to the whole emission surface.
//
// The to-zone half needs its own REACHABLE positive case: an ordinary Junos
// `global policy p match { from-zone trust; to-zone [ untrust dmz ]; }` is a
// multi-zone scope on the TO side only, and `ScopeSingular` narrows it to
// `untrust` exactly as it narrows the from side. Without this row the to-zone
// half of the predicate would be pinned only by the zone-pair row below, whose
// shape the compiler never actually produces (`compiler_security_policy.go`
// populates Match.FromZones/ToZones only for global policies) — a guard scoped
// narrower than the claim it protects, and one a future cleanup could delete as
// "tests an unreachable branch".
func TestScopedGlobalZoneSetGateCoversBothScopeSides(t *testing.T) {
	globalScoped := func(name string, from, to []string) *config.Config {
		return &config.Config{Security: config.SecurityConfig{
			GlobalPolicies: []*config.Policy{{
				Name: name,
				Match: config.PolicyMatch{
					SourceAddresses:      []string{"any"},
					DestinationAddresses: []string{"any"},
					Applications:         []string{"any"},
					FromZones:            from,
					ToZones:              to,
				},
				Action: config.PolicyDeny,
			}},
		}}
	}

	cases := []struct {
		name        string
		cfg         *config.Config
		wantSingFrm string
		wantSingTo  string
	}{
		{
			// The from-side hazard (the shape in the issue report).
			name:        "global multi-zone FROM side",
			cfg:         globalScoped("g-from-multi", []string{"dmz", "trust"}, []string{"untrust"}),
			wantSingFrm: "dmz", wantSingTo: "untrust",
		},
		{
			// The to-side hazard — reachable, ordinary Junos:
			//   global policy g match { from-zone trust; to-zone [ untrust dmz ]; }
			name:        "global multi-zone TO side",
			cfg:         globalScoped("g-to-multi", []string{"trust"}, []string{"dmz", "untrust"}),
			wantSingFrm: "trust", wantSingTo: "dmz",
		},
		{
			name:        "global multi-zone BOTH sides",
			cfg:         globalScoped("g-both-multi", []string{"dmz", "trust"}, []string{"untrust", "wan"}),
			wantSingFrm: "dmz", wantSingTo: "untrust",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The narrowing is real on this shape: the singular field a pre-v4
			// helper reads resolves a STRICTLY smaller scope than configured.
			snaps, err := buildPolicySnapshots(tc.cfg)
			if err != nil {
				t.Fatalf("buildPolicySnapshots: %v", err)
			}
			if len(snaps) != 1 {
				t.Fatalf("expected 1 lowered rule, got %d", len(snaps))
			}
			s := snaps[0]
			if s.MatchFromZone != tc.wantSingFrm || s.MatchToZone != tc.wantSingTo {
				t.Errorf("singular scope = %q->%q, want %q->%q",
					s.MatchFromZone, s.MatchToZone, tc.wantSingFrm, tc.wantSingTo)
			}
			narrowed := false
			if got := preV4HelperEffectiveScope(s.MatchFromZone); len(got) < len(s.effectiveMatchFromZones()) {
				narrowed = true
			}
			if got := preV4HelperEffectiveScope(s.MatchToZone); len(got) < len(s.effectiveMatchToZones()) {
				narrowed = true
			}
			if !narrowed {
				t.Fatalf("precondition failed: neither side is narrowed by a singular-only reader "+
					"(from %q->%q, to %q->%q); this row no longer exercises the #5488 fail-open",
					s.MatchFromZone, s.effectiveMatchFromZones(), s.MatchToZone, s.effectiveMatchToZones())
			}

			m := New()
			m.lastStatus.ConfigSnapshotProtocolVersion = preV4SnapshotProtocolVersion
			if err := m.ensureScopedGlobalZoneSetProtocolLocked(tc.cfg); !errors.Is(err, ErrScopedGlobalZoneSetProtocolIncompatible) {
				t.Errorf("gate = %v, want ErrScopedGlobalZoneSetProtocolIncompatible", err)
			}
		})
	}

	// Defensive breadth: lowerPolicy stamps the singular fields from the same
	// Match for EVERY rule, not just the global tier, so the predicate scans the
	// zone-pair tier too. The compiler does not produce this shape today
	// (compiler_security_policy.go populates the scope only for globals), so
	// this row guards the emission surface rather than a reachable config.
	t.Run("zone-pair tier (defensive, not compiler-reachable)", func(t *testing.T) {
		cfg := &config.Config{Security: config.SecurityConfig{
			Policies: []*config.ZonePairPolicies{{
				FromZone: "trust", ToZone: "untrust",
				Policies: []*config.Policy{{
					Name: "zp-scoped",
					Match: config.PolicyMatch{
						SourceAddresses:      []string{"any"},
						DestinationAddresses: []string{"any"},
						Applications:         []string{"any"},
						ToZones:              []string{"untrust", "dmz"},
					},
					Action: config.PolicyDeny,
				}},
			}},
		}}
		m := New()
		m.lastStatus.ConfigSnapshotProtocolVersion = preV4SnapshotProtocolVersion
		if err := m.ensureScopedGlobalZoneSetProtocolLocked(cfg); !errors.Is(err, ErrScopedGlobalZoneSetProtocolIncompatible) {
			t.Errorf("zone-pair tier multi-zone scope = %v, want ErrScopedGlobalZoneSetProtocolIncompatible", err)
		}
	})
}

// TestSnapshotProtocolVersionLockstepWithRust guards the failure mode that
// created #5488 in the first place: the Go emitter and the Rust consumer gate
// on EXACT version equality, so a one-sided change silently breaks every apply.
// Parse the Rust constant instead of mirroring it in a comment.
func TestSnapshotProtocolVersionLockstepWithRust(t *testing.T) {
	// Test cwd is pkg/dataplane/userspace.
	path := filepath.Join("..", "..", "..", "userspace-dp", "src", "protocol", "control.rs")
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v (the Go/Rust snapshot protocol version lockstep guard cannot run)", path, err)
	}
	re := regexp.MustCompile(`(?m)^pub\(crate\) const CONFIG_SNAPSHOT_PROTOCOL_VERSION: i32 = (\d+);`)
	match := re.FindSubmatch(src)
	if match == nil {
		t.Fatalf("CONFIG_SNAPSHOT_PROTOCOL_VERSION declaration not found in %s — "+
			"if it was renamed or moved, update this lockstep guard rather than deleting it", path)
	}
	rustVersion, err := strconv.Atoi(string(match[1]))
	if err != nil {
		t.Fatalf("parse rust CONFIG_SNAPSHOT_PROTOCOL_VERSION %q: %v", match[1], err)
	}
	if rustVersion != ProtocolVersion {
		t.Fatalf("snapshot protocol version skew: Go ProtocolVersion = %d, Rust "+
			"CONFIG_SNAPSHOT_PROTOCOL_VERSION = %d. Both apply_snapshot and bump_fib_generation "+
			"gate on EXACT equality, so the two MUST be bumped together.",
			ProtocolVersion, rustVersion)
	}
	if rustVersion <= preV4SnapshotProtocolVersion {
		t.Fatalf("snapshot protocol version = %d, must be > %d (#5488): the plural "+
			"match_from_zones/match_to_zones scope fields changed deny COVERAGE, so the version "+
			"must not collide with the pre-#4626 value whose readers ignore them",
			rustVersion, preV4SnapshotProtocolVersion)
	}
	// The Rust comment must keep naming the issue so the reason for the value
	// survives the next bump.
	if !strings.Contains(string(src), "#5488") {
		t.Errorf("%s no longer explains the #5488 reason for the version floor", path)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
