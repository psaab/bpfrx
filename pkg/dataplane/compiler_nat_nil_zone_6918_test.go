package dataplane

import (
	"context"
	"log/slog"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// capturingHandler records the message of every slog record emitted during a
// compile, so a test can assert HOW FAR execution got rather than only that it
// survived.
type capturingHandler6918 struct{ msgs *[]string }

func (h capturingHandler6918) Enabled(context.Context, slog.Level) bool { return true }
func (h capturingHandler6918) Handle(_ context.Context, r slog.Record) error {
	*h.msgs = append(*h.msgs, r.Message)
	return nil
}
func (h capturingHandler6918) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h capturingHandler6918) WithGroup(string) slog.Handler      { return h }

func captureCompileNAT6918(t *testing.T, cfg *config.Config) ([]string, error) {
	t.Helper()
	var msgs []string
	prev := slog.Default()
	slog.SetDefault(slog.New(capturingHandler6918{msgs: &msgs}))
	t.Cleanup(func() { slog.SetDefault(prev) })
	// assignZoneIDs is production's prelude to compileNAT (compiler.go runs it
	// before the NAT phase); without it the from-zone lookup fails first and the
	// to-zone path under test is never reached.
	result := newValidationResult()
	assignZoneIDs(result, cfg)
	return msgs, compileNAT(idProbeDP{}, cfg, result)
}

// snatInterfaceModeCfg6918 builds the smallest config that reaches the
// interface-mode to-zone resolution in compileNAT: one SNAT rule set whose rule
// is `then source-nat interface`, with the named to-zone slot populated by the
// caller.
func snatInterfaceModeCfg6918(toZone string, zone *config.ZoneConfig) *config.Config {
	cfg := &config.Config{}
	// The from-zone is a REAL zone in both cases: only the to-zone slot varies
	// between them, so nothing but the field under test can change the outcome.
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {Interfaces: []string{"ge-0-0-1"}},
		toZone:  zone,
	}
	cfg.Security.NAT.Source = []*config.NATRuleSet{{
		Name:     "rs1",
		FromZone: "trust",
		ToZone:   toZone,
		Rules: []*config.NATRule{{
			Name: "r1",
			Then: config.NATThen{Interface: true},
		}},
	}}
	return cfg
}

// TestCompileNATSkipsANilToZone6918 is the #6918 guard.
//
// A map entry present with a NIL *ZoneConfig makes the two-value lookup's `ok`
// true, so a guard testing `ok` alone falls through to `toZoneCfg.Interfaces`
// and panics the compile. compiler_iface.go's sibling sweep already treats a nil
// zone slot as reachable — its comment names the tolerant/programmatic and
// HA-peer-sync paths, which do not go through the parser that always allocates a
// zone. compileNAT did not, and this is the only site in the tree that did not:
// every other `Security.Zones[...]` read either discards the value, checks it
// inline, or routes through a `zone != nil` helper.
//
// RED-on-revert: dropping `toZoneCfg == nil` from the guard makes this PANIC,
// which is a test failure naming this function.
func TestCompileNATSkipsANilToZone6918(t *testing.T) {
	cfg := snatInterfaceModeCfg6918("untrust", nil)

	msgs, err := captureCompileNAT6918(t, cfg)
	if err != nil {
		t.Fatalf("compileNAT returned an error for a nil to-zone: %v", err)
	}
	if !containsMsg6918(msgs, "to-zone has no interfaces") {
		t.Fatalf("nil to-zone did not take the skip branch; records = %v.\n"+
			"A nil zone must be treated exactly like a zone with no interfaces — "+
			"the rule resolves nothing either way.", msgs)
	}
}

// TestCompileNATPopulatedToZoneReachesTheInterfaceLoop6918 is the paired
// control, and it is what stops the test above from being vacuous.
//
// "Did not panic" is satisfied by a config that never reaches the deref at all,
// so the nil case alone cannot distinguish "the guard works" from "the fixture
// misses the code". This case differs from it in ONE field — the zone slot is
// populated instead of nil — and must get PAST the guard into the interface
// loop, which it proves by failing LATER with a different message. Two different
// messages from one field change is what establishes the nil case is being
// decided at the guard rather than never arriving.
func TestCompileNATPopulatedToZoneReachesTheInterfaceLoop6918(t *testing.T) {
	cfg := snatInterfaceModeCfg6918("untrust", &config.ZoneConfig{
		Interfaces: []string{"ge-0-0-0"},
	})

	msgs, err := captureCompileNAT6918(t, cfg)
	if err != nil {
		t.Fatalf("compileNAT: %v", err)
	}
	if containsMsg6918(msgs, "to-zone has no interfaces") {
		t.Fatalf("a zone WITH an interface took the no-interfaces skip; records = %v.\n"+
			"If this branch is taken here too, the nil-zone test above proves nothing: "+
			"both cases would stop at the guard and neither would reach the deref.", msgs)
	}
	if !containsMsg6918(msgs, "no IP addresses for interface SNAT") {
		t.Fatalf("populated to-zone did not reach the interface loop; records = %v", msgs)
	}
}

func containsMsg6918(msgs []string, want string) bool {
	for _, m := range msgs {
		if m == want {
			return true
		}
	}
	return false
}
