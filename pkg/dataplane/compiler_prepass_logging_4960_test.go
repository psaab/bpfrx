package dataplane

// #6894 r8 F6: the pre-pass must not log SUCCESS for work it did not perform.
//
// Every dataplane write in the pre-pass is a no-op on the discarding shim, yet
// the covered phases logged "static NAT compilation complete", "compiled NAT64
// prefix", "flow timeouts compiled" and friends unconditionally. On a FAILED
// apply an operator therefore read a journal that reported a compile
// succeeding and then failing, for a compile whose result was thrown away.
//
// WARN duplication inside the same phases is deliberately NOT addressed here
// and stays on #6903: a soft-skip diagnostic appearing twice is noise, whereas
// a success record for work that did not happen is a false claim.

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"log/slog"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// prepassSuccessLogMarkers are the message substrings that assert completed
// work. They are matched against the message only, not the whole record, so an
// attribute that happens to contain one of these words cannot produce a false
// red.
var prepassSuccessLogMarkers = []string{
	"compiled", "complete", "registered", "auto-assigned", "IP resolved",
}

// captureSlog redirects the default logger into a buffer for the duration of
// the test. Same idiom as armproof_5275_test.go.
func captureSlog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))
	t.Cleanup(func() { slog.SetDefault(old) })
	return &buf
}

// successLogLines returns the captured INFO records whose MESSAGE carries one
// of the completed-work markers.
//
// It returns the WHOLE line, not the extracted message (#6894 r9 F2). The
// marker match still runs against the message alone -- an attribute containing
// "compiled" must not produce a false red -- but two of the gated sites emit
// the SAME message and differ only in an attribute (`default policy compiled`
// with action=permit-all vs action=deny-all). Returning messages made those two
// indistinguishable, so the over-reach arm bound whichever arm the fixture
// happened to take and the other could be suppressed on both passes unnoticed.
func successLogLines(buf *bytes.Buffer) []string {
	var out []string
	for _, line := range strings.Split(buf.String(), "\n") {
		if line == "" || !strings.Contains(line, "level=INFO") {
			continue
		}
		// slog's text handler renders the message as msg="..." (quoted when it
		// contains spaces, which every one of these does).
		i := strings.Index(line, `msg="`)
		if i < 0 {
			continue
		}
		rest := line[i+len(`msg="`):]
		j := strings.Index(rest, `"`)
		if j < 0 {
			continue
		}
		msg := rest[:j]
		for _, marker := range prepassSuccessLogMarkers {
			if strings.Contains(msg, marker) {
				out = append(out, line)
				break
			}
		}
	}
	return out
}

// warnLogLines returns the captured WARN records' messages.
//
// The WARN family is out of F6's scope as a DUPLICATION concern (#6903 owns
// that). It is in scope here for one reason: exactly one WARN site carries an
// `!isValidationPass(dp)` gate, and a gate nothing observes can be widened to
// suppress the real pass too — which would lose an operator diagnostic on a
// security-relevant fail-open path. See the assertion in the over-reach test.
func warnLogLines(buf *bytes.Buffer) []string {
	var out []string
	for _, line := range strings.Split(buf.String(), "\n") {
		if line == "" || !strings.Contains(line, "level=WARN") {
			continue
		}
		out = append(out, line)
	}
	return out
}

// logProbeConfig is idProbeConfig plus the stanzas that make the REMAINING
// gated records reachable. idProbeConfig itself is deliberately left alone: it
// is the ID-determinism fixture and every column of that comparison is pinned
// to its current shape.
//
// Each addition exists to reach ONE otherwise-unreachable gated site (#6894 r9
// F2). Before them the over-reach arm named 13 of the 19 gated records, so six
// gates could be widened to suppress the REAL pass as well with the package
// still green.
func logProbeConfig() *config.Config {
	cfg := idProbeConfig()
	// compileFlowTimeouts' success record.
	cfg.Security.Flow.UDPSessionTimeout = 60
	// `source NAT off rule compiled`: the no-NAT exemption branch (#3844) is a
	// separate write path from the pool and interface branches idProbeConfig
	// already carries, with its own gated record.
	cfg.Security.NAT.Source = append(cfg.Security.NAT.Source, &config.NATRuleSet{
		Name: "rs-off-6894", FromZone: "trust", ToZone: "dmz",
		Rules: []*config.NATRule{
			{Name: "r-off", Match: config.NATMatch{SourceAddress: "10.9.0.0/16"},
				Then: config.NATThen{Type: config.NATSource, Off: true}},
		},
	})
	// `persistent NAT pool registered`: guarded by `dp.GetPersistentNAT() !=
	// nil`, so it needs BOTH a persistent-nat pool here and a dataplane that
	// answers with a live table (persistentNATLoggingDP below).
	cfg.Security.NAT.SourcePools["pool-pnat-6894"] = &config.NATPool{
		Name: "pool-pnat-6894", Addresses: []string{"192.0.2.90"},
		PersistentNAT: &config.PersistentNATConfig{
			Permit:            config.PersistentNATPermitAnyRemoteHost,
			InactivityTimeout: 120,
		},
	}
	cfg.Security.NAT.Source = append(cfg.Security.NAT.Source, &config.NATRuleSet{
		Name: "rs-pnat-6894", FromZone: "dmz", ToZone: "egress",
		Rules: []*config.NATRule{
			{Name: "r-pnat", Match: config.NATMatch{SourceAddress: "10.8.0.0/16"},
				Then: config.NATThen{Type: config.NATSource, PoolName: "pool-pnat-6894"}},
		},
	})
	// `no IP addresses for interface SNAT`: the one gated WARN. Interface-mode
	// SNAT into a zone whose member declares no addresses.
	cfg.Security.Zones["noaddr6894"] = &config.ZoneConfig{
		Name: "noaddr6894", Interfaces: []string{"xpfp4960n.0"},
	}
	cfg.Interfaces.Interfaces["xpfp4960n"] = &config.InterfaceConfig{
		Name: "xpfp4960n", RedundancyGroup: 1,
		Units: map[int]*config.InterfaceUnit{0: {Number: 0}},
	}
	cfg.Security.NAT.Source = append(cfg.Security.NAT.Source, &config.NATRuleSet{
		Name: "rs-noaddr-6894", FromZone: "trust", ToZone: "noaddr6894",
		Rules: []*config.NATRule{
			{Name: "r-noaddr", Match: config.NATMatch{SourceAddress: "10.7.0.0/16"},
				Then: config.NATThen{Type: config.NATSource, Interface: true}},
		},
	})
	return cfg
}

// persistentNATLoggingDP is the real-pass driver's dataplane: notAValidationDP
// plus a LIVE persistent-NAT table.
//
// The pre-pass fake answers GetPersistentNAT with a typed nil ON PURPOSE
// (prePassShimDivergence documents why: modelling a real table would make the
// pre-pass CLEAR and REPOPULATE the live one from a discarded compile). A
// consequence is that the `persistent NAT pool registered` gate CANNOT fire on
// the pre-pass path it nominally protects — the whole block is skipped one
// level up. That makes the gate defensive rather than load-bearing, and it is
// the negative arm alone that is unbindable: the REAL pass reaches the record
// whenever the dataplane has a table, which is what this type supplies.
type persistentNATLoggingDP struct {
	notAValidationDP
	pnat *PersistentNATTable
}

func (d *persistentNATLoggingDP) GetPersistentNAT() *PersistentNATTable { return d.pnat }

// TestPrePassLogsNoSuccessForWorkItDidNotDo_4960 is the fail-on-revert guard
// for F6.
//
// RED-on-revert: drop any one of the `!isValidationPass(dp)` gates added around
// the covered phases' completed-work records and this fails with "the pre-pass
// logged N success record(s)", naming them.
// NEGATIVE-ARM REACH, MEASURED rather than reasoned about (#6894 r9 F2).
//
// Driving the pre-pass's own rows with every gate neutralised shows which gated
// records it can reach at all. Of the 18 `!isValidationPass(dp)` sites, 16 are
// named in gatedRecordWants and bound by the base run; the other two — the
// deny-all default-policy arm and the one gated WARN — are bound by their own
// assertions in TestRealPassStillLogsItsSuccesses_4960. TWO of the eighteen are
// NOT reachable on the pre-pass, and neither is an oversight — both are
// properties of the shim production actually uses:
//
//   - `SNAT egress IP resolved` — compileNAT's interface-SNAT branch resolves its
//     egress member through result.cachedInterfaceByName, and production's
//     validateBeforeMutate builds a newValidationResult whose ifCache is EMPTY
//     (only compileZones populates it). The branch soft-skips before the record.
//   - `persistent NAT pool registered` — the shim's GetPersistentNAT returns a
//     typed nil ON PURPOSE (see prePassShimDivergence), so the whole
//     persistent-NAT block is skipped one level up.
//
// Both gates are therefore DEFENSIVE on the pre-pass: they cannot fire on the
// path they nominally protect, and removing either leaves this test green. That
// is stated rather than papered over. Their over-reach arm IS bound —
// gatedRecordWants names both, and the real-pass driver supplies the seeded
// ifCache and the live table that reach them — so the direction that loses an
// operator record is covered.
func TestPrePassLogsNoSuccessForWorkItDidNotDo_4960(t *testing.T) {
	// Two runs, one per default-policy arm: compileDefaultPolicy gates its
	// permit-all and deny-all records in SEPARATE blocks, and PolicyPermit is
	// config's zero value, so a single run reaches only the permit-all one.
	for _, tc := range []struct {
		name   string
		mutate func(*config.Config)
	}{
		{"default-permit", func(*config.Config) {}},
		{"default-deny", func(c *config.Config) { c.Security.DefaultPolicy = config.PolicyDeny }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := logProbeConfig()
			tc.mutate(cfg)

			buf := captureSlog(t)
			if err := validateBeforeMutate(cfg); err != nil {
				t.Fatalf("the probe config must validate clean, or the pre-pass aborts "+
					"before reaching the phases whose logging is under test: %v", err)
			}
			if got := successLogLines(buf); len(got) != 0 {
				t.Errorf("the pre-pass logged %d success record(s) for writes that are "+
					"no-ops on the discarding shim. An operator reading the journal of a "+
					"FAILED apply sees a compile succeeding and then failing, for a "+
					"compile whose result was thrown away (#6894 r8 F6):\n  %s",
					len(got), strings.Join(got, "\n  "))
			}

			// The one gated WARN. F6's SCOPE is unchanged — the other 25 WARN
			// sites are ungated and stay on #6903 — but a gate this PR adds and
			// nothing observes is a gate that can be removed silently, so bind
			// the one that exists (#6894 r9 F2).
			for _, line := range warnLogLines(buf) {
				if strings.Contains(line, "no IP addresses for interface SNAT") {
					t.Errorf("the pre-pass emitted the interface-SNAT no-address "+
						"warning; the real pass emits it again, so the operator "+
						"reads the same diagnostic twice for one apply:\n  %s", line)
				}
			}
		})
	}
}

// TestRealPassStillLogsItsSuccesses_4960 is the over-reach guard, and the
// non-vacuity control for the test above: without it, "the pre-pass logged
// nothing" would also be satisfied by a fixture that reaches no logging phase,
// or by gates that suppress the records on BOTH passes.
//
// It drives the SAME rows over the SAME config with a dataplane that does not
// carry the validation marker — which is what a real pass looks like to
// isValidationPass — and requires the records back. Stays GREEN under the F6
// revert.
// gatedRecordWants is the over-reach arm's target list: one entry per
// `!isValidationPass(dp)` site the REAL pass can reach with this fixture.
//
// It is asserted COMPLETE against the production gate count by
// TestOverReachArmCoversEveryReachableGate_4960 below, so a newly gated site
// cannot be added without either binding it here or recording why it is
// unreachable. Before #6894 r9 this list held 13 of the 19 gates and nothing
// noticed the other six.
//
// Two entries pin an ATTRIBUTE, not just the message: compiler.go's two default
// policy arms emit the identical message and differ only in `action=`, so a
// message-only want binds whichever arm the fixture takes and leaves the other
// free to be suppressed on both passes.
var gatedRecordWants = []string{
	// #6420: the v4/v6 pair collapsed to ONE record when the per-address-family
	// snat_rules / snat_rules_v6 writes were deleted — the compiler no longer
	// has a per-family record to log, only the rule.
	"source NAT rule compiled",     // compileNAT, pool + interface mode
	"source NAT off rule compiled", // compileNAT, no-NAT exemption (#3844)
	"SNAT egress IP resolved",      // compileNAT, interface mode, resolved egress
	"persistent NAT pool registered",
	"destination NAT rule compiled",
	"static NAT rule compiled",
	"static NAT compilation complete",
	"nptv6 rule compiled",
	"nptv6 compilation complete",
	"compiled NAT64 prefix",
	"NAT64 compilation complete",
	"auto-assigned NAT64 source pool",
	"screen profile compiled",
	"flow timeouts compiled",
	// PolicyPermit is config's ZERO value, so the base fixture takes the
	// permit-all arm; the deny-all arm gets its own run below.
	`msg="default policy compiled" action=permit-all`,
	"flow config compiled",
}

// runRealPassPhases drives the pre-pass's OWN row set against a dataplane that
// reports FALSE for the validation marker — which is what a real pass looks
// like to isValidationPass — and returns the captured log.
//
// The rows are invoked directly because validateBeforeMutateWith refuses an
// unmarked dp by design. `seededEgressResult` rather than `newValidationResult`
// is what makes compileNAT's interface-SNAT branch resolve its egress member
// instead of soft-skipping, which is the only way to reach `SNAT egress IP resolved`
// without naming a live host link in a fixture (#6894 r3 F1 uses the same seed).
func runRealPassPhases(t *testing.T, cfg *config.Config) *bytes.Buffer {
	t.Helper()
	// The same prelude validateBeforeMutateWithResult runs before its rows:
	// without it the policies row cannot resolve a zone and the driver never
	// reaches the phases whose logging is under test.
	result := seededEgressResult()
	assignZoneIDs(result, cfg)
	assignScreenIDs(result, cfg)

	dp := &persistentNATLoggingDP{pnat: NewPersistentNATTable()}
	buf := captureSlog(t)
	for _, phase := range validationPhases(dp, cfg, result) {
		if err := phase.run(); err != nil {
			t.Fatalf("row %q rejected the probe config: %v", phase.name, err)
		}
	}
	return buf
}

func TestRealPassStillLogsItsSuccesses_4960(t *testing.T) {
	cfg := logProbeConfig()
	got := successLogLines(runRealPassPhases(t, cfg))

	// Name the specific records, per phase family: a bare non-empty check would
	// be satisfied by one surviving record while every other gate had been
	// widened to suppress both passes.
	for _, want := range gatedRecordWants {
		found := false
		for _, line := range got {
			if strings.Contains(line, want) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("the REAL pass no longer logs %q. Either the #6894 r8 F6 gate "+
				"was widened past the validation pass and now suppresses the record "+
				"an operator needs, or this fixture stopped reaching that phase — "+
				"which would make TestPrePassLogsNoSuccessForWorkItDidNotDo_4960 "+
				"vacuous for it\n  have: %s", want, strings.Join(got, "\n        "))
		}
	}

	// The OTHER default-policy arm. Same message, different action, a separate
	// `if !isValidationPass(dp)` block in compiler.go — so it needs its own run.
	denyCfg := logProbeConfig()
	denyCfg.Security.DefaultPolicy = config.PolicyDeny
	denyGot := successLogLines(runRealPassPhases(t, denyCfg))
	const wantDeny = `msg="default policy compiled" action=deny-all`
	found := false
	for _, line := range denyGot {
		if strings.Contains(line, wantDeny) {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("the REAL pass no longer logs %q. compileDefaultPolicy gates its "+
			"two arms in SEPARATE blocks; binding only the permit-all arm leaves "+
			"the deny-all one free to be suppressed on both passes (#6894 r9 F2)"+
			"\n  have: %s", wantDeny, strings.Join(denyGot, "\n        "))
	}

	// The one gated WARN. It is not a success record and F6's scope is success
	// records — but it IS gated, so without this the gate could be widened to
	// swallow an operator diagnostic on a fail-open path (interface-mode SNAT
	// silently doing nothing because the egress member has no address).
	const wantWarn = "no IP addresses for interface SNAT"
	warns := warnLogLines(runRealPassPhases(t, logProbeConfig()))
	foundWarn := false
	for _, line := range warns {
		if strings.Contains(line, wantWarn) {
			foundWarn = true
			break
		}
	}
	if !foundWarn {
		t.Errorf("the REAL pass no longer warns %q — the only gated WARN site can "+
			"now be suppressed on both passes, losing the diagnostic for an "+
			"interface-SNAT rule that silently translates nothing (#6894 r9 F2)"+
			"\n  have: %s", wantWarn, strings.Join(warns, "\n        "))
	}
}

// TestOverReachArmCoversEveryReachableGate_4960 is what stops gatedRecordWants
// from silently falling behind production.
//
// The list above is hand-written; the gate COUNT is derived by scanning the
// compiler sources for `isValidationPass(` call sites. A newly gated record
// added without a want (or without an entry in the unbindable table) reds here,
// which is the failure mode #6894 r9 F2 reported: six gates existed with no
// over-reach coverage and the package stayed green when they were widened to
// suppress both passes.
//
// This counts SITES, not records, and the two are not equal — hence the
// explicit reconciliation below rather than a bare `len(wants) == len(sites)`.
func TestOverReachArmCoversEveryReachableGate_4960(t *testing.T) {
	// Gated sites this fixture cannot drive to the REAL-pass branch, each with
	// the reason. An honest scope statement, not a silent gap.
	unbindable := map[string]string{
		"compiler.go:default policy deny-all": "same message as the permit-all arm " +
			"(PolicyPermit is config's zero value, so the base fixture takes " +
			"permit-all); bound by the SECOND run in " +
			"TestRealPassStillLogsItsSuccesses_4960, which is why it is not a " +
			"separate entry in gatedRecordWants",
		"compiler_nat.go:no IP addresses for interface SNAT": "a WARN, so " +
			"successLogLines (INFO-only) cannot see it; bound separately by the " +
			"warnLogLines assertion in TestRealPassStillLogsItsSuccesses_4960",
	}

	sites := countValidationPassGates(t)
	// FLOOR: a scan finding nothing would make the reconciliation vacuous.
	if sites < 15 {
		t.Fatalf("found only %d isValidationPass gate sites across the compiler "+
			"sources — the scan is not reaching them, so this test cannot bind "+
			"the over-reach arm's completeness", sites)
	}
	if want := len(gatedRecordWants) + len(unbindable); sites != want {
		t.Errorf("production carries %d `!isValidationPass(dp)` gate sites, but the "+
			"over-reach arm accounts for %d (%d entries in gatedRecordWants + %d "+
			"recorded as separately bound).\n\n"+
			"A gate the over-reach arm does not name can be widened to suppress the "+
			"record on the REAL pass too, and the whole package stays green — the "+
			"operator loses a record and nothing notices (#6894 r9 F2). Add a want "+
			"that this fixture actually reaches, or add the site to `unbindable` "+
			"with the reason it cannot be driven here.",
			sites, want, len(gatedRecordWants), len(unbindable))
	}
}

// countValidationPassGates counts `isValidationPass(` call sites across the
// compiler sources, by AST rather than by grep so a call inside a comment or a
// string cannot inflate the count.
func countValidationPassGates(t *testing.T) int {
	t.Helper()
	n := 0
	for _, name := range []string{"compiler.go", "compiler_nat.go", "compiler_iface.go"} {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		ast.Inspect(f, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "isValidationPass" {
				n++
			}
			return true
		})
	}
	return n
}
