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
	"compiled", "complete", "registered", "auto-assigned", "IP set",
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

// successLogLines returns the captured INFO lines whose MESSAGE carries one of
// the completed-work markers.
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
				out = append(out, msg)
				break
			}
		}
	}
	return out
}

// logProbeConfig is idProbeConfig plus a non-default flow timeout, which is
// what makes compileFlowTimeouts reach its own success record.
func logProbeConfig() *config.Config {
	cfg := idProbeConfig()
	cfg.Security.Flow.UDPSessionTimeout = 60
	return cfg
}

// TestPrePassLogsNoSuccessForWorkItDidNotDo_4960 is the fail-on-revert guard
// for F6.
//
// RED-on-revert: drop any one of the `!isValidationPass(dp)` gates added around
// the covered phases' completed-work records and this fails with "the pre-pass
// logged N success record(s)", naming them.
func TestPrePassLogsNoSuccessForWorkItDidNotDo_4960(t *testing.T) {
	cfg := logProbeConfig()

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
func TestRealPassStillLogsItsSuccesses_4960(t *testing.T) {
	cfg := logProbeConfig()

	// notAValidationDP inherits the shim's 40 no-op overrides and reports FALSE
	// for the marker, so the rows run to completion down the REAL-pass logging
	// branch. The rows are invoked directly because validateBeforeMutateWith
	// refuses an unmarked dp by design.
	// The same prelude validateBeforeMutateWithResult runs before its rows:
	// without it the policies row cannot resolve a zone and the driver never
	// reaches the phases whose logging is under test.
	result := newValidationResult()
	assignZoneIDs(result, cfg)
	assignScreenIDs(result, cfg)

	buf := captureSlog(t)
	for _, phase := range validationPhases(&notAValidationDP{}, cfg, result) {
		if err := phase.run(); err != nil {
			t.Fatalf("row %q rejected the probe config: %v", phase.name, err)
		}
	}

	got := successLogLines(buf)
	// Name the specific records, per phase family: a bare non-empty check would
	// be satisfied by one surviving record while every other gate had been
	// widened to suppress both passes.
	for _, want := range []string{
		"source NAT rule compiled",    // compileNAT, v4
		"source NAT v6 rule compiled", // compileNAT, v6
		"destination NAT rule compiled",
		"static NAT rule compiled",
		"static NAT compilation complete",
		"nptv6 rule compiled",
		"nptv6 compilation complete",
		"compiled NAT64 prefix",
		"NAT64 compilation complete",
		"auto-assigned NAT64 source pool",
		"flow timeouts compiled",
		"default policy compiled",
		"flow config compiled",
	} {
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
}
