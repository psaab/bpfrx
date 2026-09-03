package daemon

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"
)

// #5868: the first-confirmed-commit bootstrap rollback used to swallow every
// teardown failure (removing generated .network state, networkctl reload, FRR
// clear, dataplane teardown) and then log "rollback complete" unconditionally.
// These tests pin the honest-reporting contract: teardown failures are
// aggregated and surfaced, and a partial teardown is reported DEGRADED — never
// "complete".

// captureSlog redirects the default slog logger to a buffer for the duration
// of a test and returns the buffer plus a restore func. Used to assert the
// rollback does NOT log "complete" when a teardown step failed.
func captureSlog(t *testing.T) (*bytes.Buffer, func()) {
	t.Helper()
	buf := &bytes.Buffer{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	return buf, func() { slog.SetDefault(prev) }
}

// TestSummarizeBootstrapTeardown is the canonical aggregation seam (#5868).
// Reverting summarizeBootstrapTeardown to the void discard-failures behavior
// (e.g. `return nil, false`) turns the failure sub-tests RED — proving the
// aggregation, not an incidental assertion, is what surfaces the errors.
func TestSummarizeBootstrapTeardown(t *testing.T) {
	// (a) No steps at all → clean rollback.
	if err, degraded := summarizeBootstrapTeardown(nil); err != nil || degraded {
		t.Fatalf("no steps must summarize clean; got err=%v degraded=%v", err, degraded)
	}

	// (b) All steps succeeded → clean rollback (no false negative).
	ok := []bootstrapTeardownStep{
		{name: "remove takeover .network files"},
		{name: "networkctl reload"},
		{name: "clear FRR managed section"},
		{name: "dataplane teardown"},
	}
	if err, degraded := summarizeBootstrapTeardown(ok); err != nil || degraded {
		t.Fatalf("all-success must summarize clean; got err=%v degraded=%v", err, degraded)
	}

	// (c) One step failed → DEGRADED, aggregated error names the failed step.
	one := []bootstrapTeardownStep{
		{name: "clear FRR managed section"},
		{name: "dataplane teardown", err: errors.New("helper socket closed")},
	}
	err, degraded := summarizeBootstrapTeardown(one)
	if !degraded {
		t.Fatal("a failed teardown step must summarize as DEGRADED, not clean")
	}
	if err == nil {
		t.Fatal("a failed teardown step must produce a non-nil aggregated error")
	}
	if !strings.Contains(err.Error(), "dataplane teardown") {
		t.Fatalf("aggregated error must name the failed step; got %q", err.Error())
	}
	if !strings.Contains(err.Error(), "helper socket closed") {
		t.Fatalf("aggregated error must carry the underlying cause; got %q", err.Error())
	}

	// (d) Multiple simultaneous failures → both attributed in the aggregate.
	multi := []bootstrapTeardownStep{
		{name: "clear FRR managed section", err: errors.New("frr reload failed")},
		{name: "dataplane teardown", err: errors.New("helper socket closed")},
	}
	mErr, mDegraded := summarizeBootstrapTeardown(multi)
	if !mDegraded || mErr == nil {
		t.Fatalf("multiple failures must be DEGRADED with a non-nil error; got err=%v degraded=%v", mErr, mDegraded)
	}
	if !strings.Contains(mErr.Error(), "clear FRR managed section") ||
		!strings.Contains(mErr.Error(), "dataplane teardown") {
		t.Fatalf("aggregate must name every failed step; got %q", mErr.Error())
	}
}

// TestEnterBootstrapMode_DegradedOnTeardownFailure exercises the full rollback
// path via the #5868 test seam: an injected FAILING teardown step (dataplane
// teardown) must (a) make enterBootstrapMode return the aggregated error naming
// the step, and (b) NOT report "rollback complete" — the log must say DEGRADED.
// Best-effort continuation is still proven: the daemon lands in bootstrap mode.
//
// RED-on-revert: restoring the void discard-failures behavior (making
// summarizeBootstrapTeardown ignore step errors, i.e. the pre-#5868 code that
// logged "rollback complete" and returned nothing) flips assertion (a) — the
// error is nil — and the "must NOT log complete" assertion RED.
func TestEnterBootstrapMode_DegradedOnTeardownFailure(t *testing.T) {
	buf, restore := captureSlog(t)
	defer restore()

	d := &Daemon{}
	d.bootstrapTeardownForTest = func() []bootstrapTeardownStep {
		return []bootstrapTeardownStep{
			{name: "remove takeover .network files"},                                      // succeeded
			{name: "clear FRR managed section"},                                           // succeeded
			{name: "dataplane teardown", err: errors.New("helper control socket closed")}, // FAILED
		}
	}

	err := d.enterBootstrapMode()

	// (a) the aggregated error is surfaced and names the failed step.
	if err == nil {
		t.Fatal("enterBootstrapMode must return the aggregated teardown error, not swallow it")
	}
	if !strings.Contains(err.Error(), "dataplane teardown") {
		t.Fatalf("returned error must name the failed step; got %q", err.Error())
	}

	// (b) the rollback must NOT be reported as complete; it must be DEGRADED.
	logs := buf.String()
	if strings.Contains(logs, "rollback complete") {
		t.Fatalf("a degraded rollback must NOT log \"rollback complete\"; logs:\n%s", logs)
	}
	if !strings.Contains(logs, "DEGRADED") {
		t.Fatalf("a degraded rollback must log DEGRADED; logs:\n%s", logs)
	}
	if !strings.Contains(logs, "dataplane teardown") {
		t.Fatalf("the failed step must be logged at ERROR by name; logs:\n%s", logs)
	}

	// Best-effort continuation: the daemon is still driven into bootstrap mode
	// despite the failed step.
	if !d.inBootstrap() {
		t.Fatal("enterBootstrapMode must still enter bootstrap mode on a partial teardown")
	}
}

// TestEnterBootstrapMode_CleanReportsComplete is the no-false-negative
// counterpart: when every teardown step succeeds, enterBootstrapMode returns
// nil and reports "rollback complete" (not DEGRADED).
func TestEnterBootstrapMode_CleanReportsComplete(t *testing.T) {
	buf, restore := captureSlog(t)
	defer restore()

	d := &Daemon{}
	d.bootstrapTeardownForTest = func() []bootstrapTeardownStep {
		return []bootstrapTeardownStep{
			{name: "remove takeover .network files"},
			{name: "clear FRR managed section"},
			{name: "dataplane teardown"},
		}
	}

	if err := d.enterBootstrapMode(); err != nil {
		t.Fatalf("a fully-successful teardown must return nil; got %v", err)
	}
	logs := buf.String()
	if !strings.Contains(logs, "rollback complete") {
		t.Fatalf("a clean rollback must log \"rollback complete\"; logs:\n%s", logs)
	}
	if strings.Contains(logs, "DEGRADED") {
		t.Fatalf("a clean rollback must NOT log DEGRADED; logs:\n%s", logs)
	}
	if !d.inBootstrap() {
		t.Fatal("enterBootstrapMode must enter bootstrap mode")
	}
}
