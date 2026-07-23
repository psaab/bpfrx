package daemon

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// TestHostAuthCloseoutRecoversPerOwnerPanic6184 is the #6184 item-1 fail-on-
// revert merge gate. Each host-auth closeout owner runs in its own goroutine;
// before the fix a PANIC in one owner's reconcile unwound the goroutine with no
// recover and crashed the whole daemon-stop path — taking down the process and
// every remaining owner, the opposite of the M35 fail-VISIBLE discipline. The
// per-owner defer/recover in runHostAuthCloseoutOwners recovers the panic, logs
// it with the owner id, and records it as that owner's fail-visible reconcile
// error so the batch and the process survive and the failure is surfaced.
//
// This asserts (a) the batch does NOT crash and the panic is surfaced in the
// joined summary error, (b) the owners on BOTH sides of the panicking one still
// run to completion, and (c) the panicking owner is FAIL-VISIBLE — a non-nil,
// named err (not timed-out, not silently clean).
//
// Fail-on-revert: delete the defer/recover block in runHostAuthCloseoutOwners
// and the owner's panic propagates out of its goroutine, aborting the `go test`
// process (SIGABRT / exit 2) before these assertions run — the package goes RED.
// It is NOT a build break: removing the block leaves no unused import (fmt and
// slog remain used by summarizeHostAuthCloseout), so the RED is the genuine
// crash the fix prevents, not a false compile red.
func TestHostAuthCloseoutRecoversPerOwnerPanic6184(t *testing.T) {
	beforeRan, afterRan := false, false
	before := func(*config.Config) error { beforeRan = true; return nil }
	panicky := func(*config.Config) error { panic("boom in owner closeout") }
	after := func(*config.Config) error { afterRan = true; return nil }

	owners := []hostAuthOwner{
		{"before", before},
		{"panicky", panicky},
		{"after", after},
	}

	// Without the recover this call crashes the process instead of returning.
	outcomes := runHostAuthCloseoutOwners(&config.Config{}, hostAuthCloseoutBudget, owners)

	// (b) owners on both sides of the panic ran to completion.
	if !beforeRan {
		t.Error("owner before the panicking one did not run")
	}
	if !afterRan {
		t.Error("owner after the panicking one did not run — a panic in one owner " +
			"skipped the remaining owners (per-owner recover missing)")
	}

	got := map[string]hostAuthOwnerOutcome{}
	for _, o := range outcomes {
		got[o.name] = o
	}

	// (c) the panicking owner is fail-visible: non-nil err, not timed-out.
	po, ok := got["panicky"]
	if !ok {
		t.Fatal("panicking owner has no recorded outcome")
	}
	if po.err == nil {
		t.Error("panicking owner outcome has nil err — the panic was silently swallowed, not fail-visible")
	}
	if po.timedOut {
		t.Error("panicking owner marked timedOut, want a fail-visible reconcile error")
	}

	// (a) the batch did not crash and the failure is surfaced, named, in the join.
	err := summarizeHostAuthCloseout(outcomes, hostAuthCloseoutBudget)
	if err == nil {
		t.Fatal("summary returned nil despite a panicking owner — the panic failure was not surfaced")
	}
	if !strings.Contains(err.Error(), "panicky") || !strings.Contains(err.Error(), "panicked") {
		t.Errorf("summary error %q does not name the panicking owner and its panic", err)
	}

	// The clean owners are not falsely marked failed by the neighbouring panic.
	if got["before"].err != nil || got["before"].timedOut {
		t.Errorf("clean owner 'before' outcome = %+v, want clean", got["before"])
	}
	if got["after"].err != nil || got["after"].timedOut {
		t.Errorf("clean owner 'after' outcome = %+v, want clean", got["after"])
	}
}

// budgetCaptureHandler is a minimal slog.Handler that records each emitted
// record's message and attributes so a test can assert on a logged value
// (here the "budget" duration attr) without depending on text formatting.
type budgetCaptureHandler struct {
	mu      *sync.Mutex
	records *[]map[string]slog.Value
}

func (h budgetCaptureHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h budgetCaptureHandler) Handle(_ context.Context, r slog.Record) error {
	attrs := map[string]slog.Value{"msg": slog.StringValue(r.Message)}
	r.Attrs(func(a slog.Attr) bool {
		attrs[a.Key] = a.Value
		return true
	})
	h.mu.Lock()
	*h.records = append(*h.records, attrs)
	h.mu.Unlock()
	return nil
}

func (h budgetCaptureHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h budgetCaptureHandler) WithGroup(string) slog.Handler      { return h }

// TestHostAuthCloseoutLogsActualBudget6184 is the #6184 item-2 fail-on-revert
// gate. summarizeHostAuthCloseout logged the package global hostAuthCloseoutBudget
// (30s) in the "did not complete within budget" line rather than the budget the
// outcomes were actually produced under, so a non-default budget (a shrunk test
// budget, or any future non-30s production value) was reported misleadingly.
// The budget is now threaded in and logged.
//
// This runs the closeout under an explicit 20ms budget with a wedged owner that
// times out, captures the emitted slog records, and asserts the timed-out record
// carries budget=20ms — the value passed in — not the 30s global.
//
// Fail-on-revert: change the log arg back to hostAuthCloseoutBudget and the
// captured budget attr becomes 30s, failing the `got == wantBudget` assertion
// (RED). A plain assertion, not a crash or build break.
func TestHostAuthCloseoutLogsActualBudget6184(t *testing.T) {
	var mu sync.Mutex
	var recs []map[string]slog.Value
	prev := slog.Default()
	slog.SetDefault(slog.New(budgetCaptureHandler{mu: &mu, records: &recs}))
	defer slog.SetDefault(prev)

	const wantBudget = 20 * time.Millisecond
	if wantBudget == hostAuthCloseoutBudget {
		t.Fatalf("test budget %v must differ from the global %v to distinguish them",
			wantBudget, hostAuthCloseoutBudget)
	}

	release := make(chan struct{})
	defer close(release) // unblock the wedged goroutine on exit (no leak)
	wedged := func(*config.Config) error { <-release; return nil }
	owners := []hostAuthOwner{{"wedged", wedged}}

	outcomes := runHostAuthCloseoutOwners(&config.Config{}, wantBudget, owners)
	if err := summarizeHostAuthCloseout(outcomes, wantBudget); err == nil {
		t.Fatal("summary returned nil, want the wedged owner reported timed-out")
	}

	mu.Lock()
	defer mu.Unlock()
	var found bool
	for _, rec := range recs {
		if !strings.Contains(rec["msg"].String(), "did not complete within budget") {
			continue
		}
		found = true
		bv, ok := rec["budget"]
		if !ok {
			t.Fatal("timed-out log record has no budget attribute")
		}
		if got := bv.Duration(); got != wantBudget {
			t.Errorf("timed-out log record budget = %v, want the actual budget %v "+
				"(the global %v is logged instead — #6184 item 2)", got, wantBudget, hostAuthCloseoutBudget)
		}
	}
	if !found {
		t.Fatal("no 'did not complete within budget' record was emitted for the wedged owner")
	}
}
