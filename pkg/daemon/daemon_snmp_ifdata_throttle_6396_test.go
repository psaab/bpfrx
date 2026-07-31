package daemon

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
)

// TestBuildSNMPIfDataWarnThrottled is the #6396 C179-123 residual guard: a
// PERSISTENT netlink failure must not write one warning line per SNMP poll.
// buildSNMPIfData runs once per poll and a manager may poll several times a
// second, so the per-poll slog.Warn (added by the C179-123 fix) floods the
// journal on a sustained failure. The warning is now rate-limited to at most
// once per snmpIfDataWarnInterval.
//
// FAIL-ON-REVERT: making shouldLog always emit (dropping the throttle) makes
// buildSNMPIfData log on EVERY failing poll — the "exactly one line for many
// polls" assertion below goes RED.
func TestBuildSNMPIfDataWarnThrottled(t *testing.T) {
	snmpIfDataFailThrottle.reset()
	t.Cleanup(func() { snmpIfDataFailThrottle.reset() })

	prevLister := snmpLinkLister
	snmpLinkLister = func() ([]netlink.Link, error) {
		return nil, errors.New("injected: netlink RTM_GETLINK dump failed")
	}
	defer func() { snmpLinkLister = prevLister }()

	rec := &recordingSlogHandler{level: slog.LevelWarn}
	prevLogger := slog.Default()
	slog.SetDefault(slog.New(rec))
	defer slog.SetDefault(prevLogger)

	// Many rapid failing polls, all well inside snmpIfDataWarnInterval.
	const polls = 20
	for i := 0; i < polls; i++ {
		if got := buildSNMPIfData(); got != nil {
			t.Fatalf("a failed netlink read must return no interface data, got %d entries", len(got))
		}
	}

	const warn = "SNMP ifTable read failed; reporting empty interface table"
	if n := rec.count(warn); n != 1 {
		t.Fatalf("a persistent netlink failure must log %q at most once per window, "+
			"not once per poll; %d polls produced %d warnings", warn, polls, n)
	}
}

// attrCapturingHandler records each log record's message plus the integer
// value of a single named attribute, so a test can assert both that a line
// fired and what count it carried.
type attrCapturingHandler struct {
	mu   sync.Mutex
	key  string
	recs []attrRecord
}

type attrRecord struct {
	msg string
	val int64
	has bool
}

func (h *attrCapturingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *attrCapturingHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	rec := attrRecord{msg: r.Message}
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == h.key {
			rec.val = a.Value.Int64()
			rec.has = true
		}
		return true
	})
	h.recs = append(h.recs, rec)
	return nil
}

func (h *attrCapturingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *attrCapturingHandler) WithGroup(string) slog.Handler      { return h }

// find returns the count of records with the given message and the captured
// attribute value of the FIRST such record.
func (h *attrCapturingHandler) find(msg string) (count int, val int64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, r := range h.recs {
		if r.msg == msg {
			if count == 0 {
				val = r.val
			}
			count++
		}
	}
	return count, val
}

// TestBuildSNMPIfDataRecoveryLogged is the #6396 Codex MINOR 6 guard: after a
// failing→succeeding transition, buildSNMPIfData must log a one-time recovery
// carrying the number of failures suppressed since the last emitted failure
// line. Without a test the recovery log (and its count) is unbound — deleting
// it or zeroing the count would leave every other test green.
//
// FAIL-ON-REVERT: removing the recovery slog.Info makes the count-1 assertion
// go RED; hardcoding suppressed_failures to 0 makes the count-2 assertion RED.
func TestBuildSNMPIfDataRecoveryLogged(t *testing.T) {
	snmpIfDataFailThrottle.reset()
	t.Cleanup(func() { snmpIfDataFailThrottle.reset() })

	failing := true
	prevLister := snmpLinkLister
	snmpLinkLister = func() ([]netlink.Link, error) {
		if failing {
			return nil, errors.New("injected: netlink dump failed")
		}
		return nil, nil // success, empty table
	}
	defer func() { snmpLinkLister = prevLister }()

	rec := &attrCapturingHandler{key: "suppressed_failures"}
	prevLogger := slog.Default()
	slog.SetDefault(slog.New(rec))
	defer slog.SetDefault(prevLogger)

	// Three failing polls: the first logs, the next two are suppressed+counted.
	for i := 0; i < 3; i++ {
		buildSNMPIfData()
	}
	// Transition to success → one recovery log reporting the 2 suppressed.
	failing = false
	buildSNMPIfData()
	// A further success must NOT re-log recovery (throttle already reset).
	buildSNMPIfData()

	const rmsg = "SNMP ifTable read recovered"
	n, sup := rec.find(rmsg)
	if n != 1 {
		t.Fatalf("recovery must be logged exactly once on a failing->succeeding transition, got %d", n)
	}
	if sup != 2 {
		t.Fatalf("recovery suppressed_failures = %d, want 2 (the two failures suppressed since "+
			"the first emitted failure line)", sup)
	}
}

// TestWarnThrottleWindow drives the throttle primitive directly with an
// injected clock so the window-elapse, suppressed-count, and reset/recovery
// bookkeeping are covered deterministically (a real-time integration test would
// have to wait snmpIfDataWarnInterval to cross a window).
//
// FAIL-ON-REVERT: neutralizing shouldLog to always return (true, 0) makes the
// "second call is suppressed" and "window-elapse reports the suppressed count"
// assertions go RED.
func TestWarnThrottleWindow(t *testing.T) {
	var th warnThrottle
	const window = time.Minute
	base := time.Unix(1_700_000_000, 0)

	// First occurrence always emits, nothing suppressed yet.
	if emit, sup := th.shouldLog(base, window); !emit || sup != 0 {
		t.Fatalf("first occurrence: emit=%v suppressed=%d, want true/0", emit, sup)
	}
	// Two more inside the window are suppressed and counted.
	if emit, _ := th.shouldLog(base.Add(1*time.Second), window); emit {
		t.Fatalf("second occurrence inside window must be suppressed")
	}
	if emit, _ := th.shouldLog(base.Add(2*time.Second), window); emit {
		t.Fatalf("third occurrence inside window must be suppressed")
	}
	// At/after the window, it emits again and reports the 2 it suppressed.
	if emit, sup := th.shouldLog(base.Add(window), window); !emit || sup != 2 {
		t.Fatalf("window-elapsed occurrence: emit=%v suppressed=%d, want true/2", emit, sup)
	}
	// reset reports the condition was active and clears state; the next
	// occurrence then emits immediately even inside what would have been the
	// window.
	if wasActive, sup := th.reset(); !wasActive || sup != 0 {
		t.Fatalf("reset after an emitted log: wasActive=%v suppressed=%d, want true/0", wasActive, sup)
	}
	if emit, _ := th.shouldLog(base.Add(window+1*time.Second), window); !emit {
		t.Fatalf("first occurrence after reset must emit immediately")
	}
	// reset on a never-active throttle reports inactive (no spurious recovery
	// log on a healthy box).
	var fresh warnThrottle
	if wasActive, sup := fresh.reset(); wasActive || sup != 0 {
		t.Fatalf("reset on a fresh throttle: wasActive=%v suppressed=%d, want false/0", wasActive, sup)
	}
}
