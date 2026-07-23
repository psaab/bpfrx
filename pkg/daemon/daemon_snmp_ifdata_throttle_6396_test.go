package daemon

import (
	"errors"
	"log/slog"
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
