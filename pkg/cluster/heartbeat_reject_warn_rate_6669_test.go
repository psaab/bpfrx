package cluster

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

// #6669 r18 (Codex finding 8): the per-frame rejection warning must be
// rate-limited, and the bound must not conceal the rate.
//
// NoteEpochDowngradeHeartbeat was limited to one line per 30s, but admitFrame
// then emitted an UNCONDITIONAL slog.Warn for every rejected frame right
// afterwards. A peer sending 10 valid-MAC epochless heartbeats per second
// therefore produced ~10 warnings per second, while README.md claimed "the
// rejection logs a rate-limited, actionable warning". The line that was bounded
// was the one an operator most needs; the noisy one was not bounded at all.
//
// These tests drive the REAL receive path (epochEnv.feed -> admitFrame), not
// the limiter in isolation: a limiter that works but is not wired changes
// nothing about the log volume.
//
// NO SLEEPS. heartbeatRejectWarnNowNanos is the injectable clock, so the
// interval is stepped across explicitly. A rate-limit test that waits on the
// wall clock is the flakiest thing that could be added to a PR about ordering.

// countRejectWarns returns how many generic rejection warnings the captured log
// holds.
func countRejectWarns(out string) int {
	return strings.Count(out, "cluster: heartbeat auth rejected")
}

// withCapturedWarnLog redirects slog to a buffer for the duration of the test.
func withCapturedWarnLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(old) })
	return &buf
}

// withPinnedRejectWarnClock pins the limiter's clock and returns a setter, so a
// test can step across the interval without sleeping.
func withPinnedRejectWarnClock(t *testing.T, start int64) func(int64) {
	t.Helper()
	now := start
	orig := heartbeatRejectWarnNowNanos
	heartbeatRejectWarnNowNanos = func() int64 { return now }
	t.Cleanup(func() { heartbeatRejectWarnNowNanos = orig })
	return func(v int64) { now = v }
}

// TestRejectionWarningIsRateLimitedOnTheRealPath_6669 is the binder.
//
// Fail-on-revert: drop the `r.auth.rejectWarn.admit()` gate in admitFrame (i.e.
// restore the unconditional slog.Warn) and this reports one warning per
// rejected frame instead of one per interval.
func TestRejectionWarningIsRateLimitedOnTheRealPath_6669(t *testing.T) {
	const frames = 40

	e := newLatchEnv(t)
	// Arm the latch so every subsequent epochless frame is REFUSED — the
	// concrete input Codex names (10 valid-MAC epochless heartbeats/second
	// after the latch arms).
	e.liveRun(e.captureIncarnation(0xF001, uint64(epochNowNanos()), epochFramesPerIncarnation),
		"peer proving it signs an epoch")

	setNow := withPinnedRejectWarnClock(t, 1)
	buf := withCapturedWarnLog(t)

	// A burst well inside ONE interval.
	for i := 0; i < frames; i++ {
		// epoch 0 is the "no epoch" sentinel: an epochless frame.
		frame := marshalHeartbeatAuthEpoch(samplePkt(), e.key, 0xF002, uint64(i+1), 0)
		if e.feed(frame) {
			t.Fatalf("frame %d was ADMITTED; the fixture must produce REJECTED frames "+
				"or this test measures nothing", i)
		}
	}

	got := countRejectWarns(buf.String())
	if got != 1 {
		t.Fatalf("%d rejected frames inside one %v window produced %d rejection warnings, want 1: "+
			"the per-frame warning is not rate-limited, so a 10/s epochless stream floods the log "+
			"at ~10 lines/s while the README promises a rate-limited warning",
			frames, heartbeatRejectWarnInterval, got)
	}

	// Stepping PAST the interval must emit again — a limiter that latches shut
	// would hide an ongoing attack after its first line.
	setNow(1 + int64(heartbeatRejectWarnInterval) + 1)
	if e.feed(marshalHeartbeatAuthEpoch(samplePkt(), e.key, 0xF002, uint64(frames+1), 0)) {
		t.Fatal("the post-interval frame was admitted; it must still be refused")
	}
	if got := countRejectWarns(buf.String()); got != 2 {
		t.Fatalf("after stepping past %v the warning count is %d, want 2: the limiter must "+
			"resume, not latch shut", heartbeatRejectWarnInterval, got)
	}
}

// TestRejectionWarningReportsWhatItSuppressed_6669 is the separate body that
// keeps the bound from hiding the volume. It is NOT folded into the test above:
// a rate limiter that silently drops everything would satisfy the count
// assertion there and leave an operator unable to tell one stray frame from a
// sustained flood.
//
// Fail-on-revert: drop the "suppressed_since_last" attribute (or stop counting
// suppressed frames) and the second emission no longer reports the burst.
func TestRejectionWarningReportsWhatItSuppressed_6669(t *testing.T) {
	const burst = 25

	e := newLatchEnv(t)
	e.liveRun(e.captureIncarnation(0xF101, uint64(epochNowNanos()), epochFramesPerIncarnation),
		"peer proving it signs an epoch")

	setNow := withPinnedRejectWarnClock(t, 1)
	buf := withCapturedWarnLog(t)

	for i := 0; i < burst; i++ {
		if e.feed(marshalHeartbeatAuthEpoch(samplePkt(), e.key, 0xF102, uint64(i+1), 0)) {
			t.Fatalf("frame %d was admitted; the fixture must produce rejections", i)
		}
	}
	// The FIRST emission reports 0 suppressed: nothing preceded it.
	if !strings.Contains(buf.String(), "suppressed_since_last=0") {
		t.Fatalf("the first rejection warning does not report suppressed_since_last=0.\nlog:\n%s",
			buf.String())
	}

	setNow(1 + int64(heartbeatRejectWarnInterval) + 1)
	if e.feed(marshalHeartbeatAuthEpoch(samplePkt(), e.key, 0xF102, uint64(burst+1), 0)) {
		t.Fatal("the post-interval frame was admitted; it must still be refused")
	}

	// burst-1 were suppressed after the first emission consumed one.
	want := "suppressed_since_last=" + itoaU(burst-1)
	if !strings.Contains(buf.String(), want) {
		t.Fatalf("the post-interval warning does not report %q, so an operator cannot tell a "+
			"single stray frame from a %d-frame flood.\nlog:\n%s", want, burst, buf.String())
	}
}

func itoaU(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
