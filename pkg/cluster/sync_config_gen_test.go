package cluster

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

// #3931 — HA config-sync generation ordering guard tests.
//
// These exercise the config-sync wire codec (encodeConfigPayload /
// decodeConfigPayload), the receiver-side ordering guard (shouldApplyConfigGen
// admission + recordAppliedConfigGen apply-then-advance, M-2/#4151), and the
// single-consumer ordered apply loop (configApplyLoop). Every test is
// written so it FAILS against the pre-#3931 behavior, where a config was
// applied via a racing `go OnConfigReceived` with NO generation on the wire:
// a rapid commit pair (C1 then C2) could apply out of order and leave the
// standby on the older C1.

// --- wire codec round-trip -------------------------------------------------

func TestConfigPayloadRoundTrip(t *testing.T) {
	const text = "set system host-name node0\nset interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24\n"
	payload := encodeConfigPayload(text, 42)
	gotText, gotGen := decodeConfigPayload(payload)
	if gotText != text {
		t.Fatalf("config text round-trip mismatch:\n got %q\nwant %q", gotText, text)
	}
	if gotGen != 42 {
		t.Fatalf("config gen round-trip mismatch: got %d want 42", gotGen)
	}
}

// A legacy sender emits the raw config text with no trailing framing; the new
// receiver must decode it with gen==0 (applied unconditionally).
func TestConfigPayloadLegacyNoMagic(t *testing.T) {
	const text = "set system host-name legacy\n"
	gotText, gotGen := decodeConfigPayload([]byte(text))
	if gotText != text {
		t.Fatalf("legacy config text mismatch: got %q want %q", gotText, text)
	}
	if gotGen != 0 {
		t.Fatalf("legacy config gen must be 0, got %d", gotGen)
	}
}

// Config text that happens to be short must not be misread as framed.
func TestConfigPayloadShortNotFramed(t *testing.T) {
	const text = "short"
	gotText, gotGen := decodeConfigPayload([]byte(text))
	if gotText != text || gotGen != 0 {
		t.Fatalf("short payload mis-decoded: got %q/%d", gotText, gotGen)
	}
}

// An empty config text still frames and decodes with its generation.
func TestConfigPayloadEmptyText(t *testing.T) {
	payload := encodeConfigPayload("", 7)
	gotText, gotGen := decodeConfigPayload(payload)
	if gotText != "" || gotGen != 7 {
		t.Fatalf("empty-text framing mis-decoded: got %q/%d", gotText, gotGen)
	}
}

// --- ordering guard --------------------------------------------------------

// The admission gate (shouldApplyConfigGen) is strictly monotonic against the
// last SUCCESSFULLY-applied generation (advanced only via recordAppliedConfigGen
// after a confirmed apply, M-2/#4151).
func TestShouldApplyConfigGenMonotonic(t *testing.T) {
	s := &SessionSync{}
	// First real config admits; the caller records it on successful apply.
	if !s.shouldApplyConfigGen(5) {
		t.Fatal("gen 5 should admit (first config)")
	}
	s.recordAppliedConfigGen(5)
	// A strictly-newer config admits.
	if !s.shouldApplyConfigGen(6) {
		t.Fatal("gen 6 should admit (newer than 5)")
	}
	s.recordAppliedConfigGen(6)
	// An older config (the reordered C1) is refused.
	if s.shouldApplyConfigGen(5) {
		t.Fatal("gen 5 must be refused after gen 6 applied (stale)")
	}
	// The same generation is refused (not strictly newer).
	if s.shouldApplyConfigGen(6) {
		t.Fatal("gen 6 must be refused after gen 6 applied (not strictly newer)")
	}
	if got := s.lastAppliedConfigGen.Load(); got != 6 {
		t.Fatalf("last-applied gen should be 6, got %d", got)
	}
}

// The gate does NOT advance the high-water mark on its own: admitting a
// generation must not record it. Only a confirmed apply (recordAppliedConfigGen)
// advances the mark — the M-2/#4151 apply-then-advance separation.
func TestShouldApplyConfigGenDoesNotAdvance(t *testing.T) {
	s := &SessionSync{}
	if !s.shouldApplyConfigGen(9) {
		t.Fatal("gen 9 should admit (first config)")
	}
	if got := s.lastAppliedConfigGen.Load(); got != 0 {
		t.Fatalf("the admission gate must NOT advance the high-water mark, got %d (want 0)", got)
	}
	// Admitting it again (no apply recorded yet) must still succeed — the same
	// generation stays eligible until an apply confirms it.
	if !s.shouldApplyConfigGen(9) {
		t.Fatal("gen 9 must stay admissible until a successful apply records it")
	}
	s.recordAppliedConfigGen(9)
	if got := s.lastAppliedConfigGen.Load(); got != 9 {
		t.Fatalf("recordAppliedConfigGen must advance the mark to 9, got %d", got)
	}
	if s.shouldApplyConfigGen(9) {
		t.Fatal("gen 9 must be refused once recorded (not strictly newer)")
	}
}

// gen==0 (legacy sender) is always admitted and never advances the high-water
// mark, so a subsequent real generation still orders correctly.
func TestShouldApplyConfigGenLegacyUnconditional(t *testing.T) {
	s := &SessionSync{}
	if !s.shouldApplyConfigGen(0) {
		t.Fatal("legacy gen 0 must always admit")
	}
	s.recordAppliedConfigGen(0)
	if got := s.lastAppliedConfigGen.Load(); got != 0 {
		t.Fatalf("gen 0 must not advance high-water mark, got %d", got)
	}
	if !s.shouldApplyConfigGen(3) {
		t.Fatal("real gen 3 should admit after a legacy gen 0")
	}
	s.recordAppliedConfigGen(3)
	if !s.shouldApplyConfigGen(0) {
		t.Fatal("legacy gen 0 must still admit after a real gen")
	}
	s.recordAppliedConfigGen(0)
	if got := s.lastAppliedConfigGen.Load(); got != 3 {
		t.Fatalf("high-water mark should remain 3, got %d", got)
	}
}

// After a peer bulk re-prime (resetRecvGen), the high-water mark resets so a
// rebooted primary — whose monotonic counter restarts LOWER — is accepted
// instead of refused as stale (#2198 F2 reasoning applied to config).
func TestResetRecvGenResetsConfigGen(t *testing.T) {
	s := &SessionSync{}
	s.recvGenV4 = nil
	s.recvGenV6 = nil
	if !s.shouldApplyConfigGen(100) {
		t.Fatal("gen 100 should admit")
	}
	s.recordAppliedConfigGen(100)
	s.resetRecvGen()
	if got := s.lastAppliedConfigGen.Load(); got != 0 {
		t.Fatalf("resetRecvGen must zero the config gen, got %d", got)
	}
	// A lower generation (rebooted peer) now applies.
	if !s.shouldApplyConfigGen(3) {
		t.Fatal("gen 3 should admit after reset (rebooted peer)")
	}
}

// --- end-to-end ordered apply (RED-on-revert) ------------------------------

// configRecorder captures the sequence of SUCCESSFULLY applied config texts
// under a mutex so the ordered-apply consumer can be observed deterministically.
//
// failN, if > 0, makes the next failN record() calls return an error WITHOUT
// recording the text — simulating an apply that failed before promoting the
// store (a compile/promote failure or a transient RG0-primary rejection). This
// exercises the M-2/#4151 apply-then-advance contract.
type configRecorder struct {
	mu       sync.Mutex
	applied  []string
	failN    int
	attempts int
}

func (r *configRecorder) record(text string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.attempts++
	if r.failN > 0 {
		r.failN--
		return fmt.Errorf("simulated config apply failure for %q", text)
	}
	r.applied = append(r.applied, text)
	return nil
}

func (r *configRecorder) last() (string, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.applied) == 0 {
		return "", 0
	}
	return r.applied[len(r.applied)-1], len(r.applied)
}

// drainConfigApply waits for the ordered consumer to drain configApplyCh and
// finish the in-flight apply, so the recorder can be observed deterministically.
func drainConfigApply(t *testing.T, s *SessionSync) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(s.configApplyCh) == 0 {
			// Give the consumer a beat to finish the in-flight item.
			time.Sleep(5 * time.Millisecond)
			if len(s.configApplyCh) == 0 {
				return
			}
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// TestConfigSyncOrderedApplyDropsReorderedOlder is the #3931 RED-on-revert
// test. It delivers C2 (newer) BEFORE C1 (older) — the reordered-apply case —
// and asserts the standby ends on C2 and drops the stale C1. Under the
// pre-#3931 racing/no-gen behavior both would apply and the final state could
// be C1 (diverged), so this fails on revert.
func TestConfigSyncOrderedApplyDropsReorderedOlder(t *testing.T) {
	s := NewSessionSync("127.0.0.1:0", "127.0.0.1:0", nil)
	rec := &configRecorder{}
	s.OnConfigReceived = rec.record

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.configApplyLoop(ctx)

	// Reordered delivery: C2 (gen 2) enqueued before C1 (gen 1).
	s.configApplyCh <- configApplyItem{gen: 2, text: "config-C2"}
	s.configApplyCh <- configApplyItem{gen: 1, text: "config-C1"}

	drainConfigApply(t, s)

	last, count := rec.last()
	if last != "config-C2" {
		t.Fatalf("standby must end on the newest config C2, ended on %q (applied=%v)", last, rec.applied)
	}
	if count != 1 {
		t.Fatalf("only C2 should have applied; got %d applies: %v", count, rec.applied)
	}
	if got := s.stats.ConfigsStaleIgnored.Load(); got != 1 {
		t.Fatalf("stale C1 must be counted as dropped, ConfigsStaleIgnored=%d", got)
	}
	if got := s.lastAppliedConfigGen.Load(); got != 2 {
		t.Fatalf("last-applied gen should be 2 (C2), got %d", got)
	}
}

// In-order delivery applies both configs and the standby ends on the newest.
func TestConfigSyncOrderedApplyInOrder(t *testing.T) {
	s := NewSessionSync("127.0.0.1:0", "127.0.0.1:0", nil)
	rec := &configRecorder{}
	s.OnConfigReceived = rec.record

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.configApplyLoop(ctx)

	s.configApplyCh <- configApplyItem{gen: 1, text: "config-C1"}
	s.configApplyCh <- configApplyItem{gen: 2, text: "config-C2"}

	drainConfigApply(t, s)

	last, count := rec.last()
	if last != "config-C2" {
		t.Fatalf("standby must end on C2, ended on %q", last)
	}
	if count != 2 {
		t.Fatalf("both configs should apply in order, got %d: %v", count, rec.applied)
	}
	if got := s.stats.ConfigsStaleIgnored.Load(); got != 0 {
		t.Fatalf("no config should be dropped in-order, ConfigsStaleIgnored=%d", got)
	}
}

// A single config push applies normally (regression guard on the common path).
func TestConfigSyncSinglePushApplies(t *testing.T) {
	s := NewSessionSync("127.0.0.1:0", "127.0.0.1:0", nil)
	rec := &configRecorder{}
	s.OnConfigReceived = rec.record

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.configApplyLoop(ctx)

	s.configApplyCh <- configApplyItem{gen: 9, text: "config-only"}
	drainConfigApply(t, s)

	last, count := rec.last()
	if last != "config-only" || count != 1 {
		t.Fatalf("single push should apply once, got %q count=%d", last, count)
	}
}

// TestConfigSyncApplyFailureRetainsHighWater is the M-2 (#4151) RED-on-revert
// test. When the apply FAILS, the config high-water mark must NOT advance, so
// the primary's re-push of the SAME generation is re-admitted and re-attempted
// (the standby re-converges) instead of being silently dropped as stale.
//
// Under the pre-fix advance-before-apply order (admitConfigGen advanced the
// high-water BEFORE OnConfigReceived and ignored its result), the high-water
// jumped to the failed generation, the re-push was dropped as "not strictly
// newer," and the standby stayed stranded on the prior config — so this test
// fails on revert.
func TestConfigSyncApplyFailureRetainsHighWater(t *testing.T) {
	s := NewSessionSync("127.0.0.1:0", "127.0.0.1:0", nil)
	rec := &configRecorder{failN: 1} // fail the first apply, succeed after
	s.OnConfigReceived = rec.record

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.configApplyLoop(ctx)

	// (1) First delivery of gen 7 fails to apply.
	s.configApplyCh <- configApplyItem{gen: 7, text: "config-C7"}
	drainConfigApply(t, s)

	if got := s.lastAppliedConfigGen.Load(); got != 0 {
		t.Fatalf("apply failure must NOT advance the high-water mark, got %d (want 0)", got)
	}
	if got := s.stats.ConfigsApplyFailed.Load(); got != 1 {
		t.Fatalf("a failed apply must be counted in ConfigsApplyFailed, got %d", got)
	}
	if got := s.stats.ConfigsStaleIgnored.Load(); got != 0 {
		t.Fatalf("a failed apply must NOT be counted as stale-dropped, got %d", got)
	}
	if _, count := rec.last(); count != 0 {
		t.Fatalf("no config should have been recorded after the failed apply, got %d", count)
	}

	// (2) Primary re-pushes the SAME generation 7; it must be re-admitted (not
	// dropped as stale) and now applies successfully — the standby re-converges.
	s.configApplyCh <- configApplyItem{gen: 7, text: "config-C7"}
	drainConfigApply(t, s)

	last, count := rec.last()
	if last != "config-C7" || count != 1 {
		t.Fatalf("re-push of gen 7 must re-apply after the earlier failure, got %q count=%d", last, count)
	}
	if got := s.stats.ConfigsStaleIgnored.Load(); got != 0 {
		t.Fatalf("the re-push must NOT be dropped as stale, ConfigsStaleIgnored=%d", got)
	}
	if got := s.lastAppliedConfigGen.Load(); got != 7 {
		t.Fatalf("high-water must advance to 7 only AFTER the successful apply, got %d", got)
	}

	// (3) A THIRD push of gen 7, now AFTER a successful apply, is correctly
	// skipped as stale — proving the skip is legitimate only once the apply
	// actually succeeded (distinguishes it from the fail case in step 1).
	s.configApplyCh <- configApplyItem{gen: 7, text: "config-C7"}
	drainConfigApply(t, s)
	if _, count := rec.last(); count != 1 {
		t.Fatalf("a same-gen push after a successful apply must be skipped, applies=%d", count)
	}
	if got := s.stats.ConfigsStaleIgnored.Load(); got != 1 {
		t.Fatalf("the post-success same-gen push must be dropped as stale, ConfigsStaleIgnored=%d", got)
	}
}

// The QueueConfig sender + decodeConfigPayload receiver agree on the wire
// generation, and the drawn generations are strictly monotonic per push.
func TestNextConfigGenMonotonic(t *testing.T) {
	s := NewSessionSync("127.0.0.1:0", "127.0.0.1:0", nil)
	g1 := s.nextConfigGen()
	g2 := s.nextConfigGen()
	g3 := s.nextConfigGen()
	if !(g1 < g2 && g2 < g3) {
		t.Fatalf("config generations must be strictly monotonic, got %d,%d,%d", g1, g2, g3)
	}
	// A payload stamped with a drawn generation decodes back to the same value.
	payload := encodeConfigPayload("set system host-name x", g2)
	_, gen := decodeConfigPayload(payload)
	if gen != g2 {
		t.Fatalf("decoded gen %d != stamped gen %d", gen, g2)
	}
}
