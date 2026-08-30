package daemon

import (
	"testing"
)

// #7194 mixed-version behaviour: a helper whose session-delta schema is not
// this binary's must have its deltas WITHHELD, never zero-filled — and the
// refusal must be observable.
//
// FAIL-ON-REVERT: make userspaceDeltaSchemaAdmits return true unconditionally
// and the mismatch cell reds; collapse unknown into mismatch and the
// older-helper cell reds (that is the brick this gate must not become).

func TestDeltaSchemaGateAdmitsMatchingAndUnknown7194(t *testing.T) {
	local := localSessionDeltaSchemaFingerprint()

	t.Run("matching helper is admitted", func(t *testing.T) {
		d := &Daemon{}
		d.recordUserspaceDeltaSchema(local)
		if !d.userspaceDeltaSchemaAdmits(4) {
			t.Error("a helper advertising this binary's schema must be admitted")
		}
		if got := d.UserspaceDeltaSchemaWithheldCount(); got != 0 {
			t.Errorf("nothing should be withheld, got %d", got)
		}
	})

	// The state that must NOT be treated as a mismatch. A helper predating the
	// field advertises 0; refusing it would stop HA sync against an older
	// helper on the strength of a reading that never happened.
	t.Run("older helper advertising nothing is admitted", func(t *testing.T) {
		d := &Daemon{}
		d.recordUserspaceDeltaSchema(0)
		if !d.userspaceDeltaSchemaAdmits(4) {
			t.Error("a helper advertising no fingerprint must be permitted, not bricked")
		}
		if got := d.UserspaceDeltaSchemaWithheldCount(); got != 0 {
			t.Errorf("nothing should be withheld for an unknown fingerprint, got %d", got)
		}
	})

	// Never observed at all — the gate runs before any drain has returned a
	// status. Must behave exactly like unknown.
	t.Run("never observed is admitted", func(t *testing.T) {
		d := &Daemon{}
		if !d.userspaceDeltaSchemaAdmits(4) {
			t.Error("before any status is observed the gate must permit")
		}
	})
}

func TestDeltaSchemaGateWithholdsOnMismatch7194(t *testing.T) {
	d := &Daemon{}
	foreign := localSessionDeltaSchemaFingerprint() ^ 0x5555_5555_5555_5555
	d.recordUserspaceDeltaSchema(foreign)

	if d.userspaceDeltaSchemaAdmits(7) {
		t.Fatal("a helper whose delta schema differs must NOT be admitted — that is the zero-fill this gate exists to prevent")
	}
	if got := d.UserspaceDeltaSchemaWithheldCount(); got != 1 {
		t.Errorf("withheld count = %d, want 1 — a silent refusal is worse than the bug", got)
	}
	// Repeated refusals keep counting (the observable must not saturate at 1)
	// even though the WARNING is dampened to one per episode.
	d.userspaceDeltaSchemaAdmits(7)
	d.userspaceDeltaSchemaAdmits(7)
	if got := d.UserspaceDeltaSchemaWithheldCount(); got != 3 {
		t.Errorf("withheld count = %d, want 3 — the counter must keep advancing while the log is dampened", got)
	}
}

// A helper restart that fixes the mismatch must re-arm the one-shot warning,
// or a second episode is swallowed by the first episode's dampener and the
// operator never learns HA stopped syncing again.
func TestDeltaSchemaWarningReArmsAfterRecovery7194(t *testing.T) {
	d := &Daemon{}
	local := localSessionDeltaSchemaFingerprint()
	foreign := local ^ 0x0f0f_0f0f_0f0f_0f0f

	d.recordUserspaceDeltaSchema(foreign)
	d.userspaceDeltaSchemaAdmits(1)
	if !d.userspaceDeltaSchemaLogged.Load() {
		t.Fatal("first mismatch must arm the one-shot warning")
	}

	// Helper replaced with a matching build.
	d.recordUserspaceDeltaSchema(local)
	if d.userspaceDeltaSchemaLogged.Load() {
		t.Error("recovering to a matching schema must re-arm the warning for the next episode")
	}
	if !d.userspaceDeltaSchemaAdmits(1) {
		t.Error("after recovery the gate must admit again")
	}
}
