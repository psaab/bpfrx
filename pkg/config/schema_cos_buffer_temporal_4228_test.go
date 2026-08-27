package config_test

// #4228 Gap 2 follow-up: CoS scheduler `buffer-size` accepts the Junos
// `temporal <microseconds>` form in addition to an absolute byte-size (16m)
// and a percent (10%). temporal is ACCEPTED-BUT-INERT — xpf stores the
// microsecond target but does not yet resolve it to a byte-size (that needs
// the queue's transmit rate), so a commit advisory surfaces the inertness.
//
// FAIL-ON-REVERT: with the tailValidator + temporal child removed and the
// plain ValueByteSizeOrPercent validator restored, `buffer-size temporal
// 50000` is rejected at SchemaValidate (the value token "temporal" is not a
// byte-size), and the compiled BufferSizeTemporalUS field disappears.

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestCoSBufferSizeTemporal_AcceptsAndCompiles(t *testing.T) {
	cfg := mustCompileSet4228(t,
		"set class-of-service schedulers be buffer-size temporal 50000",
	)
	sched := cfg.ClassOfService.Schedulers["be"]
	if sched == nil {
		t.Fatal("expected be scheduler")
	}
	if sched.BufferSizeTemporalUS != 50000 {
		t.Fatalf("BufferSizeTemporalUS = %d, want 50000", sched.BufferSizeTemporalUS)
	}
	if sched.BufferSizeBytes != 0 || sched.BufferSizePercent != 0 {
		t.Fatalf("temporal form must not set bytes/percent (bytes=%d percent=%v)",
			sched.BufferSizeBytes, sched.BufferSizePercent)
	}
}

// TestTemporalAdvisoryNarrowsToUnresolvable6846 replaces the #4228 blanket
// inert-advisory assertion. #6846 makes `buffer-size temporal` RESOLVE against
// the queue's transmit rate, so the advisory must narrow to the case that still
// cannot: a queue with no resolvable rate has no drain speed.
//
// BOTH DIRECTIONS ARE ASSERTED, and the second is the one that matters. An
// advisory that keeps firing for configurations that now work is as much a
// defect as one that stops firing for configurations that do not — it teaches
// the operator to ignore it. A cell that only checked "it still warns" would
// pass against a change that never narrowed anything.
func TestTemporalAdvisoryNarrowsToUnresolvable6846(t *testing.T) {
	hasTemporalAdvisory := func(t *testing.T, lines ...string) bool {
		t.Helper()
		for _, w := range config.ValidateConfig(mustCompileSet4228(t, lines...)) {
			if strings.Contains(w, "buffer-size temporal") {
				return true
			}
		}
		return false
	}

	t.Run("no resolvable rate still warns", func(t *testing.T) {
		// A bare scheduler: no absolute rate, and not bound via a
		// scheduler-map to a shaped interface. Nothing to convert against.
		if !hasTemporalAdvisory(t,
			"set class-of-service schedulers be buffer-size temporal 50000",
		) {
			t.Fatal("a temporal target on a queue with no resolvable transmit-rate " +
				"must still warn — there is no drain speed to convert it against")
		}
	})

	t.Run("remainder with a shaping base resolves, so it must NOT warn", func(t *testing.T) {
		// A `remainder` queue bound via a scheduler-map to a shaped interface
		// HAS a resolvable rate, so temporal converts against it. Found by the
		// mutation matrix: making cosSchedulerRateResolves ignore
		// TransmitRateRemainder escaped GREEN against the whole Go suite,
		// because every other fixture reaches a resolvable rate by the
		// ABSOLUTE route and cannot tell the two apart.
		if hasTemporalAdvisory(t,
			"set class-of-service schedulers be transmit-rate remainder",
			"set class-of-service schedulers be buffer-size temporal 50000",
			"set class-of-service scheduler-maps sm forwarding-class best-effort scheduler be",
			"set class-of-service interfaces ge-0/0/0 scheduler-map sm",
			"set class-of-service interfaces ge-0/0/0 shaping-rate 100m",
		) {
			t.Fatal("#6846: a `remainder` queue with a shaping base resolves, so " +
				"temporal converts against it and the advisory must not fire")
		}
	})

	t.Run("remainder with a ZERO leftover still warns", func(t *testing.T) {
		// The subtest above binds a lone remainder queue to a 100m shape, so
		// the leftover is the whole 100m — it varies the right axis and samples
		// only the passing point. It cannot tell "resolves to a usable rate"
		// from "resolves to zero and is therefore still inert".
		//
		// Here siblings claim the entire shaping-rate, so the leftover is zero.
		// The dataplane declines a zero share (zero is its unshaped sentinel),
		// so the queue has no rate, temporal has no drain speed to convert
		// against, and the advisory MUST still fire. Suppressing it here would
		// be an advisory regression: a config that warned before, does not now,
		// and gained nothing at runtime.
		if !hasTemporalAdvisory(t,
			"set class-of-service schedulers full transmit-rate percent 100",
			"set class-of-service schedulers be transmit-rate remainder",
			"set class-of-service schedulers be buffer-size temporal 50000",
			"set class-of-service scheduler-maps sm forwarding-class assured-forwarding scheduler full",
			"set class-of-service scheduler-maps sm forwarding-class best-effort scheduler be",
			"set class-of-service interfaces ge-0/0/0 scheduler-map sm",
			"set class-of-service interfaces ge-0/0/0 shaping-rate 100m",
		) {
			t.Fatal("#6846: siblings claiming the whole shaping-rate leave a ZERO " +
				"leftover, the dataplane declines it, and the queue is still inert — " +
				"so the temporal advisory must still fire")
		}
	})

	t.Run("absolute rate resolves, so it must NOT warn", func(t *testing.T) {
		// An explicit transmit-rate needs no shaping base, so temporal
		// converts and the advisory must be gone.
		if hasTemporalAdvisory(t,
			"set class-of-service schedulers be transmit-rate 10m",
			"set class-of-service schedulers be buffer-size temporal 50000",
		) {
			t.Fatal("#6846: temporal RESOLVES against an explicit transmit-rate, so " +
				"the advisory must not fire. An advisory that keeps firing for a " +
				"configuration that now works teaches the operator to ignore it")
		}
	})
}

// The byte-size and percent forms must keep working after the tailValidator
// conversion (regression guard for the leaf-shape change).
func TestCoSBufferSizeBytesAndPercent_StillCompile(t *testing.T) {
	cfg := mustCompileSet4228(t,
		"set class-of-service schedulers b1 buffer-size 16m",
		"set class-of-service schedulers b2 buffer-size 10%",
	)
	if got := cfg.ClassOfService.Schedulers["b1"].BufferSizeBytes; got == 0 {
		t.Fatalf("buffer-size 16m should compile to bytes, got %d", got)
	}
	if got := cfg.ClassOfService.Schedulers["b2"].BufferSizePercent; got != 10 {
		t.Fatalf("buffer-size 10%% should compile to percent 10, got %v", got)
	}
}

func TestCoSBufferSizeTemporalZero_Rejected(t *testing.T) {
	err := flatSchemaCheck(t, "set class-of-service schedulers be buffer-size temporal 0")
	if err == nil {
		t.Fatal("expected error for `buffer-size temporal 0`")
	}
	if !strings.Contains(err.Error(), "temporal") {
		t.Fatalf("error should reference temporal: %v", err)
	}
}

func TestCoSBufferSizeTemporalGarbage_Rejected(t *testing.T) {
	err := flatSchemaCheck(t, "set class-of-service schedulers be buffer-size temporal abc")
	if err == nil {
		t.Fatal("expected error for `buffer-size temporal abc`")
	}
}

func TestCoSBufferSizeTemporalMissingValue_Rejected(t *testing.T) {
	err := flatSchemaCheck(t, "set class-of-service schedulers be buffer-size temporal")
	if err == nil {
		t.Fatal("expected error for `buffer-size temporal` with no value")
	}
}
