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

func TestCoSBufferSizeTemporal_EmitsInertAdvisory(t *testing.T) {
	cfg := mustCompileSet4228(t,
		"set class-of-service schedulers be buffer-size temporal 50000",
	)
	warnings := config.ValidateConfig(cfg)
	found := false
	for _, w := range warnings {
		if strings.Contains(w, "buffer-size temporal") && strings.Contains(w, "inert") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected an accepted-but-inert advisory for buffer-size temporal, got: %v", warnings)
	}
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
