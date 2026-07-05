package configstore

import (
	"strings"
	"testing"
)

// fable-review-164 H-2: every parse entry point must reject an over-large
// payload with a clean error before it reaches config.NewParser, so a
// pathological input cannot exhaust memory or the goroutine stack. These tests
// pin the MaxConfigSize ceiling on LoadOverride, LoadMerge, LoadSet, and the HA
// SyncApply ingress, and confirm a normal-size config still loads.

func oversizedPayload() string {
	// Just over the ceiling; the content need not be valid config — the size
	// gate runs before the parser.
	return strings.Repeat("[", MaxConfigSize+1)
}

func TestLoadOverrideRejectsOversized(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	err := s.LoadOverride(oversizedPayload())
	if err == nil {
		t.Fatal("LoadOverride accepted an oversized payload")
	}
	if !strings.Contains(err.Error(), "config too large") {
		t.Fatalf("LoadOverride error = %q, want a size-ceiling rejection", err)
	}
}

func TestLoadMergeRejectsOversized(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	err := s.LoadMerge(oversizedPayload())
	if err == nil {
		t.Fatal("LoadMerge accepted an oversized payload")
	}
	if !strings.Contains(err.Error(), "config too large") {
		t.Fatalf("LoadMerge error = %q, want a size-ceiling rejection", err)
	}
}

func TestLoadSetRejectsOversized(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	_, err := s.LoadSet(oversizedPayload())
	if err == nil {
		t.Fatal("LoadSet accepted an oversized payload")
	}
	if !strings.Contains(err.Error(), "config too large") {
		t.Fatalf("LoadSet error = %q, want a size-ceiling rejection", err)
	}
}

func TestSyncApplyRejectsOversized(t *testing.T) {
	s := newTestStore(t)
	_, err := s.SyncApply(oversizedPayload(), nil)
	if err == nil {
		t.Fatal("SyncApply accepted an oversized peer config")
	}
	if !strings.Contains(err.Error(), "config too large") {
		t.Fatalf("SyncApply error = %q, want a size-ceiling rejection", err)
	}
}

// TestLoadOverrideAcceptsNormalConfig confirms the ceiling never rejects a
// legitimate (well-under-1-MiB) configuration.
func TestLoadOverrideAcceptsNormalConfig(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	src := `system {
    host-name fw;
}`
	if err := s.LoadOverride(src); err != nil {
		t.Fatalf("LoadOverride rejected a normal config: %v", err)
	}
}
