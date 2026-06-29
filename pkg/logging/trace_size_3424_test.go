package logging

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestTraceWriter_SizeFilesClamped pins the #3424 runtime fail-safe clamp:
// NewTraceWriter clamps an out-of-range `size`/`files` (the value a
// leniently-loaded / peer-synced config can carry past the strict commit gate)
// to the same FlowTraceMin/Max bounds the gate enforces. A sub-minimum size or
// an absurd file count would otherwise rotate on every trace line and run a
// ~1e9-iteration rename loop under the writer mutex (a per-event CPU storm).
//
// RED-on-revert: remove the clamp block in NewTraceWriter and maxSize stays 1 /
// maxFiles stays 1000000000 (and the over-maximum cases keep their raw values),
// so every assertion below fails.
func TestTraceWriter_SizeFilesClamped(t *testing.T) {
	dir := t.TempDir()
	old := traceLogDir
	traceLogDir = dir
	defer func() { traceLogDir = old }()

	cases := []struct {
		name      string
		size      int
		files     int
		wantSize  int64
		wantFiles int
	}{
		{
			name: "cpu-storm-config", size: 1, files: 1000000000,
			wantSize: config.FlowTraceMinFileSize, wantFiles: config.FlowTraceMaxFileCount,
		},
		{
			name: "above-maximum", size: 2 * config.FlowTraceMaxFileSize, files: 5000,
			wantSize: config.FlowTraceMaxFileSize, wantFiles: config.FlowTraceMaxFileCount,
		},
		{
			name: "files-below-minimum", size: 1048576, files: 1,
			wantSize: 1048576, wantFiles: config.FlowTraceMinFileCount,
		},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tw, err := NewTraceWriter(&config.FlowTraceoptions{
				File:      fmt.Sprintf("rt-%d.log", i),
				FileSize:  tc.size,
				FileCount: tc.files,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer tw.Close()
			if tw.maxSize != tc.wantSize {
				t.Fatalf("maxSize = %d, want clamped to %d", tw.maxSize, tc.wantSize)
			}
			if tw.maxFiles != tc.wantFiles {
				t.Fatalf("maxFiles = %d, want clamped to %d", tw.maxFiles, tc.wantFiles)
			}
		})
	}
}

// TestTraceWriter_SubMinimumSizeNoPerLineRotation pins the behavioral
// consequence of the #3424 clamp: with a configured `size 1` the writer must
// NOT rotate on every trace line (which is the CPU storm). After the clamp the
// effective size is FlowTraceMinFileSize, so a handful of short trace lines
// stays in the active file and produces no rotated generation.
//
// RED-on-revert: drop the clamp and maxSize=1, so the first HandleEvent write
// rotates immediately and rot.log.1 appears — the storm this guards.
func TestTraceWriter_SubMinimumSizeNoPerLineRotation(t *testing.T) {
	dir := t.TempDir()
	old := traceLogDir
	traceLogDir = dir
	defer func() { traceLogDir = old }()

	tw, err := NewTraceWriter(&config.FlowTraceoptions{File: "rot.log", FileSize: 1, FileCount: 1000000})
	if err != nil {
		t.Fatal(err)
	}
	defer tw.Close()

	for i := 0; i < 8; i++ {
		tw.HandleEvent(EventRecord{Type: "SESSION_OPEN", SrcAddr: "10.0.1.5:1000", DstAddr: "10.0.2.5:80", Protocol: "TCP"}, nil)
	}
	if _, err := os.Stat(filepath.Join(dir, "rot.log.1")); err == nil {
		t.Fatalf("rot.log.1 exists: sub-minimum size rotated per-line (clamp not enforced, CPU storm)")
	}
}

// TestTraceWriter_RotationEnforcesSizeAndFiles pins that the writer enforces the
// (clamped) size and files caps end to end: writing past the size threshold
// rotates, and the retained generation count never exceeds maxFiles. This is the
// enforcement half of #3424 — a bounded size/files actually bounds the on-disk
// footprint.
func TestTraceWriter_RotationEnforcesSizeAndFiles(t *testing.T) {
	dir := t.TempDir()
	old := traceLogDir
	traceLogDir = dir
	defer func() { traceLogDir = old }()

	// FileSize is clamped up to FlowTraceMinFileSize (10 KiB); drive enough
	// trace lines through to rotate several times and prove the files cap holds.
	tw, err := NewTraceWriter(&config.FlowTraceoptions{File: "rot.log", FileSize: 1, FileCount: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer tw.Close()
	if tw.maxFiles != 2 {
		t.Fatalf("maxFiles = %d, want 2", tw.maxFiles)
	}

	// Each trace line is ~80 bytes; 10 KiB threshold rotates roughly every ~130
	// lines. 2000 lines forces many rotations.
	for i := 0; i < 2000; i++ {
		tw.HandleEvent(EventRecord{Type: "SESSION_OPEN", SrcAddr: "10.0.1.5:1000", DstAddr: "10.0.2.5:80", Protocol: "TCP"}, nil)
	}

	// The files cap (2) retains generations .1 and .2; .3 and beyond must be
	// pruned (rotate removes maxFiles+1). Without the cap the generation count
	// grows unbounded.
	if _, err := os.Stat(filepath.Join(dir, "rot.log.3")); err == nil {
		t.Fatalf("rot.log.3 exists; files cap (2) not enforced")
	}
	// The active file must respect the (clamped) size cap, give or take one line.
	fi, err := os.Stat(filepath.Join(dir, "rot.log"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() > config.FlowTraceMinFileSize+256 {
		t.Fatalf("active file size %d exceeds clamped cap %d; rotation not triggered", fi.Size(), int64(config.FlowTraceMinFileSize))
	}
}
