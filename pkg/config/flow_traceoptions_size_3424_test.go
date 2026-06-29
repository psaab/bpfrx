package config

import (
	"strings"
	"testing"
)

// #3424: `security flow traceoptions file <name> size <s> files <n>` copied
// both rotation tokens verbatim with no range check, so a committed
// `size 1 files 1000000000` made every matching trace line exceed the rotation
// threshold and turned each rotation into a ~1e9-iteration rename loop run
// synchronously from the event callback under the writer mutex (a per-event CPU
// storm). validateFlowTraceSizeFilesAST now hard-rejects an out-of-range size /
// files at strict commit / commit-check.
//
// FAIL-ON-REVERT: delete the validateFlowTraceSizeFilesAST call in compiler.go
// (or neuter the validator) and every reject subtest below goes GREEN, which is
// exactly the regression this guards.
func TestFlowTraceSizeFilesFailsCommit(t *testing.T) {
	cases := []struct {
		name string
		set  []string
		want string // substring the error must name
	}{
		{
			name: "size-below-minimum",
			set: []string{
				"set security flow traceoptions file rt-flow.log size 1",
			},
			want: "size",
		},
		{
			name: "size-above-maximum",
			set: []string{
				"set security flow traceoptions file rt-flow.log size 2147483648",
			},
			want: "size",
		},
		{
			name: "files-above-maximum-cpu-storm",
			set: []string{
				"set security flow traceoptions file rt-flow.log files 1000000000",
			},
			want: "files",
		},
		{
			name: "files-below-minimum",
			set: []string{
				"set security flow traceoptions file rt-flow.log files 1",
			},
			want: "files",
		},
		{
			name: "size-non-integer",
			set: []string{
				"set security flow traceoptions file rt-flow.log size abc",
			},
			want: "size",
		},
		{
			// files-only (no size token): exercises the child-collapsed shape
			// where the value lands in a child node's Keys rather than on the
			// file node's own Keys.
			name: "files-only-out-of-range",
			set: []string{
				"set security flow traceoptions file rt-flow.log files 5000",
			},
			want: "files",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildTree(t, tc.set)
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("expected strict commit to reject the out-of-range traceoptions size/files, got nil error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not name the offending token %q", err.Error(), tc.want)
			}
			if !strings.Contains(err.Error(), "traceoptions") {
				t.Fatalf("error %q does not name the traceoptions path", err.Error())
			}
		})
	}
}

// TestFlowTraceSizeFilesValidCommits is the anti-over-reject guard: an in-range
// size/files (and the boundary values) must still commit cleanly and land in
// the compiled config.
func TestFlowTraceSizeFilesValidCommits(t *testing.T) {
	cases := [][]string{
		{"set security flow traceoptions file rt-flow.log size 1048576 files 5"},
		// Boundary values must be accepted.
		{"set security flow traceoptions file rt-flow.log size 10240 files 2"},
		{"set security flow traceoptions file rt-flow.log size 1073741824 files 1000"},
		// size/files omitted entirely (defaults apply at runtime) must commit.
		{"set security flow traceoptions file rt-flow.log"},
	}
	for _, set := range cases {
		t.Run(set[0], func(t *testing.T) {
			tree := buildTree(t, set)
			if _, err := CompileConfig(tree); err != nil {
				t.Fatalf("strict commit rejected a valid traceoptions size/files: %v", err)
			}
		})
	}
}

// TestFlowTraceSizeFilesLenientDowngrade verifies the load / peer-sync path
// downgrades a persisted out-of-range size/files to a warning instead of
// failing the boot (#1960 fail-closed-on-load class) — NewTraceWriter
// independently clamps the value to a safe bound at runtime, so the per-event
// CPU storm cannot occur even on a leniently-loaded config.
//
// FAIL-ON-REVERT: drop the lenientFlowTraceSizeFiles downgrade (so the strict
// gate runs on the lenient path) and the boot fails instead of warning.
func TestFlowTraceSizeFilesLenientDowngrade(t *testing.T) {
	tree := buildTree(t, []string{
		"set security flow traceoptions file rt-flow.log size 1 files 1000000000",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient load must not fail on a persisted out-of-range size/files: %v", err)
	}
	wantSize, wantFiles := false, false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "traceoptions") && strings.Contains(w, "size") {
			wantSize = true
		}
		if strings.Contains(w, "traceoptions") && strings.Contains(w, "files") {
			wantFiles = true
		}
	}
	if !wantSize {
		t.Fatalf("lenient load did not record a size warning; warnings=%v", cfg.Warnings)
	}
	if !wantFiles {
		t.Fatalf("lenient load did not record a files warning; warnings=%v", cfg.Warnings)
	}
}
