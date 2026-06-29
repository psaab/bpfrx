package config

import (
	"strings"
	"testing"
)

// #3420: `security flow traceoptions file <name>` was stored verbatim and
// NewTraceWriter joined/opened it under /var/log without rejecting an absolute
// path or a ".." escape, so a committed config could append root-written flow
// telemetry anywhere the daemon user can write. validateFlowTraceFileAST now
// hard-rejects a non-basename file value at strict commit / commit-check.
//
// FAIL-ON-REVERT: delete the validateFlowTraceFileAST call in compiler.go (or
// neuter flowTraceFileNameError) and every reject subtest below goes GREEN on
// the traversal config, which is exactly the regression this guards.
func TestFlowTraceFilePathTraversalFailsCommit(t *testing.T) {
	cases := []struct {
		name string
		line string
		want string // substring the error must name
	}{
		{
			name: "absolute-path",
			line: "set security flow traceoptions file /tmp/rt-flow-leak",
			want: "/tmp/rt-flow-leak",
		},
		{
			name: "dotdot-escape",
			line: "set security flow traceoptions file ../../tmp/rt-flow-leak",
			want: "../../tmp/rt-flow-leak",
		},
		{
			name: "subdir-separator",
			line: "set security flow traceoptions file sub/dir/x",
			want: "sub/dir/x",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildTree(t, []string{tc.line})
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("expected strict commit to reject a non-basename flow-trace file, got nil error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not name the offending file value %q", err.Error(), tc.want)
			}
			if !strings.Contains(err.Error(), "traceoptions") {
				t.Fatalf("error %q does not name the traceoptions path", err.Error())
			}
		})
	}
}

// TestFlowTraceFileBasenameCommits is the anti-over-reject guard: a legitimate
// bare basename (with size/files attributes) must still commit cleanly.
func TestFlowTraceFileBasenameCommits(t *testing.T) {
	tree := buildTree(t, []string{
		"set security flow traceoptions file rt-flow.log size 1048576 files 5",
		"set security flow traceoptions flag basic-datapath",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("strict commit rejected a valid basename flow-trace file: %v", err)
	}
	to := cfg.Security.Flow.Traceoptions
	if to == nil || to.File != "rt-flow.log" {
		t.Fatalf("traceoptions file = %+v, want File=rt-flow.log", to)
	}
}

// TestFlowTraceFileLenientDowngrade verifies the load / peer-sync path
// downgrades a persisted non-basename value to a warning instead of failing the
// boot (#1960 fail-closed-on-load class) — NewTraceWriter independently refuses
// the unsafe path at runtime.
func TestFlowTraceFileLenientDowngrade(t *testing.T) {
	tree := buildTree(t, []string{
		"set security flow traceoptions file ../../tmp/rt-flow-leak",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient load must not fail on a persisted traversal value: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "../../tmp/rt-flow-leak") && strings.Contains(w, "traceoptions") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("lenient load did not record a flow-trace file warning; warnings=%v", cfg.Warnings)
	}
}
