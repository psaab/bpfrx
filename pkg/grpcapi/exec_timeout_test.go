package grpcapi

import (
	"context"
	"strings"
	"testing"
	"time"
)

// The helpers derive their deadline from the parent ctx via
// context.WithTimeout(parent, 15s) — the effective deadline is the
// earlier of the two. The timeout tests pass a short parent deadline so
// the kill path is exercised without waiting out the real 15s constant
// (pkg/daemon/exec_timeout.go, the contract reference, ships untested;
// this is the precedent for both per-package helper copies).

func TestOutputTimeoutStdoutOnly(t *testing.T) {
	out, err := outputTimeout(context.Background(), "sh", "-c", "echo out; echo err 1>&2")
	if err != nil {
		t.Fatalf("outputTimeout: %v", err)
	}
	if string(out) != "out\n" {
		t.Fatalf("outputTimeout = %q, want %q (stderr must not leak into stdout-only sites)", out, "out\n")
	}
}

func TestCombinedOutputTimeoutMergesStderr(t *testing.T) {
	out, err := combinedOutputTimeout(context.Background(), "sh", "-c", "echo out; echo err 1>&2")
	if err != nil {
		t.Fatalf("combinedOutputTimeout: %v", err)
	}
	s := string(out)
	if !strings.Contains(s, "out") || !strings.Contains(s, "err") {
		t.Fatalf("combinedOutputTimeout = %q, want both stdout and stderr", s)
	}
}

func TestCombinedOutputTimeoutKillsHungCommand(t *testing.T) {
	parent, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := combinedOutputTimeout(parent, "sleep", "30")
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("combinedOutputTimeout: want error for killed command, got nil")
	}
	// Bound: 200ms deadline + 5s WaitDelay worst case, with slack.
	if elapsed > 10*time.Second {
		t.Fatalf("combinedOutputTimeout took %v, command was not killed by the deadline", elapsed)
	}
}

func TestRunTimeoutKillsHungCommand(t *testing.T) {
	parent, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := runTimeout(parent, "sleep", "30")
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("runTimeout: want error for killed command, got nil")
	}
	if elapsed > 10*time.Second {
		t.Fatalf("runTimeout took %v, command was not killed by the deadline", elapsed)
	}
}

func TestClampTailLines(t *testing.T) {
	cases := []struct{ in, want int }{
		{-7, 1},
		{0, 1},
		{1, 1},
		{50, 50},
		{maxTailLines, maxTailLines},
		{maxTailLines + 1, maxTailLines},
		{1 << 30, maxTailLines},
	}
	for _, c := range cases {
		if got := clampTailLines(c.in); got != c.want {
			t.Errorf("clampTailLines(%d) = %d, want %d", c.in, got, c.want)
		}
	}
}
