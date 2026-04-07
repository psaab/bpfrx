package daemon

import (
	"strings"
	"testing"
	"time"
)

func TestWaitLocalFailoverCommitReadyWaitsForPromotionSettle(t *testing.T) {
	d := &Daemon{
		cluster:                    newClusterManager(true),
		localFailoverCommitReady:   make(map[int]bool),
		localFailoverCommitTimeout: 200 * time.Millisecond,
		localFailoverCommitDelay:   0,
	}

	done := make(chan error, 1)
	go func() {
		done <- d.waitLocalFailoverCommitReady([]int{0})
	}()

	time.Sleep(20 * time.Millisecond)
	d.setLocalFailoverCommitReady(0, true)

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("waitLocalFailoverCommitReady() error = %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for failover commit settle")
	}
}

func TestWaitLocalFailoverCommitReadyTimesOutWithoutPromotionSettle(t *testing.T) {
	d := &Daemon{
		cluster:                    newClusterManager(true),
		localFailoverCommitReady:   make(map[int]bool),
		localFailoverCommitTimeout: 30 * time.Millisecond,
		localFailoverCommitDelay:   0,
	}

	err := d.waitLocalFailoverCommitReady([]int{0})
	if err == nil {
		t.Fatal("expected timeout waiting for failover commit settle")
	}
	if !strings.Contains(err.Error(), "timed out waiting for local failover activation settle") {
		t.Fatalf("waitLocalFailoverCommitReady() error = %v", err)
	}
}
