package daemon

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRunHAShutdownUpdateReturnsOnContextDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	started := make(chan struct{})
	release := make(chan struct{})
	defer close(release)

	begin := time.Now()
	err := runHAShutdownUpdate(ctx, func(context.Context) error {
		close(started)
		<-release
		return nil
	})
	elapsed := time.Since(begin)

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("runHAShutdownUpdate error = %v, want deadline exceeded", err)
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("runHAShutdownUpdate elapsed = %s, want hard deadline return", elapsed)
	}
	select {
	case <-started:
	default:
		t.Fatal("shutdown update was not invoked before deadline")
	}
}
