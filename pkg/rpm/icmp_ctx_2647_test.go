// icmp_ctx_2647_test.go — #2647.
//
// ICMP RPM probes resolved their target hostname under context.Background(),
// so a stuck DNS lookup ignored the probe-cycle context
// (cancellation/deadline/config-reload/stop) — unlike the TCP DialContext
// and HTTP NewRequestWithContext paths, which are ctx-bound. The fix threads
// the probe ctx through the resolveTarget seam and resolveProbeTarget into
// the resolver's LookupIPAddr(ctx, target).
//
// These tests prove the ctx reaches the lookup for a HOSTNAME target and is
// irrelevant for a literal-IP target (which short-circuits before DNS). The
// fail-on-revert gate substitutes the lookupIPAddr seam with a resolver that
// blocks until its ctx is done: with the fix the canceled probe ctx is the
// ctx the lookup receives, so it returns promptly; reverting resolveProbeTarget
// to context.Background() hands the lookup a live ctx that never cancels, so it
// blocks past the bounded test deadline → red. Mirrors the #2614 seam-test
// style.
package rpm

import (
	"context"
	"net"
	"testing"
	"time"
)

// withBlockingLookup swaps the lookupIPAddr seam for one that ignores the
// resolver entirely and blocks until the ctx it is handed is Done — so the
// ONLY way the lookup returns is via the ctx that resolveProbeTarget threads
// in. Restores the original on cleanup.
func withBlockingLookup(t *testing.T) {
	t.Helper()
	orig := lookupIPAddr
	t.Cleanup(func() { lookupIPAddr = orig })
	lookupIPAddr = func(ctx context.Context, _ *net.Resolver, _ string) ([]net.IPAddr, error) {
		<-ctx.Done() // returns ONLY when the threaded ctx fires
		return nil, ctx.Err()
	}
}

// TestResolveProbeTargetHonorsCanceledCtx is the core #2647 fail-on-revert
// gate: with a HOSTNAME target and an already-canceled ctx, resolveProbeTarget
// must hand that ctx to the lookup so it returns PROMPTLY with the ctx error,
// instead of looking up under context.Background().
//
// fail-on-revert: revert resolveProbeTarget to LookupIPAddr(context.Background(),
// ...) and the blocking lookup receives a live background ctx that never
// cancels — it blocks past the 2s budget below, the goroutine never returns,
// and t.Fatal fires. The bounded select converts "hang" into a red test.
func TestResolveProbeTargetHonorsCanceledCtx(t *testing.T) {
	withBlockingLookup(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already canceled before the lookup

	type result struct {
		addr *net.IPAddr
		err  error
	}
	done := make(chan result, 1)
	go func() {
		addr, err := resolveProbeTarget(ctx, "host.example.com", probeSockOpts{BindDevice: "vrf-2647"})
		done <- result{addr, err}
	}()

	select {
	case res := <-done:
		if res.err == nil {
			t.Fatalf("resolveProbeTarget under a canceled ctx returned addr=%v, "+
				"want a ctx error", res.addr)
		}
		if !errMentionsCtx(res.err) {
			t.Fatalf("resolveProbeTarget err = %v, want it to wrap context.Canceled "+
				"(the probe ctx must reach the lookup)", res.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("resolveProbeTarget did not honor the canceled ctx within 2s — " +
			"DNS resolution ignored the probe ctx (#2647 regression: " +
			"context.Background() instead of the probe ctx)")
	}
}

// TestResolveProbeTargetHonorsDeadline mirrors the cancellation case with a
// past deadline: a HOSTNAME lookup under an expired ctx returns promptly.
// fail-on-revert: context.Background() ignores the deadline and the blocking
// lookup never returns → 2s budget trips.
func TestResolveProbeTargetHonorsDeadline(t *testing.T) {
	withBlockingLookup(t)

	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()

	done := make(chan error, 1)
	go func() {
		_, err := resolveProbeTarget(ctx, "host.example.com", probeSockOpts{BindDevice: "vrf-2647"})
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("resolveProbeTarget under an expired-deadline ctx returned nil error")
		}
		if !errMentionsCtx(err) {
			t.Fatalf("resolveProbeTarget err = %v, want it to wrap context.DeadlineExceeded", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("resolveProbeTarget did not honor the expired deadline within 2s (#2647)")
	}
}

// TestResolveProbeTargetLiteralIPIgnoresCtx confirms a literal-IP target
// short-circuits before any DNS, so even an already-canceled ctx resolves
// fine — ctx is irrelevant when there is no name to look up. (The blocking
// lookup seam is installed too: a literal IP must NOT reach it.)
func TestResolveProbeTargetLiteralIPIgnoresCtx(t *testing.T) {
	withBlockingLookup(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	addr, err := resolveProbeTarget(ctx, "203.0.113.7", probeSockOpts{BindDevice: "vrf-2647"})
	if err != nil {
		t.Fatalf("literal-IP target under a canceled ctx must still resolve "+
			"(no DNS, lookup seam not consulted): %v", err)
	}
	if !addr.IP.Equal(net.ParseIP("203.0.113.7")) {
		t.Fatalf("IP = %v, want 203.0.113.7", addr.IP)
	}
}

// errMentionsCtx reports whether err is (or wraps) a context error.
func errMentionsCtx(err error) bool {
	for e := err; e != nil; {
		if e == context.Canceled || e == context.DeadlineExceeded {
			return true
		}
		u, ok := e.(interface{ Unwrap() error })
		if !ok {
			break
		}
		e = u.Unwrap()
	}
	return false
}
