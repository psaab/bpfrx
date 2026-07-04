package userspace

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// oldFixedControlDeadline is the pre-#4036 control-socket round-trip deadline.
// It is hard-coded (NOT derived from controlBaseDeadline) so the fail-on-revert
// assertions below go RED if the deadline is reverted to a fixed 3s for a large
// apply_snapshot.
const oldFixedControlDeadline = 3 * time.Second

// TestControlRoundtripDeadlineScales pins the deadline-sizing math (#4036).
// A small request keeps the base deadline (status poll stays responsive); a
// large apply_snapshot scales up per-MiB; the deadline is capped and monotone.
func TestControlRoundtripDeadlineScales(t *testing.T) {
	// Small requests (sub-1-MiB) keep EXACTLY the base — the frequent 1/s
	// status poll and per-session installs must not be slowed or given a
	// looser give-up point than before.
	for _, small := range []int{0, 1, 1024, (1 << 20) - 1} {
		if got := controlRoundtripDeadline(small); got != controlBaseDeadline {
			t.Fatalf("controlRoundtripDeadline(%d) = %v, want base %v (small requests unchanged)",
				small, got, controlBaseDeadline)
		}
	}
	// A negative length can never happen (len is non-negative) but must not
	// underflow into a tiny/negative deadline.
	if got := controlRoundtripDeadline(-1); got != controlBaseDeadline {
		t.Fatalf("controlRoundtripDeadline(-1) = %v, want base %v", got, controlBaseDeadline)
	}

	// Per-MiB scaling.
	cases := []struct {
		bodyLen int
		want    time.Duration
	}{
		{1 << 20, controlBaseDeadline + controlDeadlinePerMiB},     // 1 MiB
		{2 << 20, controlBaseDeadline + 2*controlDeadlinePerMiB},   // 2 MiB
		{20 << 20, controlBaseDeadline + 20*controlDeadlinePerMiB}, // 20 MiB feed
		{64 << 20, controlBaseDeadline + 64*controlDeadlinePerMiB}, // 64 MiB ceiling
		{MaxControlRequestBytes, controlBaseDeadline + 64*controlDeadlinePerMiB},
	}
	for _, c := range cases {
		if got := controlRoundtripDeadline(c.bodyLen); got != c.want {
			t.Fatalf("controlRoundtripDeadline(%d) = %v, want %v", c.bodyLen, got, c.want)
		}
	}

	// The 64 MiB apply_snapshot deadline is materially larger than the old
	// fixed 3s — this is the core of #4036 (a legit 64 MiB apply no longer
	// false-times-out at 3s).
	if got := controlRoundtripDeadline(MaxControlRequestBytes); got <= oldFixedControlDeadline {
		t.Fatalf("64 MiB deadline %v must exceed the old fixed %v (that is the #4036 fix)",
			got, oldFixedControlDeadline)
	}
	// ...yet it stays within the sane cap so a hung helper eventually times out.
	if got := controlRoundtripDeadline(MaxControlRequestBytes); got > controlMaxDeadline {
		t.Fatalf("64 MiB deadline %v must not exceed the cap %v", got, controlMaxDeadline)
	}
	// A body far past the cap (cannot occur — the #2744 pre-flight rejects it —
	// but the sizing must clamp regardless) hits the cap exactly.
	if got := controlRoundtripDeadline(1 << 30); got != controlMaxDeadline {
		t.Fatalf("controlRoundtripDeadline(1 GiB) = %v, want cap %v", got, controlMaxDeadline)
	}

	// Monotone non-decreasing.
	prev := controlRoundtripDeadline(0)
	for mb := 1; mb <= 200; mb++ {
		got := controlRoundtripDeadline(mb << 20)
		if got < prev {
			t.Fatalf("deadline not monotone at %d MiB: %v < %v", mb, got, prev)
		}
		prev = got
	}
}

// largeApplySnapshotBody builds an apply_snapshot ControlRequest whose
// serialized JSON body exceeds minBytes, using a feed-shaped address book of
// IPv6 CIDR text (the dominant scaling dimension per #2744). Returns the
// request and its serialized length.
func largeApplySnapshotBody(t *testing.T, minBytes int) (ControlRequest, int) {
	t.Helper()
	// Each "2001:db8:xxxx:yyyy::/64" entry serializes to ~28 bytes of JSON
	// (quotes + comma). Over-provision the count so we comfortably clear the
	// target, then assert the actual body size.
	n := (minBytes / 24) + 4096
	prefixes := make([]string, 0, n)
	for i := 0; i < n; i++ {
		prefixes = append(prefixes, fmt.Sprintf("2001:db8:%04x:%04x::/64", i&0xffff, (i>>16)&0xffff))
	}
	req := ControlRequest{
		Type: "apply_snapshot",
		Snapshot: &ConfigSnapshot{
			Version: ProtocolVersion,
			AddressBooks: []AddressBookSnapshot{
				{ID: 1, Name: "threat-feed", PrefixesV6: prefixes},
			},
		},
	}
	body, err := json.Marshal(&req)
	if err != nil {
		t.Fatalf("marshal large apply_snapshot: %v", err)
	}
	if len(body) < minBytes {
		t.Fatalf("generated body %d bytes < required %d", len(body), minBytes)
	}
	if len(body) > MaxControlRequestBytes {
		t.Fatalf("generated body %d bytes exceeds the #2744 cap %d", len(body), MaxControlRequestBytes)
	}
	return req, len(body)
}

// TestLargeApplySnapshotDoesNotFalseTimeout is the #4036 fail-on-revert proof.
// A large apply_snapshot whose helper-side apply takes LONGER than the old
// fixed 3s deadline (but well under the scaled deadline) must round-trip and
// report SUCCESS. Reverting requestDetailedLocked to a fixed 3s deadline makes
// this RED: Decode times out at 3s and reports the apply FAILED while the
// (mock) helper actually applied it.
func TestLargeApplySnapshotDoesNotFalseTimeout(t *testing.T) {
	// Body >= 3 MiB => scaled deadline >= base + 3s = 6s. The mock helper
	// sleeps 3.5s (> old fixed 3s, < scaled 6s) before replying.
	const bodyFloor = 3 << 20
	req, bodyLen := largeApplySnapshotBody(t, bodyFloor)

	scaled := controlRoundtripDeadline(bodyLen)
	const applyDelay = 3500 * time.Millisecond
	if applyDelay <= oldFixedControlDeadline {
		t.Fatalf("mock apply delay %v must exceed the old fixed deadline %v to prove the fix",
			applyDelay, oldFixedControlDeadline)
	}
	if scaled <= applyDelay {
		t.Fatalf("scaled deadline %v must exceed the mock apply delay %v (test misconfigured)",
			scaled, applyDelay)
	}

	dir := t.TempDir()
	controlSock := filepath.Join(dir, "control.sock")
	ln, err := net.Listen("unix", controlSock)
	if err != nil {
		t.Fatalf("listen control socket: %v", err)
	}
	defer ln.Close()

	gotType := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Drain the whole request first so the client's Write completes, then
		// model a slow-but-successful apply before replying.
		var got ControlRequest
		if err := json.NewDecoder(conn).Decode(&got); err != nil {
			return
		}
		gotType <- got.Type
		time.Sleep(applyDelay)
		_ = json.NewEncoder(conn).Encode(ControlResponse{OK: true, Status: &ProcessStatus{}})
	}()

	proc, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatalf("FindProcess: %v", err)
	}
	m := New()
	m.proc = &exec.Cmd{Process: proc}
	m.cfg.ControlSocket = controlSock

	start := time.Now()
	m.mu.Lock()
	resp, err := m.requestDetailedLocked(req)
	m.mu.Unlock()
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("large apply_snapshot falsely failed after %v (fixed-3s regression): %v", elapsed, err)
	}
	if !resp.OK {
		t.Fatalf("large apply_snapshot response not OK: %+v", resp)
	}
	if elapsed <= oldFixedControlDeadline {
		t.Fatalf("mock did not exercise the >3s window (elapsed %v) — test would not catch a revert", elapsed)
	}
	select {
	case typ := <-gotType:
		if typ != "apply_snapshot" {
			t.Fatalf("helper received unexpected request type %q", typ)
		}
	default:
		t.Fatal("helper never received the request — it did not round-trip")
	}
}

// TestHungHelperTimesOutAtScaledDeadline proves the scaled deadline still
// bounds a genuinely-hung helper: a small request whose helper accepts but
// never replies must time out (at the base deadline) rather than block forever.
func TestHungHelperTimesOutAtScaledDeadline(t *testing.T) {
	dir := t.TempDir()
	controlSock := filepath.Join(dir, "control.sock")
	ln, err := net.Listen("unix", controlSock)
	if err != nil {
		t.Fatalf("listen control socket: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		// Read the request, then hang forever without replying.
		var got ControlRequest
		_ = json.NewDecoder(conn).Decode(&got)
		select {} // block; the connection is closed when the process exits
	}()

	proc, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatalf("FindProcess: %v", err)
	}
	m := New()
	m.proc = &exec.Cmd{Process: proc}
	m.cfg.ControlSocket = controlSock

	// A small request keeps the base deadline (3s). Assert it returns an error
	// bounded by that deadline plus slack — never an unbounded hang.
	start := time.Now()
	m.mu.Lock()
	_, err = m.requestDetailedLocked(ControlRequest{Type: "ping"})
	m.mu.Unlock()
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("a hung helper must eventually time out, got nil error")
	}
	if elapsed > controlBaseDeadline+2*time.Second {
		t.Fatalf("timeout took %v, expected ~%v (deadline not enforced)", elapsed, controlBaseDeadline)
	}
	if elapsed < controlBaseDeadline-500*time.Millisecond {
		t.Fatalf("timeout fired too early at %v (base deadline is %v)", elapsed, controlBaseDeadline)
	}
}
