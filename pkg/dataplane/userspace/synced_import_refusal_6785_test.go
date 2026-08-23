package userspace

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/psaab/xpf/pkg/dataplane"
)

// newAnsweringManager6785 builds a Manager whose helper session socket is LIVE
// and answers every request with the supplied response. That is the shape the
// #6785 discrimination turns on: the socket round-trips fine, so it is NOT the
// unreachable-helper case newMirrorFailManager5305 produces — the failure comes
// back IN the answer.
func newAnsweringManager6785(t *testing.T, resp ControlResponse) *Manager {
	t.Helper()
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("RemoveMemlock: %v", err)
	}
	dir := t.TempDir()
	sessionSock := filepath.Join(dir, "userspace-dp-sessions.sock")
	ln, err := net.Listen("unix", sessionSock)
	if err != nil {
		t.Fatalf("listen session socket: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				var req ControlRequest
				_ = json.NewDecoder(conn).Decode(&req)
				_ = json.NewEncoder(conn).Encode(resp)
			}()
		}
	}()
	m := New()
	m.proc = &exec.Cmd{Process: &os.Process{Pid: 1}}
	m.cfg.ControlSocket = filepath.Join(dir, "control.sock")
	injectSessionMaps(t, m)
	return m
}

// TestSyncedImportRefusalRollsBackWithoutGatingTakeover6785 is the #6785
// contract on the Go side, and it is a PAIRED test: the same call site, two
// helper answers, opposite health outcomes.
//
// A SEMANTIC refusal (`ok=false` with the helper's refusal token) must:
//   - roll the BPF mirror row back, because the helper did NOT take the session
//     and a row left behind is the split truth #5305 exists to prevent;
//   - NOT set sessionMirrorFailed, because that gates HA takeover-readiness
//     (#5247) and the helper is healthy — it answered correctly;
//   - be counted as its own debt.
//
// A TRANSPORT-shaped failure (`ok=false` with any other message) must do the
// opposite on the health flag. Without that half, "does not set the flag on a
// refusal" would be satisfied by an implementation that never sets the flag at
// all, which silently removes the #5247 gate.
func TestSyncedImportRefusalRollsBackWithoutGatingTakeover6785(t *testing.T) {
	key := rollbackKeyV4()
	val := dataplane.SessionValue{IsReverse: 0, IngressZone: 1, EgressZone: 2}

	t.Run("semantic-refusal", func(t *testing.T) {
		m := newAnsweringManager6785(t, ControlResponse{
			OK:    false,
			Error: syncedImportRefusedPrefix + "capacity",
		})

		err := m.SetClusterSyncedSessionV4(key, val)
		if err == nil {
			t.Fatal("SetClusterSyncedSessionV4() = nil after the helper REFUSED " +
				"the import — the caller records a success and keeps a BPF row " +
				"for a session the helper never took (#6785)")
		}
		if !errors.Is(err, dataplane.ErrSyncedImportRefused) {
			t.Fatalf("error does not classify as a semantic refusal: %v", err)
		}
		if _, getErr := m.bpfShim.GetSessionV4(key); !errors.Is(getErr, ebpf.ErrKeyNotExist) {
			t.Fatalf("BPF row survived a REFUSED import: GetSessionV4 err = %v, "+
				"want ErrKeyNotExist — this is the split truth", getErr)
		}
		if m.sessionMirrorFailed {
			t.Fatal("sessionMirrorFailed = true after a SEMANTIC refusal: the " +
				"helper answered correctly, so gating HA takeover-readiness on " +
				"this would keep a working standby from ever taking over once a " +
				"peer oversubscribed it (#5247)")
		}
		if got := m.syncedImportRefusals.Load(); got != 1 {
			t.Fatalf("syncedImportRefusals = %d, want 1 — a rolled-back import "+
				"that is counted nowhere is not health debt, it is a silent drop", got)
		}
	})

	t.Run("non-refusal-failure-still-gates", func(t *testing.T) {
		m := newAnsweringManager6785(t, ControlResponse{
			OK:    false,
			Error: "session table write failed",
		})

		err := m.SetClusterSyncedSessionV4(key, val)
		if err == nil {
			t.Fatal("SetClusterSyncedSessionV4() = nil on a helper failure")
		}
		if errors.Is(err, dataplane.ErrSyncedImportRefused) {
			t.Fatalf("an UNPREFIXED helper error was classified as a semantic "+
				"refusal: %v — the classifier is matching too broadly and every "+
				"real mirror failure would stop gating takeover", err)
		}
		if !m.sessionMirrorFailed {
			t.Fatal("sessionMirrorFailed = false on a non-refusal helper " +
				"failure — the #5247 takeover gate is gone")
		}
		if got := m.syncedImportRefusals.Load(); got != 0 {
			t.Fatalf("syncedImportRefusals = %d on a non-refusal failure, want 0", got)
		}
	})
}

// TestSyncedImportRefusalRollsBackWithoutGatingTakeoverV6_6785 is the IPv6 twin.
// The two entry points carry independently written copies of the classify /
// compensate / count sequence, so a divergence between them is always a bug and
// each needs its own cell — binding only V4 would let V6 keep reporting success.
func TestSyncedImportRefusalRollsBackWithoutGatingTakeoverV6_6785(t *testing.T) {
	key := rollbackKeyV6()
	val := dataplane.SessionValueV6{IsReverse: 0, IngressZone: 1, EgressZone: 2}

	m := newAnsweringManager6785(t, ControlResponse{
		OK:    false,
		Error: syncedImportRefusedPrefix + "stale-generation",
	})

	err := m.SetClusterSyncedSessionV6(key, val)
	if err == nil {
		t.Fatal("SetClusterSyncedSessionV6() = nil after the helper REFUSED the import (#6785)")
	}
	if !errors.Is(err, dataplane.ErrSyncedImportRefused) {
		t.Fatalf("v6 error does not classify as a semantic refusal: %v", err)
	}
	if _, getErr := m.bpfShim.GetSessionV6(key); !errors.Is(getErr, ebpf.ErrKeyNotExist) {
		t.Fatalf("v6 BPF row survived a REFUSED import: err = %v, want ErrKeyNotExist", getErr)
	}
	if m.sessionMirrorFailed {
		t.Fatal("v6: sessionMirrorFailed = true after a semantic refusal")
	}
	if got := m.syncedImportRefusals.Load(); got != 1 {
		t.Fatalf("v6: syncedImportRefusals = %d, want 1", got)
	}
}

// rustRefusalPrefixRe extracts the helper's SYNCED_IMPORT_REFUSED_PREFIX literal.
var rustRefusalPrefixRe = regexp.MustCompile(
	`(?m)^pub const SYNCED_IMPORT_REFUSED_PREFIX:\s*&str\s*=\s*"([^"]*)"\s*;`)

// TestSyncedImportRefusedPrefixMatchesTheHelper6785 asserts the AGREEMENT
// between the Go classifier's token and the Rust constant the helper actually
// emits, by READING the Rust source rather than pinning either side to a
// literal.
//
// Pinning would encode which side is trusted, and here neither is: if the Rust
// constant is renamed and Go keeps a hard-coded string, every semantic refusal
// silently reclassifies as a transport failure — which sets sessionMirrorFailed
// and permanently disarms HA takeover on a healthy standby. That failure is
// worse than the bug #6785 fixes, and it is invisible: both sides compile, all
// unit tests on either side pass, and the only symptom is a standby that never
// takes over.
func TestSyncedImportRefusedPrefixMatchesTheHelper6785(t *testing.T) {
	src, err := os.ReadFile("../../../userspace-dp/src/afxdp/ha/session_import.rs")
	if err != nil {
		t.Fatalf("read the helper source that owns the refusal token: %v", err)
	}
	// Strip line comments first: the doc comment above the constant quotes the
	// token, and a gate satisfiable by its own documentation proves nothing.
	var stripped strings.Builder
	for _, line := range strings.Split(string(src), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "//") {
			stripped.WriteString("\n")
			continue
		}
		stripped.WriteString(line)
		stripped.WriteString("\n")
	}
	match := rustRefusalPrefixRe.FindStringSubmatch(stripped.String())
	if match == nil {
		t.Fatal("SYNCED_IMPORT_REFUSED_PREFIX not found in the helper source — " +
			"it was renamed or removed, so Go can no longer tell a semantic " +
			"refusal from a transport failure and every refusal would disarm " +
			"HA takeover (#6785)")
	}
	if match[1] != syncedImportRefusedPrefix {
		t.Fatalf("refusal token disagreement: helper emits %q, Go matches %q — "+
			"every refusal would be misclassified as a transport failure",
			match[1], syncedImportRefusedPrefix)
	}
}

// TestHelperErrorClassification6785 binds the discriminator itself, at the
// transport, with NO BPF maps involved.
//
// This cell exists because the two rollback cells above need real BPF session
// maps and SKIP without CAP_BPF — a guard that skips is indistinguishable from a
// guard that passes, and the classification is the decision every other
// behaviour in #6785 hangs off: get it wrong in the permissive direction and a
// real mirror failure stops gating HA takeover; get it wrong in the strict
// direction and every capacity refusal permanently disarms a healthy standby.
//
// The table's middle row is the load-bearing one: an `ok=false` answer whose
// message merely CONTAINS the token, without starting with it, must NOT
// classify. A `strings.Contains` implementation passes the other two rows.
func TestHelperErrorClassification6785(t *testing.T) {
	cases := []struct {
		name        string
		helperError string
		wantRefusal bool
	}{
		{"refusal-capacity", syncedImportRefusedPrefix + "capacity", true},
		{"refusal-stale", syncedImportRefusedPrefix + "stale-generation", true},
		{"refusal-reserve", syncedImportRefusedPrefix + "reserve", true},
		{"token-not-at-the-start", "write failed while handling " + syncedImportRefusedPrefix + "capacity", false},
		{"plain-helper-error", "session table write failed", false},
		{"unknown-operation", "unknown session sync operation frobnicate", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			sock := filepath.Join(dir, "userspace-dp-sessions.sock")
			ln, err := net.Listen("unix", sock)
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			defer ln.Close()
			go func() {
				for {
					conn, aerr := ln.Accept()
					if aerr != nil {
						return
					}
					go func() {
						defer conn.Close()
						var req ControlRequest
						_ = json.NewDecoder(conn).Decode(&req)
						_ = json.NewEncoder(conn).Encode(ControlResponse{
							OK: false, Error: tc.helperError,
						})
					}()
				}
			}()

			m := New()
			m.proc = &exec.Cmd{Process: &os.Process{Pid: 1}}
			m.cfg.ControlSocket = filepath.Join(dir, "control.sock")

			err = m.requestSessionSync(ControlRequest{
				Type:           "sync_session",
				SuppressStatus: true,
				SessionSync:    &SessionSyncRequest{Operation: "upsert"},
			})
			if err == nil {
				t.Fatal("requestSessionSync() = nil on an ok=false answer")
			}
			if got := errors.Is(err, dataplane.ErrSyncedImportRefused); got != tc.wantRefusal {
				t.Fatalf("classified as a semantic refusal = %v, want %v (err %v)",
					got, tc.wantRefusal, err)
			}
			// A refusal must keep its reason readable; dropping it would leave
			// an operator unable to tell a capacity problem from a stale peer.
			if tc.wantRefusal {
				reason := strings.TrimPrefix(tc.helperError, syncedImportRefusedPrefix)
				if !strings.Contains(err.Error(), reason) {
					t.Fatalf("refusal error %q lost the reason %q", err, reason)
				}
			}
		})
	}
}

// TestUnreachableHelperIsNotARefusal6785 is the transport half of the same
// discriminator: with nothing listening, the round trip must classify as
// errSessionHelperUnreachable and NOT as a semantic refusal. Without this the
// classifier could return the refusal sentinel for every failure and the two
// rollback cells above — which skip without CAP_BPF — would be the only thing
// standing between that and a standby that never gates takeover.
func TestUnreachableHelperIsNotARefusal6785(t *testing.T) {
	dir := t.TempDir()
	m := New()
	m.proc = &exec.Cmd{Process: &os.Process{Pid: 1}}
	m.cfg.ControlSocket = filepath.Join(dir, "control.sock")

	err := m.requestSessionSync(ControlRequest{
		Type:           "sync_session",
		SuppressStatus: true,
		SessionSync:    &SessionSyncRequest{Operation: "upsert"},
	})
	if err == nil {
		t.Fatal("requestSessionSync() = nil with no helper listening")
	}
	if errors.Is(err, dataplane.ErrSyncedImportRefused) {
		t.Fatalf("an UNREACHABLE helper classified as a semantic refusal: %v — "+
			"a down helper would stop gating HA takeover-readiness (#5247)", err)
	}
	if !errors.Is(err, errSessionHelperUnreachable) {
		t.Fatalf("transport failure lost its errSessionHelperUnreachable "+
			"classification: %v", err)
	}
}
