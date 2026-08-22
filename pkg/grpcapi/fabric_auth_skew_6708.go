package grpcapi

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"strconv"
	"sync/atomic"
	"time"
)

// #6708: turn a wall-clock skew that kills every fabric RPC from a silent,
// mislabelled failure into a measured, named one.
//
// The fabric token is HMAC(PSK, unix_time / 30) and the verifier accepts the
// current window ±1. Beyond roughly a minute of skew every inbound fabric RPC
// rejects with "invalid auth token" — permanently, because skew does not
// self-correct without NTP. Measured on the loss userspace cluster: 141s of
// skew, NTPSynchronized=no on both nodes, every cross-node RPC dead. The
// symptom the operator saw named SESSIONS ("fw0 has only 1 established
// sessions"); the cause was the clock, and finding that cost an investigation.
//
// WHAT THIS DOES NOT DO, and why. #6708's first suggested fix is to widen
// acceptance to ±N windows. That is not implemented here: the accept band is
// the replay horizon. A captured token is replayable for as long as the
// verifier will honour it, and the allowlisted fabric RPCs include
// ClearSessions and cross-node redundancy-group failover, so widening to cover
// the measured 141s would multiply the horizon of a real attack to buy
// tolerance for an operational fault that the operator can see and fix in
// seconds once it is NAMED. The accept band is therefore unchanged at ±1 and
// this file only adds diagnosis. Making fabric RPC genuinely skew-independent
// (a monotonic window floor per peer, or a peer-clock offset carried over the
// authenticated heartbeat) is a design change with its own HA gate, tracked
// separately.
//
// WHY THE MEASUREMENT IS TRUSTWORTHY. The scan below only reports a skew when
// the presented token matches a window under an ACCEPTED KEY. Only a key holder
// can produce that, so the number is an authenticated statement, not something
// an on-segment attacker can plant in an operator's status output.

const (
	// fabricAuthSkewScanWindows bounds the diagnostic scan to ±2 hours
	// (240 × 30s) on each side of the local window.
	//
	// Two hours rather than "as far as it takes": the scan exists to name a
	// drifting clock, and a peer more than two hours out has a problem no
	// message from this node is going to characterise better than "the clock is
	// wrong". A DST-sized or timezone-sized error lands inside it.
	fabricAuthSkewScanWindows = 240

	// fabricAuthSkewScanInterval throttles the scan.
	//
	// The scan costs up to (2×240+1) HMAC-SHA256 computations per accepted key,
	// and it runs on the REJECT path — which is exactly the path an attacker
	// controls by sending garbage. Unthrottled that is a ~500× amplification on
	// junk input. Throttling is free here because the scan is a diagnostic, not
	// an auth decision: a drifting clock does not stop drifting in five
	// seconds, and the first scan in any window already produces the number.
	fabricAuthSkewScanInterval = 5 * time.Second
)

// fabricSkewState is the measured peer clock skew, guarded by atomics because
// it is written from gRPC interceptor goroutines and read by a show surface.
type fabricSkewState struct {
	// lastScanNanos is the throttle: the wall time of the most recent scan,
	// attempted or not.
	lastScanNanos atomic.Int64
	// skewSeconds is the peer's clock minus ours, in seconds, positive when the
	// peer is AHEAD. Meaningful only when atNanos is non-zero.
	skewSeconds atomic.Int64
	// atNanos is when skewSeconds was measured; zero means never.
	atNanos atomic.Int64
	// reported latches the one-shot operator warning so a drifting peer that
	// retries every RPC does not flood the log (a transition, not a per-call
	// event, per the project logging rules).
	reported atomic.Bool
}

// measureFabricAuthSkew reports the sender's clock offset in seconds, positive
// when the sender is AHEAD of now, for a token that verified under some key at
// some window inside the scan band.
//
// ok is false when no window matches, which is the honest answer for a token
// that is simply forged or signed with a key this node does not accept — the
// caller must NOT present a skew in that case, or a bad-PSK failure would be
// mislabelled as a clock problem, which is the same class of mistake #6708 is
// about.
func measureFabricAuthSkew(keys [][]byte, tokenHex string, now time.Time) (int64, bool) {
	if len(keys) == 0 || tokenHex == "" {
		return 0, false
	}
	got, err := hex.DecodeString(tokenHex)
	if err != nil || len(got) != sha256.Size {
		return 0, false
	}
	base := fabricAuthWindow(now)
	for _, key := range keys {
		if len(key) == 0 {
			continue
		}
		// Nearest-first: the smallest offset that explains the token is the
		// right one to report. Scanning outward also means a peer just past the
		// accept band costs a handful of HMACs, not the whole band.
		for delta := int64(1); delta <= fabricAuthSkewScanWindows; delta++ {
			for _, w := range [2]int64{base + delta, base - delta} {
				if hmac.Equal(got, computeFabricAuthToken(key, w)) {
					return (w - base) * fabricAuthWindowSeconds, true
				}
			}
		}
	}
	return 0, false
}

// noteFabricAuthSkew runs the throttled scan for a rejected token and records
// what it finds. It returns a clause to append to the rejection reason, or ""
// when the token is not explained by clock skew.
//
// now is injected so a test does not have to move the machine's clock.
func (s *Server) noteFabricAuthSkew(keys [][]byte, tokenHex string, now time.Time) string {
	nowNanos := now.UnixNano()
	last := s.fabricSkew.lastScanNanos.Load()
	if last != 0 && nowNanos-last < int64(fabricAuthSkewScanInterval) {
		// Throttled. Reuse a recent measurement rather than reporting nothing:
		// the operator asking "why is my cross-node show empty" gets the same
		// answer whether or not their RPC happened to win the throttle.
		return s.fabricSkewClause()
	}
	s.fabricSkew.lastScanNanos.Store(nowNanos)

	skew, ok := measureFabricAuthSkew(keys, tokenHex, now)
	if !ok {
		// Not a clock problem. Clear any stale measurement so a status surface
		// does not keep asserting a skew that no longer explains anything.
		s.fabricSkew.atNanos.Store(0)
		s.fabricSkew.reported.Store(false)
		return ""
	}
	s.fabricSkew.skewSeconds.Store(skew)
	s.fabricSkew.atNanos.Store(nowNanos)
	if !s.fabricSkew.reported.Swap(true) {
		slog.Warn(
			"cluster: peer wall clock is skewed past the fabric auth window; every cross-node fabric RPC (session queries, aggregation, clear propagation, cross-node failover) will fail authentication until the clocks agree. Forwarding, VRRP and failover are NOT affected — the heartbeat authenticates independently. Synchronise NTP on both nodes.",
			"peer_skew_seconds", skew,
			"auth_window_seconds", fabricAuthWindowSeconds,
		)
	}
	return fabricSkewClause(skew)
}

// fabricSkewClause renders the reason suffix for a measured skew.
func fabricSkewClause(skew int64) string {
	dir := "ahead of"
	mag := skew
	if mag < 0 {
		dir = "behind"
		mag = -mag
	}
	return " (peer wall clock is " + strconv.FormatInt(mag, 10) + "s " + dir +
		" ours; the fabric token is time-windowed — synchronise NTP on both nodes)"
}

// fabricSkewClause returns the clause for the LAST measurement, or "" when
// there is none.
func (s *Server) fabricSkewClause() string {
	if s.fabricSkew.atNanos.Load() == 0 {
		return ""
	}
	return fabricSkewClause(s.fabricSkew.skewSeconds.Load())
}

// FabricPeerClockSkew returns the last measured peer clock skew in seconds
// (positive: peer ahead) and whether one has been measured.
func (s *Server) FabricPeerClockSkew() (int64, bool) {
	if s.fabricSkew.atNanos.Load() == 0 {
		return 0, false
	}
	return s.fabricSkew.skewSeconds.Load(), true
}

// noteFabricAuthOK clears the skew state after a token verifies normally: the
// clocks agree again, so a status surface must stop reporting a skew and the
// one-shot warning must re-arm for the next episode.
func (s *Server) noteFabricAuthOK() {
	if s.fabricSkew.atNanos.Load() != 0 {
		slog.Info("cluster: peer fabric authentication recovered; clocks are within the auth window again")
		s.fabricSkew.atNanos.Store(0)
	}
	s.fabricSkew.reported.Store(false)
}
