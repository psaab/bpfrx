package grpcapi

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"log/slog"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// Fabric gRPC listener authentication (#4107 F1).
//
// The #4122 allowlist already fail-closes the network-exposed fabric listener
// to the handful of read/monitor/failover RPCs the cluster peer legitimately
// proxies. But the allowlist alone is an authorization gate, NOT authentication:
// ANY host on the shared control segment could still invoke those RPCs
// (GetSessions, ClearSessions, MonitorInterface, cross-node cluster-failover)
// with no credential — flushing sessions or driving RG ownership from an
// unauthenticated on-segment attacker.
//
// This layer authenticates the caller with the SAME control-link PSK that #4326
// applies to the heartbeat (cluster.Manager.ControlLinkAuthKey, set via
// `set chassis cluster authentication-key <secret>`). The token is a
// time-windowed HMAC bearer credential carried in gRPC metadata; the fabric
// listener verifies it before the allowlist interceptor runs. The loopback
// (127.0.0.1) listener is UNCHANGED — local callers are trusted.
//
// Dual-accept (rolling upgrade / key rollout), mirroring
// cluster.heartbeatAuthDecision:
//   - No local key configured: accept everything (this node cannot verify; it
//     may be the not-yet-keyed side of a key rollout, or a standalone/legacy
//     node). Standalone nodes never start a fabric listener anyway.
//   - Local key + valid token: accept, and record that the peer holds the key.
//   - Local key + present-but-invalid token: reject (Unauthenticated).
//   - Local key + no token + peer never authenticated: accept (grace window
//     while the config-synced key propagates to the peer).
//   - Local key + no token + peer HAS authenticated: reject — a downgrade to
//     tokenless once both nodes are keyed is an attack.
//
// Replay: the token is HMAC(PSK, window) where window = unix_time /
// fabricAuthWindowSeconds. A captured token is therefore replayable only within
// its window (plus one window of clock-skew tolerance on each side) — a bounded
// residual that trades the statelessness of a per-RPC nonce (which gRPC's
// connectionless interceptor model cannot cheaply track across the peer's many
// short-lived proxy dials) for a small replay horizon. mTLS with per-node certs
// would remove the horizon entirely and is the deferred stronger posture
// (#4047 convergence); this PSK layer closes the "no auth at all" HIGH hole
// with zero cert-lifecycle machinery, reusing the key the operator already
// provisions for the heartbeat.

const (
	// fabricAuthMetadataKey is the gRPC metadata header carrying the hex token.
	// Lowercase per the gRPC metadata-key contract.
	fabricAuthMetadataKey = "xpf-fabric-auth"

	// fabricAuthWindowSeconds is the token validity window. The verifier also
	// accepts the adjacent windows (±1), so a token is honored for up to
	// ~2×window across a clock-skew boundary. Small enough to bound replay,
	// large enough to tolerate NTP skew between cluster nodes.
	fabricAuthWindowSeconds = 30

	// fabricAuthDomain is a domain-separation prefix so a fabric token can never
	// be confused with (or substituted for) the heartbeat HMAC, which signs a
	// different byte layout under the same key.
	fabricAuthDomain = "xpf-fabric-grpc-auth\x00"
)

// fabricAuthWindow returns the token window index for a wall-clock time.
func fabricAuthWindow(t time.Time) int64 {
	return t.Unix() / fabricAuthWindowSeconds
}

// computeFabricAuthToken returns HMAC-SHA256(key, domain || window) — the raw
// 32-byte digest for one window. key must be non-empty (the callers guard).
func computeFabricAuthToken(key []byte, window int64) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(fabricAuthDomain))
	var wb [8]byte
	binary.LittleEndian.PutUint64(wb[:], uint64(window))
	mac.Write(wb[:])
	return mac.Sum(nil)
}

// fabricAuthTokenHex returns the hex-encoded current-window token for a key, or
// "" when no key is configured (a not-yet-keyed peer sends no token — legacy).
func fabricAuthTokenHex(key []byte, t time.Time) string {
	if len(key) == 0 {
		return ""
	}
	return hex.EncodeToString(computeFabricAuthToken(key, fabricAuthWindow(t)))
}

// verifyFabricAuthToken reports whether tokenHex is a valid token for key in the
// current or an adjacent window. The digest comparison is constant-time
// (hmac.Equal). Returns false for an empty key, an empty/malformed token, or a
// digest that matches no accepted window.
func verifyFabricAuthToken(key []byte, tokenHex string) bool {
	if len(key) == 0 || tokenHex == "" {
		return false
	}
	got, err := hex.DecodeString(tokenHex)
	if err != nil || len(got) != sha256.Size {
		return false
	}
	now := fabricAuthWindow(time.Now())
	// Accept the current window plus one on each side (clock skew / boundary).
	for _, w := range []int64{now, now - 1, now + 1} {
		if hmac.Equal(got, computeFabricAuthToken(key, w)) {
			return true
		}
	}
	return false
}

// fabricAuthTokenFromMetadata extracts the token header from an inbound context.
// present is false when the caller sent no token (a not-yet-keyed peer).
func fabricAuthTokenFromMetadata(ctx context.Context) (token string, present bool) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", false
	}
	vals := md.Get(fabricAuthMetadataKey)
	if len(vals) == 0 || vals[0] == "" {
		return "", false
	}
	return vals[0], true
}

// fabricAuthDecision applies the #4107 dual-accept policy for one inbound fabric
// RPC and returns whether to accept it (and, when rejected, a short reason for
// logging — never the token or key). It mirrors cluster.heartbeatAuthDecision so
// the two control surfaces share one auth posture.
//
//	keyConfigured — the local ControlLinkAuthKey is set (we can verify).
//	present       — the caller sent an auth token.
//	tokenOK       — the token verified (only meaningful when present).
//	peerAuthSeen  — we have previously accepted a valid token on the fabric
//	                (sticky: proves the peer holds the key, so a subsequent
//	                tokenless call is a downgrade attack, not a rollout).
func fabricAuthDecision(keyConfigured, present, tokenOK, peerAuthSeen bool) (bool, string) {
	if !keyConfigured {
		return true, ""
	}
	if present {
		if !tokenOK {
			return false, "invalid auth token"
		}
		return true, ""
	}
	if peerAuthSeen {
		return false, "missing auth token (enforced: peer previously authenticated)"
	}
	return true, ""
}

// fabricAuthKey returns the control-link PSK for the fabric listener, or nil
// when none is configured. fabricAuthKeyFn is a test seam; production reads the
// live key from the cluster manager (nil when standalone).
func (s *Server) fabricAuthKey() []byte {
	if s.fabricAuthKeyFn != nil {
		return s.fabricAuthKeyFn()
	}
	if s.cluster != nil {
		return s.cluster.ControlLinkAuthKey()
	}
	return nil
}

// checkFabricAuth authenticates one inbound fabric RPC by its metadata token.
// Returns a codes.Unauthenticated status when the call is rejected; nil to
// admit it. The key is never logged.
func (s *Server) checkFabricAuth(ctx context.Context, method string) error {
	key := s.fabricAuthKey()
	token, present := fabricAuthTokenFromMetadata(ctx)
	tokenOK := present && verifyFabricAuthToken(key, token)
	if tokenOK {
		// Sticky: once the peer proves it holds the key, a later tokenless call
		// is a downgrade attack, not a rollout gap.
		s.fabricPeerAuthSeen.Store(true)
	}
	accept, reason := fabricAuthDecision(len(key) > 0, present, tokenOK, s.fabricPeerAuthSeen.Load())
	if !accept {
		slog.Warn("fabric gRPC listener rejected call: authentication failed", "method", method, "reason", reason)
		return status.Errorf(codes.Unauthenticated, "fabric RPC authentication failed: %s", reason)
	}
	return nil
}

// fabricAuthUnaryInterceptor authenticates unary RPCs on the fabric listener
// with the control-link PSK (#4107). It runs BEFORE the #4122 allowlist
// interceptor, so an unauthenticated caller is rejected before authorization is
// even consulted. The loopback listener does NOT install this interceptor.
func (s *Server) fabricAuthUnaryInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	if err := s.checkFabricAuth(ctx, info.FullMethod); err != nil {
		return nil, err
	}
	return handler(ctx, req)
}

// fabricAuthStreamInterceptor authenticates streaming RPCs on the fabric
// listener with the control-link PSK (#4107), before the #4122 allowlist.
func (s *Server) fabricAuthStreamInterceptor(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	if err := s.checkFabricAuth(ss.Context(), info.FullMethod); err != nil {
		return err
	}
	return handler(srv, ss)
}

// fabricAuthCreds is the client-side gRPC per-RPC credential that attaches the
// control-link PSK token to every RPC the local node dials on its peer's fabric
// listener (dialPeer). keyFn is read fresh per RPC so the token rotates with the
// window and picks up a live key change; it returns no metadata when no key is
// configured (a not-yet-keyed node dials tokenless — dual-accept). It reports
// RequireTransportSecurity()==false so it may ride the fabric's insecure
// transport (the fabric link is a private cluster segment, not a public TLS
// channel).
type fabricAuthCreds struct {
	keyFn func() []byte
}

func (c fabricAuthCreds) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	token := fabricAuthTokenHex(c.keyFn(), time.Now())
	if token == "" {
		return nil, nil
	}
	return map[string]string{fabricAuthMetadataKey: token}, nil
}

func (c fabricAuthCreds) RequireTransportSecurity() bool { return false }
