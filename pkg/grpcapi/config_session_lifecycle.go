package grpcapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"sync"

	"google.golang.org/grpc/stats"
)

// Config-session lifecycle bound to the TRANSPORT CONNECTION (#5849).
//
// The config lock / candidate DB is a per-CLIENT-CONNECTION resource: a client
// enters configure mode, stages edits into the candidate, then commits or exits
// — all over one long-lived gRPC connection. Before #5849 the auto-release was
// driven by a UNARY interceptor that, after every RPC, called
// ExitConfigureSession when `ctx.Err() != nil`. That is wrong two ways:
//
//   - PER-RPC cancellation (a client Ctrl-C'ing one unrelated read, a request
//     deadline expiring) is NOT a disconnect, yet it DESTROYED the connection's
//     candidate and released its lock — a mid-edit config wipe + lock steal.
//   - the session was keyed by the peer ADDRESS (`Addr.String()`), which is
//     reused across connections: a later connection reusing a freed
//     address/port could inherit or release an earlier session.
//
// This lifecycle owner fixes both: it is a gRPC `stats.Handler` that tags each
// CONNECTION (not RPC) with an unguessable random id at `TagConn`, carries that
// id on the connection context (so every RPC on the connection keys its config
// session by it via connSessionID), and releases the lock EXACTLY ONCE when the
// connection ends (`ConnEnd`) — never on per-RPC cancellation. Explicit
// ExitConfigure (immediate) and the store's bounded idle-lease reclaim
// (reclaimStaleLockLocked) remain as backstops for a connection whose ConnEnd
// notification is lost.

// connSessionKeyT is the context-key type for the per-connection config session
// (a private type so no other package can collide with the key).
type connSessionKeyT struct{}

var connSessionKey connSessionKeyT

// connSession is the per-connection config-session state carried on the gRPC
// connection context. id is an unguessable, connection-scoped session key used
// for the config lock; released guarantees the lock is auto-released at most
// once for the connection (a graceful drain and an abrupt transport fault can
// both surface a ConnEnd).
type connSession struct {
	id       string
	released sync.Once
}

// configLockStatsHandler is the gRPC stats.Handler that owns the config-session
// lifecycle (#5849). It is installed on BOTH the loopback and the fabric gRPC
// servers so every connection has the same release contract. releaseFn is a
// test seam; production leaves it nil and the handler calls
// Store.ExitConfigureSession through s.
type configLockStatsHandler struct {
	s         *Server
	releaseFn func(sessionID string) bool // test seam; nil => s.store.ExitConfigureSession
}

func (h *configLockStatsHandler) release(sessionID string) bool {
	if h.releaseFn != nil {
		return h.releaseFn(sessionID)
	}
	return h.s.store.ExitConfigureSession(sessionID)
}

// TagConn allocates an unguessable connection id and stores the per-connection
// config-session state on the connection context. Every stream/RPC on the
// connection derives its context from this one, so connSessionID reads the id
// and HandleConn(ConnEnd) reads the same connSession to release exactly once.
func (h *configLockStatsHandler) TagConn(ctx context.Context, _ *stats.ConnTagInfo) context.Context {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand.Read never fails on a healthy Linux host. In the
		// impossible degraded case, do NOT install a predictable/colliding id —
		// leave the context untagged so connSessionID falls back to the peer
		// identity (the pre-#5849 behavior) rather than sharing one id across
		// connections.
		slog.Error("config-session: failed to allocate a connection id; "+
			"falling back to peer identity for this connection", "err", err)
		return ctx
	}
	return context.WithValue(ctx, connSessionKey, &connSession{id: "conn-" + hex.EncodeToString(b[:])})
}

// HandleConn releases the connection's config lock exactly once when the
// connection ends. Per-RPC cancellation never reaches here (that is HandleRPC),
// so a canceled unary no longer tears down the session. The release is guarded
// by the per-connection sync.Once AND, defensively, by the store's holder check
// (ExitConfigureSession is a no-op unless the id is still the live holder), so a
// duplicate ConnEnd — or a ConnEnd for a connection that reused a freed session
// id — can never release a DIFFERENT connection's session.
func (h *configLockStatsHandler) HandleConn(ctx context.Context, cs stats.ConnStats) {
	if _, ok := cs.(*stats.ConnEnd); !ok {
		return
	}
	sess, ok := ctx.Value(connSessionKey).(*connSession)
	if !ok || sess == nil {
		return
	}
	sess.released.Do(func() {
		if h.release(sess.id) {
			slog.Info("auto-released config lock on connection close", "conn", sess.id)
		}
	})
}

// TagRPC returns the RPC context unchanged: the connSession set on the
// connection context by TagConn is already visible to the handler, so config
// RPCs read it via connSessionID.
func (h *configLockStatsHandler) TagRPC(ctx context.Context, _ *stats.RPCTagInfo) context.Context {
	return ctx
}

// HandleRPC is a no-op: RPC-level events (including per-RPC cancellation) must
// NOT release the config session — only ConnEnd does (#5849).
func (h *configLockStatsHandler) HandleRPC(context.Context, stats.RPCStats) {}

// connSessionID returns the config-session key for ctx: the per-CONNECTION id
// installed by configLockStatsHandler.TagConn when present, else the peer
// identity (pre-#5849 fallback for a direct in-process call / unit test / the
// impossible rand-failure path). All config RPCs and the ConnEnd release key by
// this SAME value so a session entered on a connection is only ever mutated or
// released under that connection's id.
func connSessionID(ctx context.Context) string {
	if sess, ok := ctx.Value(connSessionKey).(*connSession); ok && sess != nil && sess.id != "" {
		return sess.id
	}
	return peerSessionID(ctx)
}
