package flowexport

import (
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// collectorConn is one UDP connection to a single collector plus the
// per-collector write-health state surfaced through status / metrics /
// the show command (#2464). Flow export is forensics/compliance data;
// a collector going unreachable was previously invisible (every failed
// Write was debug-logged and dropped), so the exporter kept counting
// "exported" while the operator got no warning. The counters here make
// that loss observable.
//
// addr is the collector destination ("host:port") used as the label /
// identity in every surface. The atomic counters (attempts / failures)
// are bumped lock-free from the export-flush goroutine; the mutex guards
// the string/time fields and the healthy edge-detect flag so a concurrent
// status reader gets a consistent snapshot (run -race).
type collectorConn struct {
	conn net.Conn
	addr string

	attempts atomic.Uint64
	failures atomic.Uint64

	mu              sync.Mutex
	lastError       string
	lastErrorTime   time.Time
	lastFailureTime time.Time
	lastSuccessTime time.Time
	// healthy tracks the last observed reachability so writeAll logs only
	// on the unhealthy<->healthy EDGE, not on every failed (or recovered)
	// write. A collector starts healthy (optimistic): the first failure is
	// the transition that warns. consecFail counts consecutive failures so
	// the recovery edge is unambiguous.
	healthy    bool
	consecFail uint64
}

// ExporterCollectorHealth is one collector's write-health snapshot
// annotated with the protocol family ("netflow-v9" / "ipfix"), the
// sampling instance, and the template group it belongs to (#2464). It is
// the cross-package shape surfaced through the daemon to the REST status,
// gRPC show, and Prometheus collector. It lives here (not pkg/daemon) so
// pkg/api and pkg/grpcapi — which must not import pkg/daemon — can name
// the return type of the injected accessor callback.
type ExporterCollectorHealth struct {
	Protocol string `json:"protocol"`
	Instance string `json:"instance"`
	Template string `json:"template"`
	CollectorHealth
}

// CollectorHealth is an immutable snapshot of one collector's write-health
// state, returned by collectorConns.health() and surfaced through the
// status response, Prometheus metrics, and the show command (#2464).
type CollectorHealth struct {
	Address         string    `json:"address"`
	WriteAttempts   uint64    `json:"write_attempts"`
	WriteFailures   uint64    `json:"write_failures"`
	Healthy         bool      `json:"healthy"`
	LastError       string    `json:"last_error,omitempty"`
	LastErrorTime   time.Time `json:"last_error_time,omitempty"`
	LastFailureTime time.Time `json:"last_failure_time,omitempty"`
	LastSuccessTime time.Time `json:"last_success_time,omitempty"`
}

// collectorConns owns the set of UDP connections to the configured
// collectors. Both the NetFlow v9 and IPFIX exporters share this
// connection-management code: the dial loop, the per-packet fan-out
// write, and teardown are identical between the two protocols.
type collectorConns struct {
	conns []*collectorConn
}

// dialUDP and resolveUDPAddr are indirection seams so tests can inject
// dial/resolve failures and observe connection teardown. They default to
// the net package and are only overridden by tests. dialUDP returns a
// net.Conn (not *net.UDPConn) so tests can substitute a recording fake
// and assert that connections opened before a mid-loop failure are
// closed.
var (
	dialUDP = func(network string, laddr, raddr *net.UDPAddr) (net.Conn, error) {
		return net.DialUDP(network, laddr, raddr)
	}
	resolveUDPAddr = net.ResolveUDPAddr
)

// dialCollectors opens a UDP connection to every collector in the list.
// When a collector specifies a SourceAddress the local bind address is
// pinned; otherwise the OS selects it. On any resolve or dial error all
// already opened connections are closed and the error is returned, so a
// partial failure mid-loop never leaks the connections opened before it.
func dialCollectors(collectors []CollectorConfig) (*collectorConns, error) {
	cc := &collectorConns{}
	// fail closes every connection opened so far and returns err as-is
	// (call sites wrap err with collector context). Callers
	// must return its result without retaining cc, so no descriptor opened
	// in this loop survives an error return.
	fail := func(err error) (*collectorConns, error) {
		cc.close()
		return nil, err
	}
	for _, c := range collectors {
		var conn net.Conn
		var err error
		if c.SourceAddress != "" {
			// A misconfigured SourceAddress must be surfaced, not
			// silently dropped to a nil local bind (which would let the
			// OS pick an arbitrary source and mask the misconfiguration).
			// JoinHostPort brackets an IPv6 source-address literal so
			// resolveUDPAddr can parse it; "addr:0" leaves an IPv6
			// address unbracketed and unparseable (sibling of #2183).
			laddr, err2 := resolveUDPAddr("udp", net.JoinHostPort(c.SourceAddress, "0"))
			if err2 != nil {
				return fail(fmt.Errorf("resolve collector %s source-address %s: %w", c.Address, c.SourceAddress, err2))
			}
			raddr, err2 := resolveUDPAddr("udp", c.Address)
			if err2 != nil {
				return fail(fmt.Errorf("resolve collector %s: %w", c.Address, err2))
			}
			conn, err = dialUDP("udp", laddr, raddr)
		} else {
			conn, err = net.Dial("udp", c.Address)
		}
		if err != nil {
			return fail(fmt.Errorf("dial collector %s: %w", c.Address, err))
		}
		// A collector starts healthy (optimistic) so the FIRST failed write
		// is the unhealthy edge that warns (#2464).
		cc.conns = append(cc.conns, &collectorConn{conn: conn, addr: c.Address, healthy: true})
	}
	return cc, nil
}

// writeAll transmits pkt to every collector connection and records the
// per-collector write-health (#2464). A failure to one collector does
// not stop delivery to the others (the export DATA path is unchanged —
// writes are still attempted to all collectors and failures are still
// non-fatal). The change is observability: each write bumps the
// attempt counter, a success refreshes LastSuccessTime, and a failure
// records LastError/LastErrorTime + the failure counter.
//
// Logging is RATE-LIMITED to the unhealthy<->healthy EDGE, not every
// write: writeAll runs once per export flush (the v9/IPFIX batch ticker
// fires every 100ms) plus once per template refresh, so a per-write
// slog.Warn would flood the journal for an unreachable collector. The
// project logging rules forbid Warn/Info inside per-tick loops; a
// transition log fires once when a healthy collector starts failing and
// once when it recovers. errMsg disambiguates the protocol/path
// (template vs data) in the debug line kept for deep tracing.
func (cc *collectorConns) writeAll(pkt []byte, errMsg string) {
	for _, c := range cc.conns {
		_, err := c.conn.Write(pkt)
		c.attempts.Add(1)
		now := time.Now()
		if err != nil {
			c.failures.Add(1)
			c.mu.Lock()
			c.lastError = err.Error()
			c.lastErrorTime = now
			c.lastFailureTime = now
			c.consecFail++
			wasHealthy := c.healthy
			c.healthy = false
			c.mu.Unlock()
			// Keep the per-write debug line for deep tracing; emit a single
			// Warn only on the healthy->unhealthy edge.
			slog.Debug(errMsg, "collector", c.addr, "err", err)
			if wasHealthy {
				slog.Warn("flow-export collector unreachable",
					"collector", c.addr, "err", err)
			}
			continue
		}
		c.mu.Lock()
		c.lastSuccessTime = now
		wasUnhealthy := !c.healthy
		c.healthy = true
		c.consecFail = 0
		c.mu.Unlock()
		if wasUnhealthy {
			slog.Info("flow-export collector recovered", "collector", c.addr)
		}
	}
}

// health returns an immutable snapshot of every collector's write-health
// for the status / metrics / show surfaces (#2464). Safe to call
// concurrently with writeAll.
func (cc *collectorConns) health() []CollectorHealth {
	if cc == nil {
		return nil
	}
	out := make([]CollectorHealth, 0, len(cc.conns))
	for _, c := range cc.conns {
		c.mu.Lock()
		out = append(out, CollectorHealth{
			Address:         c.addr,
			WriteAttempts:   c.attempts.Load(),
			WriteFailures:   c.failures.Load(),
			Healthy:         c.healthy,
			LastError:       c.lastError,
			LastErrorTime:   c.lastErrorTime,
			LastFailureTime: c.lastFailureTime,
			LastSuccessTime: c.lastSuccessTime,
		})
		c.mu.Unlock()
	}
	return out
}

// close shuts down all collector connections.
func (cc *collectorConns) close() {
	for _, c := range cc.conns {
		c.conn.Close()
	}
}

// flowBatch accumulates flow records pending export, split by address
// family. The export loop drains it on a periodic ticker (and on
// shutdown) and hands each non-empty slice to the protocol-specific
// send path. The split is by family, not by zone.
type flowBatch struct {
	mu sync.Mutex
	v4 []FlowRecord
	v6 []FlowRecord
}

// add queues a record into the appropriate per-family batch.
func (b *flowBatch) add(fr FlowRecord) {
	b.mu.Lock()
	if fr.IsIPv6 {
		b.v6 = append(b.v6, fr)
	} else {
		b.v4 = append(b.v4, fr)
	}
	b.mu.Unlock()
}

// drain atomically removes and returns the accumulated v4 and v6
// records, resetting both batches to empty.
func (b *flowBatch) drain() (v4, v6 []FlowRecord) {
	b.mu.Lock()
	v4 = b.v4
	v6 = b.v6
	b.v4 = nil
	b.v6 = nil
	b.mu.Unlock()
	return v4, v6
}
