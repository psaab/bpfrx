package flowexport

import (
	"fmt"
	"log/slog"
	"net"
	"sync"
)

// collectorConns owns the set of UDP connections to the configured
// collectors. Both the NetFlow v9 and IPFIX exporters share this
// connection-management code: the dial loop, the per-packet fan-out
// write, and teardown are identical between the two protocols.
type collectorConns struct {
	conns []net.Conn
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
		cc.conns = append(cc.conns, conn)
	}
	return cc, nil
}

// writeAll transmits pkt to every collector connection. Write failures
// are logged at debug level using errMsg; a failure to one collector
// does not stop delivery to the others.
func (cc *collectorConns) writeAll(pkt []byte, errMsg string) {
	for _, c := range cc.conns {
		if _, err := c.Write(pkt); err != nil {
			slog.Debug(errMsg, "err", err)
		}
	}
}

// close shuts down all collector connections.
func (cc *collectorConns) close() {
	for _, c := range cc.conns {
		c.Close()
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
