package authz

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

// socketscan.go collapses concurrent socket-table lookups into a single read
// (#5561).
//
// # Why this exists
//
// The authorization gate resolves a peer identity once per accepted CONNECTION,
// started at accept so the caller cannot choose the moment (see
// pkg/api/authz.go connContext). Reading /proc/net/tcp{,6} is not proportional
// to the number of rows: the kernel walks its entire TCP hash table, whose size
// is derived from RAM. Measured on an idle box carrying 11 and 39 rows, a single
// raw read costs 4.3 ms and 10.1 ms respectively, and a full lookup 6-9 ms.
//
// Per-connection and unbounded, that is a denial of service available to any
// local process with no credentials at all — a connect loop at ~110 conn/s
// saturates a core inside the daemon. That is the same unprivileged local
// population #5561 exists to constrain, so paying 6-9 ms of daemon CPU per
// unauthenticated connection is not an acceptable price for the identity.
//
// # The fix, and why it keeps the security property
//
// Lookups are single-flighted. One goroutine reads the tables; every waiter
// registered before that read STARTED is answered from it. A waiter that
// arrives while a read is in progress is served by the NEXT read.
//
// The property that matters is preserved exactly: a connection accepted at T is
// only ever answered from a read that STARTED at or after T. The batch a request
// joins is taken under the same lock the request was appended under, and the
// read begins after that swap — so no request is ever answered from a table
// observation older than its own arrival. The caller still cannot influence when
// the read happens, which is the whole point of resolving at accept.
//
// What changes is only the cost: N connections arriving together cost ONE read
// instead of N.

// socketScans counts completed table reads. It exists so a test can assert the
// COST property (N connections must not cost N reads) rather than merely that
// lookups run concurrently — the distinction that made the previous accept-loop
// guard narrower than the claim it protected.
var socketScans atomic.Uint64

// SocketScansForTest returns the number of socket-table reads performed so far.
// Test-only; dep-free, so no test-only import leaks into the production binary.
func SocketScansForTest() uint64 { return socketScans.Load() }

// scanKey identifies one row to look for in one table file.
type scanKey struct {
	path   string
	local  string
	remote string
}

// socketQuery is one caller's pending lookup plus the result accumulated for it
// as the shared read progresses.
type socketQuery struct {
	keys []scanKey

	uid   uint32
	state uint64
	found bool
	// filesRead counts how many of this query's target files were actually
	// read. Zero means we looked nowhere, which must not be reported as "no
	// row found" — see findPeerSocket.
	filesRead int

	res chan socketResult
}

type socketResult struct {
	uid   uint32
	state uint64
	found bool
	err   error
}

// socketBatcher is the single-flight scheduler.
type socketBatcher struct {
	mu      sync.Mutex
	pending []*socketQuery
	running bool
}

var batcher socketBatcher

// lookup enqueues q and blocks until a read that started after the enqueue has
// answered it.
func (b *socketBatcher) lookup(q *socketQuery) socketResult {
	b.mu.Lock()
	b.pending = append(b.pending, q)
	if !b.running {
		b.running = true
		go b.run()
	}
	b.mu.Unlock()
	return <-q.res
}

// run drains batches until none are pending. Each iteration takes the whole
// pending set, then reads — so every query in the batch was enqueued strictly
// before that read began.
func (b *socketBatcher) run() {
	for {
		b.mu.Lock()
		batch := b.pending
		b.pending = nil
		if len(batch) == 0 {
			b.running = false
			b.mu.Unlock()
			return
		}
		b.mu.Unlock()

		scanBatch(batch)
		socketScans.Add(1)

		for _, q := range batch {
			var err error
			if q.filesRead == 0 {
				// Every candidate table was absent or unreadable. "No row
				// found" would be a claim about the caller drawn from having
				// looked nowhere — and under LookupPeer's precedence that
				// claim hands the caller the credential path.
				err = fmt.Errorf("no socket table could be read")
			}
			q.res <- socketResult{uid: q.uid, state: q.state, found: q.found, err: err}
		}
	}
}

// scanBatch reads each distinct table file ONCE and fills in every query that
// was waiting on a row from it.
func scanBatch(batch []*socketQuery) {
	// path -> local -> remote -> queries. Two levels so the per-row test is a
	// map lookup on an existing string rather than a concatenation.
	wants := map[string]map[string]map[string][]*socketQuery{}
	for _, q := range batch {
		for _, k := range q.keys {
			byLocal := wants[k.path]
			if byLocal == nil {
				byLocal = map[string]map[string][]*socketQuery{}
				wants[k.path] = byLocal
			}
			byRemote := byLocal[k.local]
			if byRemote == nil {
				byRemote = map[string][]*socketQuery{}
				byLocal[k.local] = byRemote
			}
			byRemote[k.remote] = append(byRemote[k.remote], q)
		}
	}

	for path, byLocal := range wants {
		if !scanTableInto(path, byLocal) {
			continue // absent or unreadable; filesRead stays unincremented
		}
		for _, byRemote := range byLocal {
			for _, qs := range byRemote {
				for _, q := range qs {
					q.filesRead++
				}
			}
		}
	}
}

// scanTableInto reads one /proc/net/tcp{,6} file, recording matches onto the
// queries waiting for them. It reports whether the file was read at all.
func scanTableInto(path string, byLocal map[string]map[string][]*socketQuery) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		// Columns: sl local rem st tx:rx tr:when retrnsmt uid timeout inode ...
		fields := strings.Fields(sc.Text())
		if len(fields) < 8 {
			continue // the header row and any short/garbled line
		}
		byRemote, ok := byLocal[normalizeHexColumn(fields[1])]
		if !ok {
			continue
		}
		qs, ok := byRemote[normalizeHexColumn(fields[2])]
		if !ok {
			continue
		}
		st, perr := strconv.ParseUint(fields[3], 16, 8)
		if perr != nil {
			continue
		}
		uid, perr := strconv.ParseUint(fields[7], 10, 32)
		if perr != nil {
			continue
		}
		for _, q := range qs {
			if q.found && q.state == tcpEstablished {
				continue // already have the live socket
			}
			if st == tcpEstablished {
				q.uid, q.state, q.found = uint32(uid), st, true
				continue
			}
			// A non-established match still proves the caller is LOCAL, but its
			// UID is deliberately NOT carried out as an identity: the kernel
			// reports 0 for a timewait mini-socket.
			q.uid, q.state, q.found = 0, st, true
		}
	}
	// A read error mid-file (including bufio.Scanner's token-too-long) leaves
	// whatever matched before it. Report the file as read only if it completed,
	// so a truncated scan cannot be mistaken for "no row exists".
	return sc.Err() == nil
}

// normalizeHexColumn upper-cases a /proc address column. The kernel already
// emits upper-case hex, so this is insurance rather than a hot-path cost:
// strings.ToUpper returns its argument unchanged (no allocation) when there is
// nothing to fold.
func normalizeHexColumn(s string) string { return strings.ToUpper(s) }
