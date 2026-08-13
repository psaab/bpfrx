package authz

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
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
// What changes is the cost, stated precisely: connections that arrive before a
// read STARTS share that read, and connections that arrive during it share the
// read after it. So reads are bounded by elapsed time over read duration rather
// than by connection count — NOT "N connections cost one read", which is the
// stronger claim the batch-before-read discipline deliberately does not make.
// Measured: 60 concurrent connections cost 2 reads, and 120 cost 3.

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
	// malformed records that a row matched this query's 4-tuple but its state
	// or uid column would not parse. It is kept separate from `found` because
	// the two carry different obligations: `found` may still yield an identity,
	// `malformed` never does — but it does prove a socket exists, which is the
	// half that must not be lost. See scanTableInto.
	malformed bool
	// filesRead counts how many of this query's target files were actually
	// read. Zero means we looked nowhere, which must not be reported as "no
	// row found" — see findPeerSocket.
	filesRead int
	// filesFailed counts this query's target files that could NOT be read.
	//
	// Non-zero is a FAILURE even when filesRead is also non-zero. A caller's row
	// lives in exactly one of tcp/tcp6 and we cannot know which, so "tcp read
	// clean and empty, tcp6 unreadable" is not evidence of "no row" — it is a
	// partial observation. Reporting it as a successful omission sends a LOCAL
	// caller whose row is in the unread file to the off-box row, which is the
	// one row an api-auth credential may speak for. Only the full-failure case
	// was checked before; this is the partial one.
	filesFailed int

	res chan socketResult
}

type socketResult struct {
	uid       uint32
	state     uint64
	found     bool
	malformed bool
	err       error
}

// maxPendingLookups caps the batcher's queue.
//
// Every entry is a goroutine blocked in LookupPeer, so the queue length is
// bounded in practice by the number of connections accepted since the current
// read began — but "in practice" is not a bound, and http.Server imposes no
// connection limit of its own. Past the cap a lookup is refused outright rather
// than queued, which LookupPeer turns into a DENIAL (an errored table read
// falls back to the address classification, and a caller that could be local is
// denied). Refusing is therefore fail-closed, and it keeps a connect flood from
// growing an unbounded slice inside the daemon while it also grows the goroutine
// count.
//
// The value is deliberately far above any legitimate concurrency: the surface
// answers a handful of operator actions per second, and 4096 simultaneous
// in-flight peer lookups on it is already an attack rather than a workload.
const maxPendingLookups = 4096

// socketBatcher is the single-flight scheduler.
type socketBatcher struct {
	mu      sync.Mutex
	pending []*socketQuery
	running bool
}

var batcher socketBatcher

// errBatcherSaturated is returned when the pending queue is at maxPendingLookups.
var errBatcherSaturated = errors.New("socket-table lookup queue is saturated")

// lookup enqueues q and blocks until a read that started after the enqueue has
// answered it.
func (b *socketBatcher) lookup(q *socketQuery) socketResult {
	b.mu.Lock()
	if len(b.pending) >= maxPendingLookups {
		b.mu.Unlock()
		slog.Warn("authz: refusing peer lookup, socket-table queue saturated",
			"pending", maxPendingLookups)
		return socketResult{err: errBatcherSaturated}
	}
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
			switch {
			case q.filesFailed > 0:
				// Partial (or total) read failure: at least one candidate table
				// could not be consulted, so "no row" is unsupported. Fail closed.
				err = fmt.Errorf("%d of this peer's %d socket tables could not be read",
					q.filesFailed, q.filesFailed+q.filesRead)
			case q.filesRead == 0:
				// Every candidate table was absent or unreadable. "No row
				// found" would be a claim about the caller drawn from having
				// looked nowhere — and under LookupPeer's precedence that
				// claim hands the caller the credential path.
				err = fmt.Errorf("no socket table could be read")
			}
			q.res <- socketResult{
				uid: q.uid, state: q.state, found: q.found, malformed: q.malformed, err: err,
			}
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
		ok, absent := scanTableInto(path, byLocal)
		if absent {
			// ENOENT is not a failed observation. A kernel built without IPv6
			// has no /proc/net/tcp6 at all, so the file is not a candidate
			// table rather than one we could not read — counting it as a
			// failure would deny every caller on such a box.
			continue
		}
		for _, byRemote := range byLocal {
			for _, qs := range byRemote {
				for _, q := range qs {
					if ok {
						q.filesRead++
					} else {
						q.filesFailed++
					}
				}
			}
		}
	}
}

// scanTableInto reads one /proc/net/tcp{,6} file, recording matches onto the
// queries waiting for them.
//
// A row that MATCHES a query's 4-tuple but whose state or uid column will not
// parse is recorded as `malformed` rather than dropped. Dropping it reported "no
// row" for a caller we had in fact found, which under LookupPeer's shape sends
// that caller to the address classification and, on a stale negative, to the
// credential. Recording it keeps the fail-safe outcome (no identity, and the
// caller is known local, so it is denied) AND keeps the diagnosis, which a
// silent `continue` threw away — the kernel does not emit such a row, so if one
// appears the operator needs to know rather than see an unexplained 403.
// It reports (read, absent): read=true means the file was consulted end to end;
// absent=true means it does not exist, which is not a failure (see scanBatch).
// read=false with absent=false is a genuine failure — present but unreadable, or
// truncated mid-scan — and MUST NOT be reported as "no row found".
func scanTableInto(path string, byLocal map[string]map[string][]*socketQuery) (read, absent bool) {
	f, err := os.Open(path)
	if err != nil {
		return false, errors.Is(err, fs.ErrNotExist)
	}
	defer f.Close()

	// Collected and logged ONCE per file per scan: the batcher already bounds
	// scan frequency, and a per-row log on a table this size would be a flood
	// vector rather than a diagnostic.
	var badRows int
	var badSample string

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		// Columns: sl local rem st tx:rx tr:when retrnsmt uid timeout inode ...
		line := sc.Text()
		fields := strings.Fields(line)
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
		st, sterr := strconv.ParseUint(fields[3], 16, 8)
		uid, uiderr := strconv.ParseUint(fields[7], 10, 32)
		if sterr != nil || uiderr != nil {
			badRows++
			if badSample == "" {
				badSample = fmt.Sprintf("state=%q uid=%q", fields[3], fields[7])
			}
			for _, q := range qs {
				q.malformed = true
			}
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
	if badRows > 0 {
		slog.Warn("authz: socket-table row matched a peer lookup but would not parse; "+
			"the caller is treated as local-and-unattributable (denied)",
			"path", path, "rows", badRows, "first", badSample)
	}
	// A read error mid-file (including bufio.Scanner's token-too-long) leaves
	// whatever matched before it. Report the file as read only if it completed,
	// so a truncated scan cannot be mistaken for "no row exists".
	return sc.Err() == nil, false
}

// normalizeHexColumn upper-cases a /proc address column. The kernel already
// emits upper-case hex, so this is insurance rather than a hot-path cost:
// strings.ToUpper returns its argument unchanged (no allocation) when there is
// nothing to fold.
func normalizeHexColumn(s string) string { return strings.ToUpper(s) }
