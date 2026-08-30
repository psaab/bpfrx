// Package journal implements the configstore commit audit trail as a
// compact, rotated, tail-readable JSONL log (#1896).
//
// History: the v1 journal (pkg/configstore/journal.go, deleted in
// #1896) appended the FULL compiled *config.Config per commit and every
// history view re-read and re-unmarshaled the entire file — O(lifetime
// commits x config size) per `show system commit`, no rotation, and the
// compiled payload (including secrets) sat in a 0644 file forever while
// being read by nobody: both renderers print only Timestamp, Action and
// Detail, and full config trees already live in the rollback slots with
// explicit retention.
//
// v2 entries are compact metadata only and the file is written
// owner-only 0600 (#4579 A4-02): although the metadata is not itself a
// secret store, Detail carries the operator's free-text commit comment
// verbatim, so the journal matches the 0600 posture of the rest of the
// config surface (#4056) instead of sitting world-readable. Reads are
// reverse tail scans bounded by the requested limit; the file rotates
// by size with a keep-N segment policy; appends are fsynced
// (operator-paced — the
// commit path already pays several fsyncs for active.json and rollback
// slot 1, see #1894). Legacy fat v1 lines decode tolerantly (unknown
// JSON fields are ignored), and the first append after upgrade rotates
// an over-threshold legacy file to segment .1 intact, so old history
// stays visible until it ages out. First use — the first Log or Tail —
// runs a one-time permission-repair pass (#5188): every OWNED segment
// (the current file plus its rotation siblings .1../.N) is lstat'd and,
// if a pre-0600 build left it more permissive than owner-only, chmod'd
// to 0600, and rotation re-asserts 0600 on the renamed segment. This
// closes the residual #4579 A4-02 left: O_APPEND ignores the perm arg on
// an EXISTING inode, so an upgraded 0644 current file — and any rotated
// secret-bearing legacy .N segment — otherwise stayed world-readable
// with no migration pass at all. The repair only ever tightens (a
// stricter-than-0600 file is left alone), refuses to follow a symlink
// (lstat, never chmod through it to an arbitrary target), and surfaces
// failures as warnings rather than swallowing them. Boot never reads the
// journal at all.
package journal

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/psaab/xpf/pkg/fsatomic"
)

// Entry is a single audit record (schema v2). Legacy v1 entries carried
// full compiled-config "before"/"after" payloads; those fields are gone
// — tolerant decode drops them — and the rollback files (the canonical
// full-config history, saveRollbackFiles in pkg/configstore) carry the
// trees instead.
type Entry struct {
	// Schema is 2 for entries written by this package and 0 for
	// legacy v1 lines. Forensic marker only — decode is tolerant in
	// both directions.
	Schema    int       `json:"v,omitempty"`
	Timestamp time.Time `json:"timestamp"`
	// Action: "commit", "commit_confirmed", "auto_rollback",
	// "config_sync", "persist_error", "persist_recovered",
	// "system_action" (destructive maintenance verb, #4108 F8).
	Action string `json:"action"`
	// Detail is the human-readable description (commit comment or
	// error text).
	Detail string `json:"detail,omitempty"`
	// ConfigHash is the sha256 (hex) of the post-action active
	// config tree's Format() text — the same text saveRollbackFiles
	// writes to rollback slots, so `sha256sum <conf>.N` correlates a
	// retained rollback file to its journal entry. Best-effort
	// correlation while the slot is retained (slots shift every
	// commit and only ~50 are kept), NOT a referential-integrity
	// guarantee. Empty for entries that carry no config
	// (persist_error / persist_recovered).
	ConfigHash string `json:"config_hash,omitempty"`
}

// SchemaV2 marks entries written by this package.
const SchemaV2 = 2

const (
	// DefaultMaxSegmentBytes rotates the current segment once it
	// reaches 1 MiB (~4-7k compact entries).
	DefaultMaxSegmentBytes = 1 << 20
	// DefaultMaxSegments keeps 2 rotated segments next to the
	// current one: bounded worst-case disk ≈ 3 MiB + one fat legacy
	// segment until it ages out.
	DefaultMaxSegments = 2

	// readChunk is the reverse-scan chunk size. Larger lines (legacy
	// fat v1 entries) are assembled across chunks.
	readChunk = 64 << 10

	// maxTailLineBytes caps reverse-scan line assembly (AGY plan-r1
	// F4): a corrupt newline-free segment would otherwise buffer the
	// whole file. 16 MiB is far above any real legacy fat entry; a
	// fragment past the cap is discarded and the scanner resyncs at
	// the previous newline, dropping only the poisoned line.
	maxTailLineBytes = 16 << 20
)

// Journal is an append-only, size-rotated JSONL audit log. All methods
// are goroutine-safe via an internal mutex: ListCommitHistory readers
// do NOT hold the configstore Store.mu, and without internal locking a
// reader that opens the current segment while Log rotates it to ".1"
// would read the same inode under both names and duplicate entries.
//
// Lock discipline (#4829): j.mu guards the SEGMENT STATE (rotation, the
// current-file inode, the buffered append), NOT the per-write fsync.
// Log holds j.mu only for rotation + open + the buffered f.Write, then
// RELEASES it before the synchronous f.Sync/SyncDir. A concurrent Tail
// takes the same j.mu, so it is still serialized against rotation (no
// duplicate inode) and against the write itself (no torn read), but it
// no longer blocks for the writer's fsync duration.
type Journal struct {
	mu              sync.Mutex
	path            string
	maxSegmentBytes int64
	maxSegments     int
	// migrated guards the one-time permission-repair pass (#5188) so it
	// runs once on first use, under j.mu, and is a no-op thereafter.
	migrated bool
	// syncFile fsyncs a fully-written segment for durability. It is a
	// field only so tests can inject a slow/blocking fsync and prove Tail
	// does not stall behind it (#4829); production always uses
	// (*os.File).Sync. Called with j.mu RELEASED.
	syncFile func(*os.File) error
}

// Option configures a Journal.
type Option func(*Journal)

// WithMaxSegmentBytes overrides the rotation threshold (tests).
func WithMaxSegmentBytes(n int64) Option {
	return func(j *Journal) { j.maxSegmentBytes = n }
}

// WithMaxSegments overrides how many rotated segments are kept (tests).
func WithMaxSegments(n int) Option {
	return func(j *Journal) { j.maxSegments = n }
}

// New creates a journal at the given file path. Out-of-range options
// are clamped to the defaults: maxSegments < 1 would make rotation
// resolve segmentPath(0) — the CURRENT file — and delete the live
// journal (AGY code-r1 F2), and maxSegmentBytes < 1 would rotate on
// every append.
func New(path string, opts ...Option) *Journal {
	j := &Journal{
		path:            path,
		maxSegmentBytes: DefaultMaxSegmentBytes,
		maxSegments:     DefaultMaxSegments,
		syncFile:        (*os.File).Sync,
	}
	for _, o := range opts {
		o(j)
	}
	if j.maxSegments < 1 {
		j.maxSegments = DefaultMaxSegments
	}
	if j.maxSegmentBytes < 1 {
		j.maxSegmentBytes = DefaultMaxSegmentBytes
	}
	return j
}

// segmentPath returns the path of rotated segment n (1 = newest
// rotated). n == 0 is the current segment.
func (j *Journal) segmentPath(n int) string {
	if n == 0 {
		return j.path
	}
	return fmt.Sprintf("%s.%d", j.path, n)
}

// migratePermsLocked runs once on first use (Log or Tail) and repairs
// the permissions of every OWNED journal segment — the current file and
// its rotation siblings — to owner-only 0600 (#5188). #4579 A4-02 made
// NEW journals 0600, but O_APPEND ignores the perm arg on an existing
// inode, so an upgraded 0644 current file, and any rotated
// secret-bearing legacy .N segment, stayed world-readable with no
// migration pass. Only these journal-owned paths are touched, never an
// unrelated file. Caller holds j.mu.
func (j *Journal) migratePermsLocked() {
	if j.migrated {
		return
	}
	j.migrated = true
	for seg := 0; seg <= j.maxSegments; seg++ {
		chmodOwnerOnly(j.segmentPath(seg))
	}
}

// chmodOwnerOnly tightens path to 0600 when it is a regular file whose
// mode grants any access beyond owner read/write. It only ever tightens:
// a file that is already 0600 or stricter is left untouched, so a
// deliberately locked-down journal is never loosened. A symlink is
// refused — the path is lstat'd and the link is never followed to chmod
// an arbitrary target — and a missing path is a no-op. Failures are
// surfaced as warnings (#5188 "surface failures"), not swallowed.
func chmodOwnerOnly(path string) {
	fi, err := os.Lstat(path)
	if err != nil {
		if !os.IsNotExist(err) {
			slog.Warn("journal: lstat segment for permission repair failed",
				"path", path, "err", err)
		}
		return
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		slog.Warn("journal: refusing to chmod through a symlinked journal segment",
			"path", path)
		return
	}
	if !fi.Mode().IsRegular() {
		return // not an owned journal segment (device/socket/dir/etc.)
	}
	if fi.Mode().Perm()&^0o600 == 0 {
		return // already owner-only (or stricter): only tighten, never loosen
	}
	if err := os.Chmod(path, 0o600); err != nil {
		slog.Warn("journal: chmod journal segment to 0600 failed",
			"path", path, "err", err)
	}
}

// Log appends an entry, rotating first when the current segment is
// over the size threshold. The append is fsynced (the journal is the
// only audit record now that config payloads live in rollback storage,
// and appends are operator-paced); segment creation and rotation get a
// directory fsync so the namespace change survives power loss too.
//
// Lock discipline (#4829): j.mu is held ONLY for the segment-state
// mutation — rotation, open, the torn-tail check, and the buffered
// f.Write — inside appendLocked. The durability step (f.Sync and, on
// create/rotate, SyncDir) runs with j.mu RELEASED, because fsync
// provides durability, NOT visibility: the record's bytes are already in
// the page cache once f.Write returns. A concurrent Tail takes the same
// j.mu, so it observes the segment namespace either before appendLocked
// acquires the lock or after it releases the lock — never mid-rotation
// (no duplicate inode) and never mid-write (no torn read) — yet it no
// longer stalls for the writer's fsync (hundreds of ms on a busy disk).
// Durability is unchanged: Log returns success only after f.Sync (and,
// when the namespace changed, SyncDir) succeed.
//
// Concurrent Log callers serialize on the fast in-lock write via
// appendLocked, then fsync in parallel with j.mu released; O_APPEND makes
// each write land atomically at EOF, and every writer fsyncs its own fd,
// so durability holds regardless of interleaving.
func (j *Journal) Log(entry *Entry) error {
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now()
	}
	if entry.Schema == 0 {
		entry.Schema = SchemaV2
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshal journal entry: %w", err)
	}

	f, created, rotated, err := j.appendLocked(data)
	if err != nil {
		return err
	}
	defer f.Close()

	// Durability with j.mu RELEASED (see the method doc). Do NOT move
	// these back under the lock: that reintroduces #4829, where a Tail
	// reader blocks for the writer's entire fsync duration.
	sync := j.syncFile
	if sync == nil {
		sync = (*os.File).Sync
	}
	if err := sync(f); err != nil {
		return fmt.Errorf("sync journal: %w", err)
	}
	if created || rotated {
		if err := fsatomic.SyncDir(filepath.Dir(j.path)); err != nil {
			return fmt.Errorf("sync journal dir: %w", err)
		}
	}
	return nil
}

// appendLocked runs the lock-held part of Log: the one-time permission
// repair, rotation when the current segment is over threshold, opening
// the current segment, the torn-tail self-heal, and the buffered write of
// the newline-framed record. It returns the still-open file (the caller
// fsyncs it with j.mu released) plus whether the segment was created or
// rotated (both need a directory fsync). j.mu is held for the whole body,
// so the buffered f.Write completes and is visible in the page cache
// before the lock is released — any concurrent Tail that then acquires
// j.mu sees a complete record, never a torn one.
func (j *Journal) appendLocked(data []byte) (f *os.File, created, rotated bool, err error) {
	j.mu.Lock()
	defer j.mu.Unlock()

	j.migratePermsLocked()

	rotated, err = j.maybeRotateLocked()
	if err != nil {
		return nil, false, false, err
	}

	if _, statErr := os.Stat(j.path); os.IsNotExist(statErr) {
		created = true
	}

	// O_RDWR (not O_WRONLY): the torn-tail check below reads the
	// last byte through the same fd.
	//
	// Owner-only 0600 (#4579 A4-02): v2 entries are metadata only
	// (Timestamp/Action/ConfigHash plus a free-text Detail), so the
	// journal is not a secret store the way active.json is. But Detail
	// carries the operator-supplied commit comment verbatim, and an
	// operator can put anything there — including, by mistake, a
	// credential ("rotated the vpn psk to hunter2"). The rest of the
	// .configdb-adjacent config surface is already 0600 (#4056); the
	// journal is written next to it and should match rather than sit
	// world-readable as a defense-in-depth gap. The daemon owns the file,
	// so 0600 does not affect append or tail read-back. NOTE: this perm
	// arg only applies when O_CREATE actually creates the file; on an
	// EXISTING inode O_APPEND ignores it, so migratePermsLocked() above
	// is what tightens an upgraded 0644 journal (#5188).
	// #7176 (C179-061): O_NOFOLLOW plus a post-open regular-file check.
	//
	// This package already refuses to CHMOD through a symlinked segment
	// (chmodOwnerOnly above: Lstat, reject ModeSymlink, require IsRegular) — it
	// just did not refuse to APPEND through one. The audit journal is the record
	// an operator reads to reconstruct what happened, so writing it into
	// someone else's file is worse than the permission gap that convention was
	// written for.
	//
	// Both checks are needed and neither subsumes the other:
	//
	//   - O_NOFOLLOW refuses when the FINAL path component is a symlink, and the
	//     kernel decides it at open time, so there is no TOCTOU window the way
	//     an Lstat-then-open would have.
	//   - O_NOFOLLOW happily opens a FIFO, device or socket planted directly at
	//     the path — those are not symlinks. A FIFO is the worst of them: with
	//     O_RDWR the open succeeds, writes land in the pipe buffer, and the
	//     daemon BLOCKS once it fills. So fstat the descriptor and require a
	//     regular file.
	//
	// The check is f.Stat() on the open descriptor, not os.Stat(j.path): a
	// path-based stat would be checking a different object from the one just
	// opened.
	//
	// Cost to a legitimate deployment: an operator who symlinks the journal FILE
	// itself now gets a clear error instead of silent indirection. Symlinking
	// the journal DIRECTORY still works — O_NOFOLLOW only constrains the final
	// component.
	f, err = os.OpenFile(j.path, os.O_APPEND|os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, false, false, fmt.Errorf("open journal: %w", err)
	}
	if fi, statErr := f.Stat(); statErr != nil {
		f.Close()
		return nil, false, false, fmt.Errorf("stat journal after open: %w", statErr)
	} else if !fi.Mode().IsRegular() {
		mode := fi.Mode()
		f.Close()
		return nil, false, false, fmt.Errorf(
			"journal path %s is not a regular file (mode %s) — refusing to append the "+
				"audit journal into it", j.path, mode)
	}

	// Torn-tail self-heal: a crash between a previous write and its
	// fsync can leave a partial final line. Starting this record on a
	// fresh line confines the damage to that one record (which the
	// tail reader's parse-or-skip rule already drops).
	buf := make([]byte, 0, len(data)+2)
	if fi, statErr := f.Stat(); statErr == nil && fi.Size() > 0 {
		last := make([]byte, 1)
		if _, readErr := f.ReadAt(last, fi.Size()-1); readErr == nil && last[0] != '\n' {
			buf = append(buf, '\n')
		}
	}
	buf = append(buf, data...)
	buf = append(buf, '\n')

	if _, writeErr := f.Write(buf); writeErr != nil {
		f.Close()
		return nil, false, false, fmt.Errorf("write journal entry: %w", writeErr)
	}
	return f, created, rotated, nil
}

// maybeRotateLocked rotates the current segment when it is at or over
// the size threshold: the oldest kept segment is removed, every rotated
// segment shifts up one slot, and the current file becomes ".1". A
// crash mid-shift can leave a gap in the segment sequence (lost oldest
// retention); Tail tolerates gaps. Caller holds j.mu.
func (j *Journal) maybeRotateLocked() (bool, error) {
	fi, err := os.Stat(j.path)
	if err != nil || fi.Size() < j.maxSegmentBytes {
		return false, nil // missing/unreadable current segment: nothing to rotate
	}
	if err := os.Remove(j.segmentPath(j.maxSegments)); err != nil && !os.IsNotExist(err) {
		return false, fmt.Errorf("rotate journal: remove oldest segment: %w", err)
	}
	for i := j.maxSegments - 1; i >= 1; i-- {
		if err := os.Rename(j.segmentPath(i), j.segmentPath(i+1)); err != nil && !os.IsNotExist(err) {
			return false, fmt.Errorf("rotate journal: shift segment %d: %w", i, err)
		}
	}
	if err := os.Rename(j.path, j.segmentPath(1)); err != nil {
		return false, fmt.Errorf("rotate journal: rotate current: %w", err)
	}
	// The renamed segment inherits the current file's mode. New v2 files
	// are 0600, but an un-migrated legacy 0644 current would carry
	// world-read into the rotated (secret-bearing) segment; re-assert
	// owner-only here so rotation never widens exposure (#5188).
	chmodOwnerOnly(j.segmentPath(1))
	return true, nil
}

// Tail returns up to limit most-recent entries in oldest-first order
// (matching the v1 ListEntries contract). The read is bounded: segments
// are scanned newest-first with a reverse chunked scan that stops as
// soon as limit entries have been collected, so Tail(50) reads O(50)
// entries regardless of journal lifetime. Unparseable lines (torn tail,
// corruption, foreign content) are skipped, the same tolerance v1 had.
// limit <= 0 reads everything (oldest segment first) — the legacy
// full-scan path kept for ListCommitHistory(0) callers.
func (j *Journal) Tail(limit int) ([]*Entry, error) {
	j.mu.Lock()
	defer j.mu.Unlock()

	j.migratePermsLocked()

	if limit <= 0 {
		return j.readAllLocked()
	}

	// newestFirst[0] is the most recent entry.
	var newestFirst []*Entry
	for seg := 0; seg <= j.maxSegments && len(newestFirst) < limit; seg++ {
		entries, err := tailSegment(j.segmentPath(seg), limit-len(newestFirst))
		if err != nil {
			return nil, err
		}
		newestFirst = append(newestFirst, entries...)
	}

	// Reverse to oldest-first.
	out := make([]*Entry, len(newestFirst))
	for i, e := range newestFirst {
		out[len(out)-1-i] = e
	}
	return out, nil
}

// readAllLocked is the unbounded path (limit <= 0): every segment,
// oldest first, parsed forward. Caller holds j.mu.
func (j *Journal) readAllLocked() ([]*Entry, error) {
	var out []*Entry
	for seg := j.maxSegments; seg >= 0; seg-- {
		data, err := os.ReadFile(j.segmentPath(seg))
		if err != nil {
			if os.IsNotExist(err) {
				continue // gaps tolerated (crash mid-rotation)
			}
			return nil, fmt.Errorf("read journal segment: %w", err)
		}
		for _, line := range bytes.Split(data, []byte{'\n'}) {
			if e := parseLine(line); e != nil {
				out = append(out, e)
			}
		}
	}
	return out, nil
}

// tailSegment returns up to limit entries from the END of one segment
// file, newest first. A missing segment yields (nil, nil).
func tailSegment(path string, limit int) ([]*Entry, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("open journal segment: %w", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat journal segment: %w", err)
	}
	return tailScan(f, fi.Size(), limit)
}

// tailScan reads up to limit newline-terminated JSON entries from the
// end of r, newest first, reading backwards in readChunk-sized chunks.
// Lines longer than a chunk (legacy fat v1 entries) are assembled
// across chunks. Split out on (io.ReaderAt, size) so tests can prove
// boundedness with a counting reader.
func tailScan(r io.ReaderAt, size int64, limit int) ([]*Entry, error) {
	var entries []*Entry
	// pending holds the head fragment of the region processed so far:
	// a (possibly partial) line whose beginning may still be in an
	// earlier chunk, terminated by at most one '\n' at its end.
	var pending []byte
	// skipping means the line currently being assembled blew past
	// maxTailLineBytes (AGY plan-r1 F4); its bytes are discarded until
	// the scanner resyncs at the previous newline.
	skipping := false
	off := size
	for off > 0 && len(entries) < limit {
		n := int64(readChunk)
		if off < n {
			n = off
		}
		off -= n
		chunk := make([]byte, n)
		if _, err := r.ReadAt(chunk, off); err != nil {
			return nil, fmt.Errorf("read journal segment: %w", err)
		}
		buf := chunk
		if skipping {
			// Everything from the LAST newline onward belongs to the
			// poisoned over-cap line; drop it and resume normal
			// scanning on the bytes before it.
			ln := bytes.LastIndexByte(chunk, '\n')
			if ln < 0 {
				continue // whole chunk inside the poisoned line
			}
			buf = chunk[:ln+1]
			skipping = false
		} else if len(pending) > 0 {
			// File order: chunk precedes pending. chunk was allocated
			// with cap == len, so append copies — pending's backing
			// array is never aliased into a reused buffer.
			buf = append(chunk, pending...)
			pending = nil
		}
		// Lines fully contained in buf end at each '\n'; the bytes
		// before the first '\n' may continue in the previous chunk.
		nl := bytes.IndexByte(buf, '\n')
		if nl < 0 {
			pending = buf
		} else {
			complete := buf[nl+1:]
			pending = buf[:nl+1] // head fragment incl. its terminating '\n'
			lines := bytes.Split(complete, []byte{'\n'})
			for i := len(lines) - 1; i >= 0 && len(entries) < limit; i-- {
				if e := parseLine(lines[i]); e != nil {
					entries = append(entries, e)
				}
			}
		}
		// Cap check on EVERY pending update, not only the no-newline
		// path (AGY code-r1 F1): a fragment that retained its
		// terminating '\n' (e.g. an over-cap line that ends in a
		// newline) keeps satisfying IndexByte on later iterations and
		// would otherwise grow without bound.
		if len(pending) > maxTailLineBytes {
			pending = nil
			skipping = true
		}
	}
	// Whatever is left runs from offset 0: the file's first line (or
	// the whole file when it contains no newline at all).
	if len(pending) > 0 && len(entries) < limit {
		if e := parseLine(bytes.TrimSuffix(pending, []byte{'\n'})); e != nil {
			entries = append(entries, e)
		}
	}
	return entries, nil
}

// parseLine decodes one JSONL line; nil for blank or unparseable lines
// (torn tail, corruption — v1 had the same skip rule). Unknown fields —
// the legacy "before"/"after" config payloads — are ignored by
// encoding/json, which is the whole back-compat story: a fat v1 line
// decodes to its Timestamp/Action/Detail, exactly what the renderers
// print.
func parseLine(line []byte) *Entry {
	line = bytes.TrimSpace(line)
	if len(line) == 0 {
		return nil
	}
	e := &Entry{}
	if err := json.Unmarshal(line, e); err != nil {
		return nil
	}
	// An object that decodes but carries no action/timestamp is not a
	// journal entry (e.g. a stray "{}" from corruption) — drop it the
	// way v1's renderers would have shown garbage. Keep anything with
	// an action, even zero-timestamp, to stay tolerant of hand edits.
	if e.Action == "" && e.Timestamp.IsZero() {
		return nil
	}
	return e
}
