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
// v2 entries are compact metadata only. Reads are reverse tail scans
// bounded by the requested limit; the file rotates by size with a
// keep-N segment policy; appends are fsynced (operator-paced — the
// commit path already pays several fsyncs for active.json and rollback
// slot 1, see #1894). Legacy fat v1 lines decode tolerantly (unknown
// JSON fields are ignored), and the first append after upgrade rotates
// an over-threshold legacy file to segment .1 intact, so old history
// stays visible until it ages out — no migration pass, and boot never
// reads the journal at all.
package journal

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
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
	// "config_sync", "persist_error", "persist_recovered".
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
type Journal struct {
	mu              sync.Mutex
	path            string
	maxSegmentBytes int64
	maxSegments     int
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

// New creates a journal at the given file path.
func New(path string, opts ...Option) *Journal {
	j := &Journal{
		path:            path,
		maxSegmentBytes: DefaultMaxSegmentBytes,
		maxSegments:     DefaultMaxSegments,
	}
	for _, o := range opts {
		o(j)
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

// Log appends an entry, rotating first when the current segment is
// over the size threshold. The append is fsynced (the journal is the
// only audit record now that config payloads live in rollback storage,
// and appends are operator-paced); segment creation and rotation get a
// directory fsync so the namespace change survives power loss too.
func (j *Journal) Log(entry *Entry) error {
	j.mu.Lock()
	defer j.mu.Unlock()

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

	rotated, err := j.maybeRotateLocked()
	if err != nil {
		return err
	}

	created := false
	if _, err := os.Stat(j.path); os.IsNotExist(err) {
		created = true
	}

	// O_RDWR (not O_WRONLY): the torn-tail check below reads the
	// last byte through the same fd.
	f, err := os.OpenFile(j.path, os.O_APPEND|os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return fmt.Errorf("open journal: %w", err)
	}
	defer f.Close()

	// Torn-tail self-heal: a crash between a previous write and its
	// fsync can leave a partial final line. Starting this record on a
	// fresh line confines the damage to that one record (which the
	// tail reader's parse-or-skip rule already drops).
	buf := make([]byte, 0, len(data)+2)
	if fi, err := f.Stat(); err == nil && fi.Size() > 0 {
		last := make([]byte, 1)
		if _, err := f.ReadAt(last, fi.Size()-1); err == nil && last[0] != '\n' {
			buf = append(buf, '\n')
		}
	}
	buf = append(buf, data...)
	buf = append(buf, '\n')

	if _, err := f.Write(buf); err != nil {
		return fmt.Errorf("write journal entry: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync journal: %w", err)
	}
	if created || rotated {
		if err := fsatomic.SyncDir(filepath.Dir(j.path)); err != nil {
			return fmt.Errorf("sync journal dir: %w", err)
		}
	}
	return nil
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
			if len(pending) > maxTailLineBytes {
				pending = nil
				skipping = true
			}
			continue
		}
		complete := buf[nl+1:]
		pending = buf[:nl+1] // head fragment incl. its terminating '\n'
		lines := bytes.Split(complete, []byte{'\n'})
		for i := len(lines) - 1; i >= 0 && len(entries) < limit; i-- {
			if e := parseLine(lines[i]); e != nil {
				entries = append(entries, e)
			}
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
