package logging

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// LocalLogWriter writes security log events to a local file with rotation.
// Used when security log mode is "event" instead of streaming to remote syslog.
type LocalLogWriter struct {
	mu       sync.Mutex
	file     *os.File
	path     string
	maxSize  int64
	maxFiles int
	written  int64

	// Filtering (same as SyslogClient)
	MinSeverity int
	Categories  uint8
	Format      string // "structured" or "" (standard)

	// Failure observability (#3478). droppedWrites counts security-log lines
	// lost because the file write failed or the file handle is nil (closed, or
	// a prior rotation reopen failed); failedRotations counts rotations that
	// could not complete (a generation shift, the active-file rename, or the
	// post-rotation reopen failed). These are audit-grade signals — an operator
	// running `security log mode event` must be able to tell that audit lines
	// are being lost. The two failure classes get SEPARATE ≤1/s warn clocks
	// (lastDropWarn / lastRotWarn, mu-guarded) so a write-drop storm cannot
	// suppress the rotation warning and vice versa.
	droppedWrites   atomic.Uint64
	failedRotations atomic.Uint64
	lastDropWarn    time.Time
	lastRotWarn     time.Time
}

// warnRateLimited emits a ≤1/s WARN carrying the current failure counters,
// gated by the supplied per-class clock. Must be called with lw.mu held.
func (lw *LocalLogWriter) warnRateLimited(clock *time.Time, msg string, err error) {
	now := time.Now()
	if !clock.IsZero() && now.Sub(*clock) < time.Second {
		return
	}
	*clock = now
	slog.Warn(msg,
		"err", err,
		"path", lw.path,
		"dropped_writes", lw.droppedWrites.Load(),
		"failed_rotations", lw.failedRotations.Load())
}

// DroppedWrites reports the number of security-log lines lost because the file
// write failed (#3478). Observability accessor for status/metrics surfaces.
func (lw *LocalLogWriter) DroppedWrites() uint64 { return lw.droppedWrites.Load() }

// FailedRotations reports the number of security-log rotations that could not
// complete (#3478).
func (lw *LocalLogWriter) FailedRotations() uint64 { return lw.failedRotations.Load() }

// LocalLogConfig configures a LocalLogWriter.
type LocalLogConfig struct {
	Path     string // log file path (default: /var/log/xpf/security.log)
	MaxSize  int64  // max file size in bytes (default: 10MB)
	MaxFiles int    // number of rotated files to keep (default: 5)
}

// NewLocalLogWriter creates a local file log writer.
func NewLocalLogWriter(cfg LocalLogConfig) (*LocalLogWriter, error) {
	path := cfg.Path
	if path == "" {
		path = "/var/log/xpf/security.log"
	}
	maxSize := cfg.MaxSize
	if maxSize <= 0 {
		maxSize = 10 * 1024 * 1024 // 10MB
	}
	maxFiles := cfg.MaxFiles
	if maxFiles <= 0 {
		maxFiles = 5
	}

	// Directory 0750 (not 0755) — the security log dir should not be
	// world-traversable (#3477 M02).
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return nil, fmt.Errorf("create log dir: %w", err)
	}
	// Open the active file with the shared audit-log hardening (#3477 M01):
	// O_NOFOLLOW (no symlink redirect), regular-file verified, mode 0600 (not
	// world-readable 0644 — the event-mode security log carries the same
	// policy/session/NAT forensics the flow-trace writer was hardened for).
	f, err := openHardenedAuditLog(path, os.O_APPEND)
	if err != nil {
		return nil, fmt.Errorf("open log file: %w", err)
	}

	lw := &LocalLogWriter{
		file:     f,
		path:     path,
		maxSize:  maxSize,
		maxFiles: maxFiles,
	}
	if info, err := f.Stat(); err == nil {
		lw.written = info.Size()
	}
	return lw, nil
}

// Send writes a log message to the local file. It matches the SyslogClient.Send
// signature pattern so it can be used as a drop-in replacement.
func (lw *LocalLogWriter) Send(severity int, msg string) error {
	ts := time.Now().Format("2006-01-02T15:04:05.000")
	line := fmt.Sprintf("%s [%s] %s\n", ts, severityTag(severity), msg)

	lw.mu.Lock()
	defer lw.mu.Unlock()

	if lw.file == nil {
		// #3478 item 1/4: a nil file (closed, or a prior rotation reopen
		// failed) drops the line. Count it on EVERY failure path — not just a
		// write error — so a wedged writer is observable, and return the error.
		lw.droppedWrites.Add(1)
		lw.warnRateLimited(&lw.lastDropWarn, "local security-log write dropped: file unavailable", errFileUnavailable)
		return fmt.Errorf("log file closed")
	}

	n, err := lw.file.WriteString(line)
	if err != nil {
		// #3478 M04: count the lost audit line and surface it (the error is
		// also returned to the caller; the counter makes the aggregate
		// observable even where callers discard it).
		lw.droppedWrites.Add(1)
		lw.warnRateLimited(&lw.lastDropWarn, "local security-log write failed (audit line lost)", err)
		return err
	}
	lw.written += int64(n)

	if lw.written >= lw.maxSize {
		if rerr := lw.rotate(); rerr != nil {
			lw.warnRateLimited(&lw.lastRotWarn, "local security-log rotation failed", rerr)
		}
	}
	return nil
}

// SendBinary writes a binary log record to the local file.
// The record is self-framing (contains its own length), so no additional
// framing is added.
func (lw *LocalLogWriter) SendBinary(data []byte) error {
	lw.mu.Lock()
	defer lw.mu.Unlock()

	if lw.file == nil {
		// #3478 item 1/4: count the dropped binary record on the nil-file path.
		lw.droppedWrites.Add(1)
		lw.warnRateLimited(&lw.lastDropWarn, "local security-log binary write dropped: file unavailable", errFileUnavailable)
		return fmt.Errorf("log file closed")
	}

	n, err := lw.file.Write(data)
	if err != nil {
		lw.droppedWrites.Add(1)
		lw.warnRateLimited(&lw.lastDropWarn, "local security-log binary write failed (audit record lost)", err)
		return err
	}
	lw.written += int64(n)

	if lw.written >= lw.maxSize {
		if rerr := lw.rotate(); rerr != nil {
			lw.warnRateLimited(&lw.lastRotWarn, "local security-log rotation failed", rerr)
		}
	}
	return nil
}

// ShouldSendEvent returns true if both severity and category filters pass.
func (lw *LocalLogWriter) ShouldSendEvent(severity int, categoryBit uint8) bool {
	if lw.MinSeverity != 0 && severity > lw.MinSeverity {
		return false
	}
	return lw.Categories == 0 || lw.Categories&categoryBit != 0
}

// Close closes the log file.
func (lw *LocalLogWriter) Close() error {
	lw.mu.Lock()
	defer lw.mu.Unlock()
	if lw.file != nil {
		err := lw.file.Close()
		lw.file = nil
		return err
	}
	return nil
}

// rotate rolls the active security-log file aside and reopens a fresh one. It
// returns a non-nil error if the rotation could not complete and bumps
// failedRotations (#3478 M03). The reopen uses the shared hardened open
// (O_NOFOLLOW, regular-file verified, 0600) instead of the old
// O_TRUNC|0644 — O_TRUNC followed a symlink planted between the rename and the
// reopen, turning rotation into a truncate-arbitrary-file primitive (#3477
// M02). lw.written is reset to 0 ONLY when the active file was actually moved
// aside; on a failed primary rename it is re-synced to the real size so the
// next write retries rotation rather than silently growing unbounded.
func (lw *LocalLogWriter) rotate() error {
	lw.file.Close()
	lw.file = nil

	// A missing generation is normal (ENOENT); any other shift failure means a
	// retained generation was lost — count and surface it (#3478 item 2).
	var shiftErr error
	for i := lw.maxFiles - 1; i > 0; i-- {
		old := fmt.Sprintf("%s.%d", lw.path, i)
		next := fmt.Sprintf("%s.%d", lw.path, i+1)
		if err := os.Rename(old, next); err != nil && !os.IsNotExist(err) {
			slog.Debug("local log rotate generation shift failed", "from", old, "to", next, "err", err)
			lw.failedRotations.Add(1)
			if shiftErr == nil {
				shiftErr = fmt.Errorf("rotate shift %s->%s: %w", old, next, err)
			}
		}
	}
	renameErr := os.Rename(lw.path, lw.path+".1")
	excess := fmt.Sprintf("%s.%d", lw.path, lw.maxFiles+1)
	if err := os.Remove(excess); err != nil && !os.IsNotExist(err) {
		slog.Debug("local log rotate excess removal failed", "path", excess, "err", err)
	}

	// Reopen with the shared hardened semantics. The primary rename (when it
	// succeeds) removed the active path, so O_CREATE yields a fresh empty file;
	// O_TRUNC is deliberately NOT used (see openHardenedAuditLog).
	f, err := openHardenedAuditLog(lw.path, os.O_APPEND)
	if err != nil {
		lw.failedRotations.Add(1)
		return fmt.Errorf("reopen after rotate: %w", err)
	}
	lw.file = f

	if renameErr != nil {
		lw.failedRotations.Add(1)
		if info, statErr := f.Stat(); statErr == nil {
			lw.written = info.Size()
		}
		return fmt.Errorf("rotate rename %s: %w", lw.path, renameErr)
	}
	// Active file rotated cleanly; reset the byte count. shiftErr (if any) is a
	// retained-generation loss only — surface it so the caller warns.
	lw.written = 0
	return shiftErr
}

func severityTag(severity int) string {
	switch severity {
	case SyslogError:
		return "ERROR"
	case SyslogWarning:
		return "WARNING"
	case SyslogInfo:
		return "INFO"
	default:
		return "INFO"
	}
}
