package logging

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
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
}

// LocalLogConfig configures a LocalLogWriter.
type LocalLogConfig struct {
	Path     string // log file path (default: /var/log/bpfrx/security.log)
	MaxSize  int64  // max file size in bytes (default: 10MB)
	MaxFiles int    // number of rotated files to keep (default: 5)
}

// NewLocalLogWriter creates a local file log writer.
func NewLocalLogWriter(cfg LocalLogConfig) (*LocalLogWriter, error) {
	path := cfg.Path
	if path == "" {
		path = "/var/log/bpfrx/security.log"
	}
	maxSize := cfg.MaxSize
	if maxSize <= 0 {
		maxSize = 10 * 1024 * 1024 // 10MB
	}
	maxFiles := cfg.MaxFiles
	if maxFiles <= 0 {
		maxFiles = 5
	}

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, fmt.Errorf("create log dir: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
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
		return fmt.Errorf("log file closed")
	}

	n, err := lw.file.WriteString(line)
	if err != nil {
		return err
	}
	lw.written += int64(n)

	if lw.written >= lw.maxSize {
		lw.rotate()
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

func (lw *LocalLogWriter) rotate() {
	lw.file.Close()
	lw.file = nil

	for i := lw.maxFiles - 1; i > 0; i-- {
		old := fmt.Sprintf("%s.%d", lw.path, i)
		next := fmt.Sprintf("%s.%d", lw.path, i+1)
		os.Rename(old, next)
	}
	os.Rename(lw.path, lw.path+".1")
	os.Remove(fmt.Sprintf("%s.%d", lw.path, lw.maxFiles+1))

	f, err := os.OpenFile(lw.path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		slog.Warn("failed to open rotated local log file", "err", err)
		return
	}
	lw.file = f
	lw.written = 0
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
