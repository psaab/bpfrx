package upgrade

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/psaab/xpf/pkg/fsatomic"
)

// Default filesystem layout (plan §6.1). Overridable in Config for tests.
const (
	DefaultStagedDir   = "/usr/local/share/xpf/staged"
	DefaultVersionsDir = "/var/lib/xpf/versions"
	DefaultSbinDir     = "/usr/local/sbin"
	DefaultConfigDBDir = "/etc/xpf/.configdb"
	DefaultJournalPath = "/var/lib/xpf/upgrade.state"
	DefaultUnit        = "xpfd"

	// currentLink is the bookkeeping pointer inside VersionsDir.
	currentLink = "current"

	// retainVersions is N in the N=3 retention policy. The running version
	// and its immediate predecessor are NEVER GC'd regardless of N.
	retainVersions = 3

	// partialPrefix marks an in-progress version copy. A stray
	// .<ver>.partial dir is always safe to delete on re-run.
	partialPrefix = "."
	partialSuffix = ".partial"
)

// managedBins are the binaries copied into each version dir and linked
// from /usr/local/sbin. xpfd and xpf-userspace-dp are the matched set cut
// in lockstep; cli and xpf-day0-config are operator tools.
var managedBins = []string{"xpfd", "cli", "xpf-userspace-dp", "xpf-day0-config"}

// System abstracts the OS / systemd / clock surface so the state machine
// is unit-testable without a live host. The production implementation is
// realSystem (system_linux.go).
type System interface {
	// StopUnit stops the given systemd unit and waits for it to be
	// inactive.
	StopUnit(unit string) error
	// StartUnit starts the given systemd unit.
	StartUnit(unit string) error
	// DaemonReload runs `systemctl daemon-reload`.
	DaemonReload() error
	// WriteUnitDropin writes (atomically) a drop-in for unit that pins
	// ExecStart/ExecStartPre to the concrete versioned xpfd path, then the
	// caller must DaemonReload. content is the full drop-in file body.
	WriteUnitDropin(unit, name, content string) error
	// FreeBytes reports available bytes on the filesystem backing path.
	FreeBytes(path string) (uint64, error)
	// VerifyDataplane runs `<bin> verify-dataplane` and reports whether it
	// PASSED. A REJECT (exit 3) returns (false, nil); any other failure
	// returns an error.
	VerifyDataplane(bin string, env []string) (bool, error)
	// BinaryVersion runs `<bin> version` and returns the version token.
	BinaryVersion(bin string) (string, error)
	// HelperHealthy reports whether the running daemon's helper is healthy
	// and reports the expected version within the deadline.
	HelperHealthy(expectVersion string, deadline time.Duration) error
	// Now returns the current time.
	Now() time.Time
}

// Config configures a Runner.
type Config struct {
	StagedDir   string
	VersionsDir string
	SbinDir     string
	ConfigDBDir string
	JournalPath string
	Unit        string

	// DiskMarginBytes is the headroom required on /var beyond the staged
	// size + DB snapshot size in PREFLIGHT.
	DiskMarginBytes uint64

	// StartHealthDeadline bounds the post-start helper-health wait before
	// auto-rollback (standalone) fires.
	StartHealthDeadline time.Duration

	// Sys is the OS/systemd surface. Required.
	Sys System

	// Logf is an optional structured progress sink (defaults to no-op).
	Logf func(format string, args ...any)
}

func (c *Config) withDefaults() {
	if c.StagedDir == "" {
		c.StagedDir = DefaultStagedDir
	}
	if c.VersionsDir == "" {
		c.VersionsDir = DefaultVersionsDir
	}
	if c.SbinDir == "" {
		c.SbinDir = DefaultSbinDir
	}
	if c.ConfigDBDir == "" {
		c.ConfigDBDir = DefaultConfigDBDir
	}
	if c.JournalPath == "" {
		c.JournalPath = DefaultJournalPath
	}
	if c.Unit == "" {
		c.Unit = DefaultUnit
	}
	if c.DiskMarginBytes == 0 {
		c.DiskMarginBytes = 64 << 20 // 64 MiB headroom
	}
	if c.StartHealthDeadline == 0 {
		c.StartHealthDeadline = 30 * time.Second
	}
	if c.Logf == nil {
		c.Logf = func(string, ...any) {}
	}
}

// Runner drives the cut-over state machine.
type Runner struct {
	cfg Config
}

// NewRunner builds a Runner. Sys must be set.
func NewRunner(cfg Config) (*Runner, error) {
	cfg.withDefaults()
	if cfg.Sys == nil {
		return nil, fmt.Errorf("upgrade: Config.Sys is required")
	}
	return &Runner{cfg: cfg}, nil
}

func (r *Runner) logf(format string, args ...any) { r.cfg.Logf(format, args...) }

// versionDir returns the runtime dir for ver.
func (r *Runner) versionDir(ver string) string {
	return filepath.Join(r.cfg.VersionsDir, ver)
}

// partialDir returns the in-progress copy dir for ver.
func (r *Runner) partialDir(ver string) string {
	return filepath.Join(r.cfg.VersionsDir, partialPrefix+ver+partialSuffix)
}

// currentPath returns the path of the `current` bookkeeping symlink.
func (r *Runner) currentPath() string {
	return filepath.Join(r.cfg.VersionsDir, currentLink)
}

// readCurrentVersion resolves the version the `current` symlink points at,
// or "" if it does not exist (very first cut).
func (r *Runner) readCurrentVersion() (string, error) {
	target, err := os.Readlink(r.currentPath())
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("read current symlink: %w", err)
	}
	// current -> <ver> (relative within VersionsDir).
	return filepath.Base(target), nil
}

// loadJournal reads the persisted journal, or returns a zero Journal if
// none exists.
func (r *Runner) loadJournal() (*Journal, error) {
	data, err := os.ReadFile(r.cfg.JournalPath)
	if err != nil {
		if os.IsNotExist(err) {
			return &Journal{State: StateInit}, nil
		}
		return nil, fmt.Errorf("read upgrade journal: %w", err)
	}
	j := &Journal{}
	if err := json.Unmarshal(data, j); err != nil {
		return nil, fmt.Errorf("parse upgrade journal: %w", err)
	}
	return j, nil
}

// saveJournal persists j durably (temp+fsync+rename+dir fsync). Every
// state transition routes through here so a crash leaves a consistent,
// resumable record.
func (r *Runner) saveJournal(j *Journal) error {
	data, err := json.MarshalIndent(j, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal upgrade journal: %w", err)
	}
	if err := fsatomic.MkdirAllDurable(filepath.Dir(r.cfg.JournalPath), 0755); err != nil {
		return fmt.Errorf("create journal dir: %w", err)
	}
	if err := fsatomic.WriteFileDurable(r.cfg.JournalPath, data, 0644); err != nil {
		return fmt.Errorf("persist upgrade journal: %w", err)
	}
	return nil
}

// clearJournal removes the journal on terminal success.
func (r *Runner) clearJournal() error {
	if err := os.Remove(r.cfg.JournalPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove upgrade journal: %w", err)
	}
	return nil
}

// transition records the completed state.
func (r *Runner) transition(j *Journal, s State) error {
	j.State = s
	r.logf("upgrade: -> %s (target=%s prev=%s)", s, j.TargetVersion, j.PreviousVersion)
	return r.saveJournal(j)
}

// dirSize sums the apparent size of all regular files under dir.
func dirSize(dir string) (uint64, error) {
	var total uint64
	err := filepath.Walk(dir, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			total += uint64(info.Size())
		}
		return nil
	})
	return total, err
}

// copyTree recursively copies src into dst, preserving file modes,
// fsyncing each file. dst must not exist. Returns a sha256 over the
// sorted (relpath, content) stream for an integrity check.
func copyTree(src, dst string) (string, error) {
	h := sha256.New()
	// Collect entries first for a deterministic checksum order.
	type ent struct {
		rel  string
		info os.FileInfo
		path string
	}
	var ents []ent
	err := filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(src, p)
		if rerr != nil {
			return rerr
		}
		ents = append(ents, ent{rel: rel, info: info, path: p})
		return nil
	})
	if err != nil {
		return "", err
	}
	sort.Slice(ents, func(i, j int) bool { return ents[i].rel < ents[j].rel })

	for _, e := range ents {
		target := filepath.Join(dst, e.rel)
		switch {
		case e.info.IsDir():
			if err := os.MkdirAll(target, 0755); err != nil {
				return "", fmt.Errorf("mkdir %s: %w", target, err)
			}
		case e.info.Mode().IsRegular():
			if err := copyFileFsync(e.path, target, e.info.Mode()); err != nil {
				return "", err
			}
			f, oerr := os.Open(target)
			if oerr != nil {
				return "", oerr
			}
			io.WriteString(h, e.rel+"\x00")
			if _, cerr := io.Copy(h, f); cerr != nil {
				f.Close()
				return "", cerr
			}
			f.Close()
		default:
			return "", fmt.Errorf("copyTree: unsupported file type for %s", e.path)
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// copyFileFsync copies src -> dst with mode, fsyncing dst before close.
func copyFileFsync(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open %s: %w", src, err)
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return fmt.Errorf("create %s: %w", dst, err)
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return fmt.Errorf("copy %s -> %s: %w", src, dst, err)
	}
	if err := out.Sync(); err != nil {
		out.Close()
		return fmt.Errorf("fsync %s: %w", dst, err)
	}
	if err := out.Close(); err != nil {
		return fmt.Errorf("close %s: %w", dst, err)
	}
	return nil
}

// removeAllPartials sweeps any leftover .partial dirs (safe on re-run).
func (r *Runner) removeAllPartials() {
	entries, err := os.ReadDir(r.cfg.VersionsDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		n := e.Name()
		if strings.HasPrefix(n, partialPrefix) && strings.HasSuffix(n, partialSuffix) {
			_ = os.RemoveAll(filepath.Join(r.cfg.VersionsDir, n))
		}
	}
}
