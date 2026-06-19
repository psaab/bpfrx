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
	"github.com/psaab/xpf/pkg/upgrade/lock"
	"github.com/psaab/xpf/pkg/upgrade/manifest"
	"github.com/psaab/xpf/pkg/upgrade/stagedgen"
)

// lockHandle is the host-wide advisory lock surface used by the upgrade
// runner. acquireUpgradeLock is indirected through a package var so tests
// can substitute a fake that records acquire/release ordering and can be
// forced busy (#1965). Production calls lock.Acquire.
type lockHandle interface{ Release() error }

var acquireUpgradeLock = func(subcommand, target string) (lockHandle, error) {
	return lock.Acquire(subcommand, target)
}

// Default filesystem layout (plan §6.1). Overridable in Config for tests.
const (
	DefaultStagedDir    = "/usr/local/share/xpf/staged"
	DefaultVersionsDir  = "/var/lib/xpf/versions"
	DefaultStagedGenDir = stagedgen.DefaultDir
	DefaultSbinDir      = "/usr/local/sbin"
	DefaultConfigDBDir  = "/etc/xpf/.configdb"
	DefaultJournalPath  = "/var/lib/xpf/upgrade.state"
	DefaultUnit         = "xpfd"

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
// in lockstep; cli and xpf-day0-config are operator tools. The list is
// derived from the single source of truth in pkg/upgrade/manifest (#1982) so
// the cut machine, the first-install seed, the maintainer scripts, and
// debian/rules can never silently drift (the manifest drift canary enforces
// the shell sites). manifest.Names returns a fresh slice, so package-level
// mutation here cannot leak back into the SSOT.
var managedBins = manifest.Names()

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
	// StagedGenDir is the staged-generation root (#1981 Option B). The cut
	// copies from staged-gen/<SourceGeneration>/ here, NEVER from live
	// StagedDir, closing the dpkg-unpack torn-read window.
	StagedGenDir string
	SbinDir      string
	ConfigDBDir  string
	JournalPath  string
	Unit         string

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
	if c.StagedGenDir == "" {
		c.StagedGenDir = DefaultStagedGenDir
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

// stagedGenConfig builds the staged-generation surface (#1981 Option B) wired
// to this runner's StagedDir + StagedGenDir + log sink.
func (r *Runner) stagedGenConfig() stagedgen.Config {
	return stagedgen.Config{
		StagedDir: r.cfg.StagedDir,
		Dir:       r.cfg.StagedGenDir,
		Logf:      r.cfg.Logf,
	}
}

// srcGenPath returns the path of the source-generation stamp inside
// versions/<ver>/ (#1981 B-P3b OPT1). It lives INSIDE the version dir so GC
// removes it with the dir (not a sibling dotfile).
func (r *Runner) srcGenPath(ver string) string {
	return filepath.Join(r.versionDir(ver), stagedgen.SrcGenFile)
}

// readSrcGen returns the source generation stamped into versions/<ver>/, or ""
// if the stamp is absent (a pre-#1981 version dir, or one mid-copy). A read
// error other than not-exist is reported.
func (r *Runner) readSrcGen(ver string) (string, error) {
	data, err := os.ReadFile(r.srcGenPath(ver))
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
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

// ReadJournalSourceGeneration returns the SourceGeneration recorded in the
// upgrade journal at path, or "" if the journal is absent, unparsable, or has
// no pinned generation. It is used by `xpfd publish-generation` to PROTECT a
// crashed/resumable cut's pinned generation from the publish GC (the journal
// is durable; the host-wide lock that would otherwise serialize the cut is NOT
// held across a crash).
//
// Both a missing journal AND a malformed (unparsable) one return ("", nil): a
// journal that does not parse cannot name a genid to protect, and this is a
// best-effort GC-protection seam (the cut's own gc(j) protects its source from
// the authoritative in-memory journal). Only a genuine READ error (I/O,
// permission) surfaces — that is worth logging, and the caller treats it as
// "no protection" without failing the publish. The returned genid is only ever
// used as a GC-protection key, never as a path, so the caller need not
// validate it.
func ReadJournalSourceGeneration(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("read upgrade journal: %w", err)
	}
	j := &Journal{}
	if uerr := json.Unmarshal(data, j); uerr != nil {
		// A malformed journal names no genid to protect; degrade to "no
		// protection" rather than surfacing an error a best-effort caller would
		// only log-and-ignore.
		return "", nil
	}
	return j.SourceGeneration, nil
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

	var createdDirs []string
	for _, e := range ents {
		target := filepath.Join(dst, e.rel)
		switch {
		case e.info.IsDir():
			if err := os.MkdirAll(target, 0755); err != nil {
				return "", fmt.Errorf("mkdir %s: %w", target, err)
			}
			// Preserve the SOURCE dir's permissions (MkdirAll applies the
			// umask and won't chmod an existing dir) so versions/<ver>/ is
			// not silently restricted to 0700 under a tight operator umask,
			// which would break non-root execution of cli/etc. via the sbin
			// links (AGY review-011 r2; parity with pkg/upgrade/runtime).
			if err := os.Chmod(target, preservedMode(e.info.Mode())); err != nil {
				return "", fmt.Errorf("chmod %s: %w", target, err)
			}
			createdDirs = append(createdDirs, target)
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
	// Fsync every copied directory. copyFileFsync commits file *contents*, but
	// a newly-created directory entry (a file or a nested subdir) is durable
	// only once its parent directory fd is fsynced. Callers fsync only the
	// top-level copy root (SyncDir(partial)/SyncDir(snapPartial)); nested dirs
	// are NOT covered there, so a power loss after the atomic rename could
	// orphan nested entries and a later rollback would restore a corrupt
	// snapshot. Latent today (.configdb and staged are both flat — AGY
	// review-011 Part I) but this makes copyTree durable for any future
	// nesting.
	if err := fsyncDirsDeepestFirst(createdDirs); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// copyTreeSyncDir is the directory-fsync primitive used by
// fsyncDirsDeepestFirst. It is a package var so tests can substitute a
// recorder and prove copyTree actually fsyncs each copied directory (and in
// deepest-first order, and that an error propagates) — otherwise deleting the
// fsync loop would not fail any test (Codex/Copilot r1).
var copyTreeSyncDir = fsatomic.SyncDir

// fsyncDirsDeepestFirst fsyncs each directory deepest-first (by path-component
// depth, NOT string length — a deeper path can be shorter, Copilot r1) so a
// child dir's entries are committed before the parent dir entry that
// references it. Correctness does not depend on order (every dir is fsynced,
// so every dentry becomes durable); the ordering only tightens the crash
// window.
func fsyncDirsDeepestFirst(dirs []string) error {
	ordered := append([]string(nil), dirs...)
	sort.Slice(ordered, func(i, j int) bool {
		di := strings.Count(ordered[i], string(os.PathSeparator))
		dj := strings.Count(ordered[j], string(os.PathSeparator))
		if di != dj {
			return di > dj
		}
		return ordered[i] > ordered[j]
	})
	for _, d := range ordered {
		if err := copyTreeSyncDir(d); err != nil {
			return fmt.Errorf("fsync copied dir %s: %w", d, err)
		}
	}
	return nil
}

// preservedMode returns the chmod-applicable mode bits of m: the rwx
// permission bits PLUS the setuid/setgid/sticky special bits. m.Perm() alone
// masks the special bits off (Copilot), so a setgid staged dir or setuid
// staged binary would lose those bits in versions/<ver>/. (Staged content is
// 0755 today, so this is forward-looking exactness, not a current bug.)
func preservedMode(m os.FileMode) os.FileMode {
	return m.Perm() | (m & (os.ModeSetuid | os.ModeSetgid | os.ModeSticky))
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
	// OpenFile applies the umask to the create mode; chmod to the exact
	// source mode (incl. setuid/setgid/sticky) so the staged binaries stay
	// 0755-executable through versions/<ver>/ regardless of the operator's
	// umask (AGY review-011 r2; preservedMode keeps special bits, Copilot).
	if err := out.Chmod(preservedMode(mode)); err != nil {
		out.Close()
		return fmt.Errorf("chmod %s: %w", dst, err)
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
//
// After removing any partial it fsyncs VersionsDir (#1967 C4): os.RemoveAll
// unlinks the directory entries but the parent-directory metadata change is
// not durable until the parent dir fd is fsynced. Without this a crash
// between the sweep and the later parent fsync (in copyStaged / preflight's
// snapshot path) could RESURRECT a stale `.partial` entry on remount — a
// torn copy a subsequent run would have to re-sweep. The fsync is gated on
// an actual removal so the common no-partials case costs nothing.
func (r *Runner) removeAllPartials() {
	entries, err := os.ReadDir(r.cfg.VersionsDir)
	if err != nil {
		return
	}
	removedAny := false
	for _, e := range entries {
		n := e.Name()
		if strings.HasPrefix(n, partialPrefix) && strings.HasSuffix(n, partialSuffix) {
			_ = os.RemoveAll(filepath.Join(r.cfg.VersionsDir, n))
			removedAny = true
		}
	}
	if removedAny {
		// Make the unlinks durable so they cannot be resurrected by a crash
		// before the next parent fsync (#1967 C4).
		if err := partialSweepSyncDir(r.cfg.VersionsDir); err != nil {
			r.logf("upgrade: WARN fsync versions dir after partial sweep: %v", err)
		}
	}
}

// partialSweepSyncDir is the directory-fsync primitive removeAllPartials uses
// to make a partial-dir unlink durable (#1967 C4). It is a package var so a
// test can substitute a recorder and prove the fsync actually fires after a
// partial is swept (and targets VersionsDir) — without the seam, deleting the
// fsync would not fail any test.
var partialSweepSyncDir = fsatomic.SyncDir
