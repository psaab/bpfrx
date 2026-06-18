// Package runtime owns the FIRST-INSTALL seeding of the versioned runtime
// layout (#1964 mechanism A). On the very first `.deb` install there is no
// versioned rollback target, so the first or legacy-migration upgrade had
// PreviousVersion=="" and the cut hard-refused (or, worse, stopped a daemon
// it could not roll back). Seeding a real, immutable rollback target at
// install time closes that gap.
//
// Layout contract (plan §4): versions/<ver>/ and the `current` symlink are
// runtime state OWNED BY MAINTAINER SCRIPTS, never in dpkg's file list, so
// dpkg never clobbers a versioned rollback target. dpkg only ever writes
// /usr/local/share/xpf/staged/. After seeding, /usr/local/sbin/* resolve
// THROUGH versions/current.
//
// Seed runs from the .deb postinst on FIRST install ($2 empty), AFTER unpack
// (so the new binaries are on disk and runnable) but BEFORE #DEBHELPER#
// starts the unit — there is NO cut/verify/stop at install. The legacy
// upgrade-migration of a pre-fix host is a DIFFERENT mechanism (B), and is
// self-contained shell in debian/xpf.preinst because preinst runs BEFORE
// unpack, when the new xpfd binary is not yet on disk.
//
// Crash-safety: Seed is idempotent. A copy uses a .partial dir + atomic
// rename; the `current` symlink and each sbin link are repointed atomically
// (temp symlink + rename). A crash at any point re-runs Seed (postinst is
// re-run by apt) and converges to the same fully-seeded state without
// snapshotting a different version.
package runtime

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/fsatomic"
	"github.com/psaab/xpf/pkg/upgrade"
)

// Default layout, shared with pkg/upgrade. Overridable in Config for tests.
const (
	defaultStagedDir   = "/usr/local/share/xpf/staged"
	defaultVersionsDir = "/var/lib/xpf/versions"
	defaultSbinDir     = "/usr/local/sbin"

	currentLink = "current"
)

// managedBins are the binaries copied into the version dir and linked from
// /usr/local/sbin. Kept in lockstep with upgrade.managedBins (xpfd and
// xpf-userspace-dp are the matched cut set; cli + xpf-day0-config are
// operator tools). Defined here too because upgrade.managedBins is
// unexported.
var managedBins = []string{"xpfd", "cli", "xpf-userspace-dp", "xpf-day0-config"}

// Config configures a Seed. Zero values fall back to the production layout.
type Config struct {
	StagedDir   string
	VersionsDir string
	SbinDir     string

	// Logf is an optional progress sink (defaults to no-op).
	Logf func(format string, args ...any)

	// version, when non-empty, overrides the version read from
	// `staged/xpfd version` (tests). Production leaves it empty.
	version string
}

func (c *Config) withDefaults() {
	if c.StagedDir == "" {
		c.StagedDir = defaultStagedDir
	}
	if c.VersionsDir == "" {
		c.VersionsDir = defaultVersionsDir
	}
	if c.SbinDir == "" {
		c.SbinDir = defaultSbinDir
	}
	if c.Logf == nil {
		c.Logf = func(string, ...any) {}
	}
}

// Seed performs the first-install seeding (mechanism A). It is safe to call
// when the layout is already (partially or fully) seeded: it never
// snapshots a different version, never clobbers an existing version dir, and
// always (idempotently) ensures `current` and the sbin links resolve
// through versions/<ver>.
//
// Steps (each idempotent and crash-safe):
//  1. read the staged version (validated as a safe single path segment).
//  2. copy staged/* -> versions/<ver>/ via a .partial dir + atomic rename
//     (skip if versions/<ver> already exists — a prior seed crashed after
//     the rename).
//  3. repoint versions/current -> <ver> (atomic).
//  4. repoint /usr/local/sbin/<bin> -> versions/current/<bin> (atomic).
func Seed(cfg Config) (err error) {
	cfg.withDefaults()
	logf := cfg.Logf

	ver := cfg.version
	if ver == "" {
		ver, err = stagedVersion(cfg.StagedDir)
		if err != nil {
			return fmt.Errorf("seed: read staged version: %w", err)
		}
	}
	if verr := upgrade.ValidateVersionSegment(ver); verr != nil {
		return fmt.Errorf("seed: staged version is not a safe path segment: %w", verr)
	}

	if err := fsatomic.MkdirAllDurable(cfg.VersionsDir, 0o755); err != nil {
		return fmt.Errorf("seed: create versions dir: %w", err)
	}

	verDir := filepath.Join(cfg.VersionsDir, ver)
	if fi, statErr := os.Stat(verDir); statErr == nil {
		// An existing versions/<ver> is treated as a completed prior copy and
		// the copy is skipped (resume-after-crash). But a NON-directory entry
		// there (corruption / manual edit) would make `current` and the sbin
		// links resolve to a broken launch path. Fail seeding so the postinst
		// falls back to legacy direct-staged links rather than leaving the
		// daemon unlaunchable (Copilot).
		if !fi.IsDir() {
			return fmt.Errorf("seed: %s exists but is not a directory (corrupt "+
				"runtime layout); refusing to seed through it", verDir)
		}
		logf("seed: version dir %s already present; skipping copy", verDir)
	} else if !os.IsNotExist(statErr) {
		return fmt.Errorf("seed: stat version dir: %w", statErr)
	} else {
		if err := copyStagedToVersion(cfg.StagedDir, cfg.VersionsDir, verDir); err != nil {
			return err
		}
	}

	// 3. current -> <ver> (relative within VersionsDir). Always run: a crash
	//    after the copy but before the symlink must still complete on retry.
	if err := atomicRelSymlink(filepath.Join(cfg.VersionsDir, currentLink), ver); err != nil {
		return fmt.Errorf("seed: repoint current -> %s: %w", ver, err)
	}

	// 4. sbin/<bin> -> versions/current/<bin> (absolute). Always run for the
	//    same crash-safety reason. Pointing through `current` (not the
	//    concrete version dir) matches the cut-over flip layout so a later
	//    upgrade's flip is a no-op-shaped repoint of the same link.
	if err := fsatomic.MkdirAllDurable(cfg.SbinDir, 0o755); err != nil {
		return fmt.Errorf("seed: create sbin dir: %w", err)
	}
	for _, b := range managedBins {
		link := filepath.Join(cfg.SbinDir, b)
		target := filepath.Join(cfg.VersionsDir, currentLink, b)
		if err := atomicAbsSymlink(link, target); err != nil {
			return fmt.Errorf("seed: repoint sbin %s: %w", b, err)
		}
	}
	logf("seed: seeded versioned runtime %s (current + sbin resolve through versions/)", ver)
	return nil
}

// copyStagedToVersion copies staged/* into a .partial dir, fsyncs, and
// atomically renames to verDir. A leftover .partial from a prior crash is
// removed first.
func copyStagedToVersion(stagedDir, versionsDir, verDir string) error {
	partial := verDir + ".partial"
	_ = os.RemoveAll(partial)
	if err := copyTreeFsync(stagedDir, partial); err != nil {
		_ = os.RemoveAll(partial)
		return fmt.Errorf("seed: copy staged -> partial: %w", err)
	}
	if err := fsatomic.SyncDir(partial); err != nil {
		_ = os.RemoveAll(partial)
		return fmt.Errorf("seed: fsync partial: %w", err)
	}
	if err := os.Rename(partial, verDir); err != nil {
		_ = os.RemoveAll(partial)
		return fmt.Errorf("seed: atomic rename partial -> version dir: %w", err)
	}
	if err := fsatomic.SyncDir(versionsDir); err != nil {
		return fmt.Errorf("seed: fsync versions dir after rename: %w", err)
	}
	return nil
}

// stagedVersion runs `<staged>/xpfd version` and returns the version token.
// Output shape: "xpfd <version> (commit <c>, built <t>)".
func stagedVersion(stagedDir string) (string, error) {
	bin := filepath.Join(stagedDir, "xpfd")
	out, err := exec.Command(bin, "version").Output()
	if err != nil {
		return "", fmt.Errorf("%s version: %w", bin, err)
	}
	fields := strings.Fields(string(out))
	if len(fields) >= 2 && fields[0] == "xpfd" {
		return fields[1], nil
	}
	return strings.TrimSpace(string(out)), nil
}

// atomicRelSymlink atomically points link at a RELATIVE target (basename in
// the same dir, e.g. current -> <ver>) via temp+rename, then fsyncs the dir.
func atomicRelSymlink(link, relTarget string) error {
	return atomicSymlink(link, relTarget)
}

// atomicAbsSymlink atomically points link at an ABSOLUTE target.
func atomicAbsSymlink(link, absTarget string) error {
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		return err
	}
	return atomicSymlink(link, absTarget)
}

func atomicSymlink(link, target string) error {
	dir := filepath.Dir(link)
	tmp := filepath.Join(dir, "."+filepath.Base(link)+".tmp")
	_ = os.Remove(tmp)
	if err := os.Symlink(target, tmp); err != nil {
		return fmt.Errorf("create temp symlink: %w", err)
	}
	if err := os.Rename(tmp, link); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename symlink into place: %w", err)
	}
	if err := fsatomic.SyncDir(dir); err != nil {
		return fmt.Errorf("fsync symlink dir: %w", err)
	}
	return nil
}

// copyTreeFsync recursively copies src into dst (which must not exist),
// preserving file modes and fsyncing each file. Mirrors upgrade.copyTree's
// durability without the checksum (Seed re-runs idempotently; there is no
// torn-source race at install — dpkg has finished unpacking staged/ before
// the postinst configure step runs).
func copyTreeFsync(src, dst string) error {
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
		return err
	}
	sort.Slice(ents, func(i, j int) bool { return ents[i].rel < ents[j].rel })

	var createdDirs []string
	for _, e := range ents {
		target := filepath.Join(dst, e.rel)
		switch {
		case e.info.IsDir():
			if err := os.MkdirAll(target, 0o755); err != nil {
				return fmt.Errorf("mkdir %s: %w", target, err)
			}
			// Preserve the SOURCE dir's permissions (MkdirAll applies the
			// umask and won't chmod an existing dir, so set it explicitly) —
			// otherwise versions/<ver>/ could end up more permissive than
			// staged/ for a non-0755 staged subdir. preservedMode keeps the
			// setuid/setgid/sticky bits too (Copilot).
			if err := os.Chmod(target, preservedMode(e.info.Mode())); err != nil {
				return fmt.Errorf("chmod %s: %w", target, err)
			}
			createdDirs = append(createdDirs, target)
		case e.info.Mode().IsRegular():
			if err := copyFileFsync(e.path, target, e.info.Mode()); err != nil {
				return err
			}
		default:
			return fmt.Errorf("copyTreeFsync: unsupported file type for %s", e.path)
		}
	}
	// Fsync created dirs deepest-first so a child's entries are durable
	// before the parent entry referencing it.
	sort.Slice(createdDirs, func(i, j int) bool {
		di := strings.Count(createdDirs[i], string(os.PathSeparator))
		dj := strings.Count(createdDirs[j], string(os.PathSeparator))
		if di != dj {
			return di > dj
		}
		return createdDirs[i] > createdDirs[j]
	})
	for _, d := range createdDirs {
		if err := fsatomic.SyncDir(d); err != nil {
			return fmt.Errorf("fsync copied dir %s: %w", d, err)
		}
	}
	return nil
}

// preservedMode returns the chmod-applicable mode bits of m: the rwx
// permission bits PLUS setuid/setgid/sticky. m.Perm() alone masks the
// special bits off (Copilot). Staged content is 0755 today, so this is
// forward-looking exactness rather than a current bug.
func preservedMode(m os.FileMode) os.FileMode {
	return m.Perm() | (m & (os.ModeSetuid | os.ModeSetgid | os.ModeSticky))
}

func copyFileFsync(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open %s: %w", src, err)
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return fmt.Errorf("create %s: %w", dst, err)
	}
	// OpenFile applies the umask to the create mode, so chmod to the exact
	// source mode — the staged binaries are 0755 and must stay executable
	// through versions/<ver>/ regardless of the installing process's umask.
	// preservedMode keeps any setuid/setgid/sticky bits too (Copilot).
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
