// Package stagedgen implements Option B of #1981 — immutable, versioned
// publication of the dpkg-staged binary set into generation-keyed source
// directories, so the in-place-upgrade cut reads a WHOLE, single-generation
// source that dpkg is NOT actively rewriting.
//
// # The race this closes
//
// dpkg unpacks the managed binaries into the dpkg-owned staging path one file
// at a time (write `<bin>.dpkg-new`, rename over `<bin>`). Across an `apt
// upgrade` unpack window the staging dir therefore holds a MIX of old and new
// binaries. The legacy cut (`copyStaged`, pkg/upgrade) copied directly from
// that live staging dir, so a cut landing inside the unpack window could
// publish a `versions/<ver>` mixing binaries from two dpkg generations — a
// torn set whose verify-dataplane gate (xpfd+shim only) cannot detect a
// mismatched `xpf-userspace-dp`. See #1981 / docs/in-place-upgrade.md.
//
// # The mechanism (Option B)
//
// After a COMPLETE unpack (Debian Policy §6.7: `postinst configure` runs after
// all files are unpacked and the dpkg frontend lock serializes transactions),
// the postinst PUBLISHES the staged tree into an immutable, generation-keyed
// source directory:
//
//	staged-gen/<genid>/        # one immutable copy of the staged set
//	staged-gen/current-gen     # atomic symlink naming the latest generation
//
// The publish is `.partial` + atomic-rename + dir-fsync, then an atomic
// (temp-symlink + rename) repoint of `current-gen`. A crash before the dir
// rename leaves a `.partial` (pre-swept on the next publish); a crash after
// the dir rename but before the `current-gen` repoint leaves a
// complete-but-unreferenced generation (the prior `current-gen` stays valid,
// and the next publish re-publishes idempotently). There is NEVER a torn
// published generation and NEVER an absent `current-gen`.
//
// The cut then resolves `current-gen` ONCE at INIT, records the genid in its
// journal, and copies from the resolved `staged-gen/<genid>/` DIRECTORY (never
// re-reading the symlink, never reading live staged/) — so a concurrent
// publish cannot redirect an in-flight cut, and the copy is internally a
// single generation by construction.
//
// # Lifecycle ownership
//
// staged-gen/ is maintainer-script-managed runtime state under /var/lib/xpf/
// (a sibling of versions/), NEVER a dpkg payload file — so dpkg never writes
// or removes it on unpack (it only touches its own recorded payload files).
// The postrm removes it on purge and on a downgrade to a pre-B package.
//
// # GC
//
// GC mirrors the versions/ GC shape but with a SMALLER retention (N=2:
// current + 1 prior). Unlike versions/ (which backs binary+DB rollback to N
// prior versions), staged-gen/ is only ever a CUT SOURCE: once superseded by a
// newer current-gen an older generation is never read again. GC protects
// current-gen AND any genid an active/resumable journal still references
// (the caller supplies the protected genid set), and sweeps .partial orphans.
package stagedgen

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/psaab/xpf/pkg/fsatomic"
	"github.com/psaab/xpf/pkg/upgrade/manifest"
)

const (
	// DirName is the staged-generation root, a sibling of versions/ under
	// /var/lib/xpf. The default absolute path is DefaultDir; tests override
	// via Config.Dir.
	DirName = "staged-gen"

	// DefaultDir is the production staged-generation root.
	DefaultDir = "/var/lib/xpf/" + DirName

	// CurrentGenLink is the atomic symlink naming the latest complete
	// generation, mirroring versions/current.
	CurrentGenLink = "current-gen"

	// SrcGenFile is the dotfile stamped INSIDE versions/<ver>/ recording the
	// source generation a version dir was cut from (B-P3b OPT1 identity
	// stamp). It lives inside the version dir so GC removes it with the dir.
	SrcGenFile = ".srcgen"

	// RetainGenerations is N in the staged-gen retention policy: keep the
	// current generation + 1 prior. Smaller than versions/ N=3 because a
	// superseded generation is never read again (B-P5 / plan §4.B.5).
	RetainGenerations = 2

	partialSuffix = ".partial"
)

// Config configures publish / resolve / GC against a staged-generation root.
// Zero values fall back to the production layout.
type Config struct {
	// StagedDir is the dpkg-owned staging path to publish FROM (the source).
	StagedDir string
	// Dir is the staged-generation root to publish INTO. Defaults to
	// DefaultDir.
	Dir string
	// Logf is an optional progress sink (defaults to no-op).
	Logf func(format string, args ...any)
}

func (c *Config) withDefaults() {
	if c.Dir == "" {
		c.Dir = DefaultDir
	}
	if c.Logf == nil {
		c.Logf = func(string, ...any) {}
	}
}

// GenID returns a fresh generation identifier: a monotonic nanosecond
// timestamp (zero-padded so lexicographic order matches chronological order)
// joined with a random suffix. The timestamp keeps mtime-independent ordering
// stable; the random suffix makes a same-version reinstall (or two publishes
// in the same nanosecond) yield DISTINCT generations (plan B-P5). The result
// is a safe single path segment (lowercase hex + a single '-').
func GenID() string {
	var b [8]byte
	// crypto/rand never fails on Linux; if it ever did, fall back to a
	// time-only suffix so the genid is still unique-enough and a publish is
	// never blocked on entropy.
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%020d-%016x", time.Now().UnixNano(), time.Now().UnixNano())
	}
	return fmt.Sprintf("%020d-%s", time.Now().UnixNano(), hex.EncodeToString(b[:]))
}

// ValidGenID reports whether s is a syntactically valid generation id (the
// shape GenID produces): non-empty, not current-gen, no '.' prefix (so it can
// never collide with the current-gen temp file or a .partial), no path
// separators or "..", and only lowercase-hex + a single '-'. A resolved genid
// keys staged-gen/<genid>, so it MUST be a safe single path segment before any
// path use.
func ValidGenID(s string) bool {
	if s == "" || s == CurrentGenLink {
		return false
	}
	if strings.HasPrefix(s, ".") {
		return false
	}
	if strings.ContainsAny(s, "/\x00") {
		return false
	}
	if strings.Contains(s, "..") {
		return false
	}
	dashes := 0
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f':
		case r == '-':
			dashes++
		default:
			return false
		}
	}
	return dashes == 1
}

func (c Config) logf(format string, args ...any) { c.Logf(format, args...) }

// genDir returns the directory for a generation id.
func (c Config) genDir(genid string) string { return filepath.Join(c.Dir, genid) }

// currentGenPath returns the path of the current-gen symlink.
func (c Config) currentGenPath() string { return filepath.Join(c.Dir, CurrentGenLink) }

// Publish copies the staged set into a fresh, immutable staged-gen/<genid>/
// and atomically repoints current-gen at it. It returns the new genid.
//
// Steps (each crash-safe; plan B-P2):
//  1. pre-sweep stale staged-gen/*.partial (a crashed prior publish must not
//     accumulate half-copies that exhaust /var — B-P2b);
//  2. copy staged/* -> staged-gen/<genid>.partial (durable per-file fsync);
//  3. fsync the .partial, atomic-rename to staged-gen/<genid>, fsync Dir;
//  4. repoint current-gen -> <genid> via temp-symlink + rename + dir-fsync.
//
// The caller is responsible for holding the host-wide upgrade lock (the
// postinst path serializes publish against an operator cut so GC cannot
// delete a generation a cut is reading). Publish does NOT take the lock
// itself so it composes with a caller that already holds it.
func (c Config) Publish() (genid string, err error) {
	c.withDefaults()
	if c.StagedDir == "" {
		return "", fmt.Errorf("stagedgen: StagedDir is required")
	}
	if err := fsatomic.MkdirAllDurable(c.Dir, 0o755); err != nil {
		return "", fmt.Errorf("stagedgen: create %s: %w", c.Dir, err)
	}

	// 1. Pre-sweep stale .partial dirs (B-P2b): a crashed prior publish leaves
	// a half-copy that would otherwise leak /var space until the next GC.
	c.sweepPartials()

	genid = GenID()
	// Defensive: GenID is internal, but a path is keyed by it, so validate.
	if !ValidGenID(genid) {
		return "", fmt.Errorf("stagedgen: generated an invalid genid %q (bug)", genid)
	}

	finalDir := c.genDir(genid)
	partial := finalDir + partialSuffix

	// 2. Copy staged/* -> <genid>.partial.
	_ = os.RemoveAll(partial)
	if err := copyTreeFsync(c.StagedDir, partial); err != nil {
		_ = os.RemoveAll(partial)
		return "", fmt.Errorf("stagedgen: copy staged -> %s: %w", partial, err)
	}
	// 3. Make the .partial contents durable, then atomic-rename it into place.
	if err := fsatomic.SyncDir(partial); err != nil {
		_ = os.RemoveAll(partial)
		return "", fmt.Errorf("stagedgen: fsync partial: %w", err)
	}
	if err := os.Rename(partial, finalDir); err != nil {
		_ = os.RemoveAll(partial)
		return "", fmt.Errorf("stagedgen: atomic rename %s -> %s: %w", partial, finalDir, err)
	}
	if err := fsatomic.SyncDir(c.Dir); err != nil {
		return "", fmt.Errorf("stagedgen: fsync %s after rename: %w", c.Dir, err)
	}

	// 4. Atomically repoint current-gen -> <genid>. A crash before this leaves
	// the prior current-gen valid (the new gen dir is complete but
	// unreferenced; a re-publish is idempotent, and the GC's protected set
	// keeps the dir from being prematurely reaped if a journal references it).
	if err := atomicRelSymlink(c.currentGenPath(), genid); err != nil {
		return "", fmt.Errorf("stagedgen: repoint current-gen -> %s: %w", genid, err)
	}
	c.logf("stagedgen: published generation %s (current-gen -> %s)", genid, genid)
	return genid, nil
}

// ResolveCurrent reads the current-gen symlink and returns the genid it names,
// validated as a safe single path segment. It returns ("", nil) when
// current-gen is absent (no generation published yet — the cut refuses with no
// source). A current-gen present but naming an unsafe / missing generation is
// an error (a corrupt layout must not key a path off it).
func (c Config) ResolveCurrent() (string, error) {
	c.withDefaults()
	target, err := os.Readlink(c.currentGenPath())
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("stagedgen: read current-gen: %w", err)
	}
	genid := filepath.Base(target)
	if !ValidGenID(genid) {
		return "", fmt.Errorf("stagedgen: current-gen names an unsafe generation %q", genid)
	}
	// The dir MUST exist — current-gen is only repointed AFTER the gen dir is
	// renamed into place, so a dangling current-gen is a corrupt layout.
	if fi, serr := os.Stat(c.genDir(genid)); serr != nil || !fi.IsDir() {
		return "", fmt.Errorf("stagedgen: current-gen -> %s but %s is missing or not a directory",
			genid, c.genDir(genid))
	}
	return genid, nil
}

// GenDir returns the absolute path of a published generation directory. The
// caller MUST have validated genid (via ValidGenID) before use; this is the
// directory the cut copies FROM.
func (c Config) GenDir(genid string) string {
	c.withDefaults()
	return c.genDir(genid)
}

// GC removes generation dirs beyond RetainGenerations (current + 1 prior),
// NEVER removing the current-gen generation NOR any genid in protected (the
// generations an active/resumable journal still references — plan §4.B.5 /
// B-P3 GC-vs-resume protection). It also sweeps .partial orphans. A missing
// staged-gen root is a no-op.
func (c Config) GC(protected map[string]bool) error {
	c.withDefaults()
	c.sweepPartials()

	entries, err := os.ReadDir(c.Dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("stagedgen: read %s: %w", c.Dir, err)
	}

	// The caller's `protected` set (journal-referenced generations) is kept
	// ADDITIVELY — outside and on top of the RetainGenerations window — so a
	// journal-pinned OLD generation never pushes the immediate-prior-to-current
	// generation out of the window (Copilot). The current generation is NOT in
	// this additive set: it is naturally the newest and counts toward the
	// window (RetainGenerations = current + N-1 prior).
	extraProtected := map[string]bool{}
	for g := range protected {
		extraProtected[g] = true
	}

	type gen struct {
		name string
		mod  int64
	}
	var gens []gen
	for _, e := range entries {
		n := e.Name()
		if n == CurrentGenLink {
			continue
		}
		if strings.HasPrefix(n, ".") { // .partial, temp symlinks
			continue
		}
		if !e.IsDir() {
			continue
		}
		info, ierr := e.Info()
		if ierr != nil {
			continue
		}
		gens = append(gens, gen{name: n, mod: info.ModTime().UnixNano()})
	}
	// Newest first.
	sort.Slice(gens, func(i, j int) bool { return gens[i].mod > gens[j].mod })

	kept := 0
	removedAny := false
	for _, g := range gens {
		// The RetainGenerations newest generations form the window (current-gen
		// is naturally among them as the newest).
		if kept < RetainGenerations {
			kept++
			continue
		}
		// Outside the window: keep ONLY if journal-referenced (additive
		// protection — never reap a generation a resumable cut still pins).
		if extraProtected[g.name] {
			continue
		}
		c.logf("stagedgen: gc removing old generation %s", g.name)
		if rerr := os.RemoveAll(c.genDir(g.name)); rerr != nil {
			c.logf("stagedgen: WARN gc remove %s: %v", g.name, rerr)
			continue
		}
		removedAny = true
	}
	if removedAny {
		if serr := fsatomic.SyncDir(c.Dir); serr != nil {
			c.logf("stagedgen: WARN fsync %s after gc: %v", c.Dir, serr)
		}
	}
	return nil
}

// RemoveAll removes the entire staged-generation root (postrm purge / pre-B
// downgrade cleanup, B-P6). Best-effort; a missing root is a no-op.
func (c Config) RemoveAll() error {
	c.withDefaults()
	if err := os.RemoveAll(c.Dir); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("stagedgen: remove %s: %w", c.Dir, err)
	}
	return nil
}

// sweepPartials removes any staged-gen/*.partial dirs (a crashed publish), and
// fsyncs Dir if it removed anything so the unlink cannot be resurrected.
func (c Config) sweepPartials() {
	entries, err := os.ReadDir(c.Dir)
	if err != nil {
		return
	}
	removedAny := false
	for _, e := range entries {
		n := e.Name()
		if strings.HasSuffix(n, partialSuffix) {
			_ = os.RemoveAll(filepath.Join(c.Dir, n))
			removedAny = true
		}
	}
	if removedAny {
		if serr := fsatomic.SyncDir(c.Dir); serr != nil {
			c.logf("stagedgen: WARN fsync %s after partial sweep: %v", c.Dir, serr)
		}
	}
}

// ManagedNames returns the managed-binary basenames a published generation
// contains. Exposed so the cut and tests share the SSOT list.
func ManagedNames() []string { return manifest.Names() }
