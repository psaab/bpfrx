package upgrade

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/fsatomic"
)

// unitDropinName is the drop-in file basename written under
// /etc/systemd/system/<unit>.service.d/ to pin ExecStart to the concrete
// versioned path.
const unitDropinName = "10-xpf-version.conf"

// flip performs the three journaled-idempotent FLIP substeps (plan §6.1
// step 6 / §8 inv. 2). All three are DERIVED from ver so a crash between
// substeps re-runs idempotently to the same target:
//
//	6a. repoint versions/current -> <ver> (atomic symlink rename)
//	6b. repoint /usr/local/sbin/<bin> -> versions/current/<bin>
//	6c. template the xpfd unit ExecStart/ExecStartPre to the CONCRETE
//	    versions/<ver>/xpfd path + daemon-reload
//
// 6c uses the concrete versioned path (NOT the `current` symlink) because
// systemd does NOT symlink-resolve argv[0]: a symlink ExecStart would
// leave dir(os.Args[0]) = /usr/local/sbin and a helper respawn would grab
// the flipped /usr/local/sbin/xpf-userspace-dp. Pinning the version dir
// makes dir(os.Args[0]) the matching-version dir.
func (r *Runner) flip(ver string) error {
	// 6a: current -> <ver>
	if err := r.repointSymlink(r.currentPath(), ver); err != nil {
		return fmt.Errorf("flip current symlink: %w", err)
	}
	// 6b: /usr/local/sbin/<bin> -> versions/current/<bin>
	for _, b := range managedBins {
		linkPath := filepath.Join(r.cfg.SbinDir, b)
		target := filepath.Join(r.cfg.VersionsDir, currentLink, b)
		if err := r.repointSymlinkAbs(linkPath, target); err != nil {
			return fmt.Errorf("flip sbin link %s: %w", b, err)
		}
	}
	// 6c: unit ExecStart pinned to the concrete version path.
	if err := r.writeUnitDropin(ver); err != nil {
		return fmt.Errorf("template unit ExecStart: %w", err)
	}
	if err := r.cfg.Sys.DaemonReload(); err != nil {
		return fmt.Errorf("daemon-reload after unit template: %w", err)
	}
	return nil
}

// repointSymlink atomically points linkPath at a RELATIVE target (basename
// within the same dir, e.g. current -> <ver>). Atomic via temp+rename.
func (r *Runner) repointSymlink(linkPath, relTarget string) error {
	dir := filepath.Dir(linkPath)
	tmp := filepath.Join(dir, "."+filepath.Base(linkPath)+".tmp")
	_ = os.Remove(tmp)
	if err := os.Symlink(relTarget, tmp); err != nil {
		return fmt.Errorf("create temp symlink: %w", err)
	}
	if err := os.Rename(tmp, linkPath); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename symlink into place: %w", err)
	}
	if err := fsatomic.SyncDir(dir); err != nil {
		return fmt.Errorf("fsync symlink dir: %w", err)
	}
	return nil
}

// repointSymlinkAbs atomically points linkPath at an ABSOLUTE target.
func (r *Runner) repointSymlinkAbs(linkPath, absTarget string) error {
	dir := filepath.Dir(linkPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	tmp := filepath.Join(dir, "."+filepath.Base(linkPath)+".tmp")
	_ = os.Remove(tmp)
	if err := os.Symlink(absTarget, tmp); err != nil {
		return fmt.Errorf("create temp symlink: %w", err)
	}
	if err := os.Rename(tmp, linkPath); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename symlink into place: %w", err)
	}
	if err := fsatomic.SyncDir(dir); err != nil {
		return fmt.Errorf("fsync symlink dir: %w", err)
	}
	return nil
}

// writeUnitDropin templates the xpfd unit ExecStart/ExecStartPre to the
// concrete versioned path.
func (r *Runner) writeUnitDropin(ver string) error {
	xpfd := filepath.Join(r.versionDir(ver), "xpfd")
	content := fmt.Sprintf(`# Managed by xpf-upgrade (#1917 increment B). Pins ExecStart to the
# concrete versioned binary so a helper respawn resolves the matching
# version's xpf-userspace-dp (systemd does not symlink-resolve argv[0]).
[Service]
ExecStartPre=
ExecStartPre=%s verify-dataplane
ExecStart=
ExecStart=%s
`, xpfd, xpfd)
	return r.cfg.Sys.WriteUnitDropin(r.cfg.Unit, unitDropinName, content)
}

// rollback performs binary+DB-atomic rollback to the previous version
// (standalone auto-rollback, plan §6.4). Order is mandatory:
//
//  1. stop the (failed) new daemon
//  2. restore the config DB from the PREFLIGHT snapshot (so the old
//     binary never boots against a too-new envelope DB and fatal-rejects)
//  3. re-flip current/sbin/unit back to the previous version
//  4. start the old daemon
//
// If there is no previous version (first cut) or no DB snapshot, rollback
// is best-effort and surfaces a clear error.
func (r *Runner) rollback(j *Journal) error {
	if j.PreviousVersion == "" {
		return fmt.Errorf("no previous version to roll back to (first cut); the new "+
			"version %s is unhealthy and there is no prior runtime version — "+
			"operator intervention required", j.TargetVersion)
	}
	// Journal the rollback so a crash mid-rollback resumes the rollback,
	// NOT the failed forward cut. Codex r1 Critical#1: an auto-rollback
	// that re-flips to PreviousVersion but leaves the journal at FLIPPED
	// (target=failed) would let a re-run resume at START for the FAILED
	// target and mark it COMMITTED. We retarget the journal to the
	// previous version and mark the state ROLLINGBACK; on terminal success
	// the journal is CLEARED (the failed cut is abandoned — the operator
	// re-stages to retry).
	j.State = StateRollingBack
	if err := r.saveJournal(j); err != nil {
		return fmt.Errorf("rollback: journal rollback intent: %w", err)
	}

	// 1. stop the failed new daemon.
	if err := r.cfg.Sys.StopUnit(r.cfg.Unit); err != nil {
		return fmt.Errorf("rollback: stop failed new daemon: %w", err)
	}
	// 2. restore the DB BEFORE re-flipping the binary.
	if j.AdvancedStateFloor && j.DBSnapshotPath != "" {
		if err := r.restoreDBSnapshot(j.DBSnapshotPath); err != nil {
			return fmt.Errorf("rollback: restore config DB snapshot: %w", err)
		}
		r.logf("upgrade: rollback restored config DB from %s", j.DBSnapshotPath)
	}
	// 3. re-flip to the previous version.
	if err := r.flip(j.PreviousVersion); err != nil {
		return fmt.Errorf("rollback: re-flip to previous version %s: %w", j.PreviousVersion, err)
	}
	// 4. start the old daemon.
	if err := r.cfg.Sys.StartUnit(r.cfg.Unit); err != nil {
		return fmt.Errorf("rollback: start previous daemon: %w", err)
	}
	// 5. Terminal: clear the journal. The previous version is live; the
	//    failed cut is abandoned. A re-run of `xpfd upgrade` starts fresh
	//    against whatever is now staged (it will not resume the failed
	//    target).
	return r.clearJournal()
}

// restoreDBSnapshot replaces the live config DB dir with the snapshot taken
// in PREFLIGHT, crash-safely. Strategy:
//
//  1. stage the snapshot into a sibling .restore.partial (copy+fsync);
//  2. if a leftover .old exists from a prior interrupted swap, the live
//     dir may be absent — recover by completing the swap first;
//  3. swap: move the (current) live dir to .old, then rename the staged
//     restore into place. If a crash lands between those two renames, the
//     live dir is absent BUT BOTH .old (the failed-new DB) AND
//     .restore.partial (the snapshot to install) exist on disk, so the
//     next rollback re-run completes the swap. A re-run NEVER finds the
//     live DB permanently destroyed.
func (r *Runner) restoreDBSnapshot(snapDir string) error {
	parent := filepath.Dir(r.cfg.ConfigDBDir)
	restore := r.cfg.ConfigDBDir + ".restore.partial"
	old := r.cfg.ConfigDBDir + ".old"

	// Recovery: a prior interrupted swap may have left ConfigDBDir absent
	// with .restore.partial already staged. If so, complete the install
	// from the staged restore without re-copying.
	_, liveErr := os.Stat(r.cfg.ConfigDBDir)
	_, restErr := os.Stat(restore)
	if os.IsNotExist(liveErr) && restErr == nil {
		if err := os.Rename(restore, r.cfg.ConfigDBDir); err != nil {
			return fmt.Errorf("complete interrupted DB restore swap: %w", err)
		}
		if err := fsatomic.SyncDir(parent); err != nil {
			return err
		}
		_ = os.RemoveAll(old)
		return nil
	}

	// Fresh stage of the snapshot.
	_ = os.RemoveAll(restore)
	if _, err := copyTree(snapDir, restore); err != nil {
		_ = os.RemoveAll(restore)
		return fmt.Errorf("stage DB restore copy: %w", err)
	}
	if err := fsatomic.SyncDir(restore); err != nil {
		_ = os.RemoveAll(restore)
		return err
	}
	if err := fsatomic.SyncDir(parent); err != nil { // make .restore.partial entry durable
		return err
	}

	// Swap. Both .old and .restore.partial are durable on disk before the
	// live dir is moved aside, so a crash between the two renames is
	// recoverable by the recovery branch above on re-run.
	_ = os.RemoveAll(old)
	if _, err := os.Stat(r.cfg.ConfigDBDir); err == nil {
		if err := os.Rename(r.cfg.ConfigDBDir, old); err != nil {
			return fmt.Errorf("move live DB aside: %w", err)
		}
	}
	if err := os.Rename(restore, r.cfg.ConfigDBDir); err != nil {
		// Put the live dir back.
		_ = os.Rename(old, r.cfg.ConfigDBDir)
		return fmt.Errorf("move restored DB into place: %w", err)
	}
	if err := fsatomic.SyncDir(parent); err != nil {
		return err
	}
	_ = os.RemoveAll(old)
	return nil
}

// gc removes version dirs beyond the N=3 retention, NEVER removing the
// running (current) version or its immediate predecessor (the rollback
// target), and removes orphaned DB snapshots for GC'd versions.
func (r *Runner) gc(j *Journal) error {
	entries, err := os.ReadDir(r.cfg.VersionsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	// Protected: current target + previous (rollback) version.
	protected := map[string]bool{}
	if j.TargetVersion != "" {
		protected[j.TargetVersion] = true
	}
	if j.PreviousVersion != "" {
		protected[j.PreviousVersion] = true
	}
	cur, _ := r.readCurrentVersion()
	if cur != "" {
		protected[cur] = true
	}

	type vdir struct {
		name string
		mod  int64
	}
	var versions []vdir
	for _, e := range entries {
		n := e.Name()
		if n == currentLink {
			continue
		}
		// Skip dotfiles (.partial, .dbsnap, temp symlinks).
		if len(n) > 0 && n[0] == '.' {
			continue
		}
		if !e.IsDir() {
			continue
		}
		info, ierr := e.Info()
		if ierr != nil {
			continue
		}
		versions = append(versions, vdir{name: n, mod: info.ModTime().UnixNano()})
	}
	// Newest first.
	sort.Slice(versions, func(i, j int) bool { return versions[i].mod > versions[j].mod })

	kept := 0
	for _, v := range versions {
		if protected[v.name] {
			kept++
			continue
		}
		if kept < retainVersions {
			kept++
			continue
		}
		r.logf("upgrade: gc removing old version %s", v.name)
		if err := os.RemoveAll(r.versionDir(v.name)); err != nil {
			r.logf("upgrade: WARN gc remove %s: %v", v.name, err)
		}
		// Remove its DB snapshot too, if any.
		_ = os.RemoveAll(filepath.Join(r.cfg.VersionsDir, "."+v.name+".dbsnap"))
	}

	// Sweep ORPHAN DB snapshots (AGY r2): a PREFLIGHT abort takes the
	// snapshot before the version dir exists, so a `.<ver>.dbsnap` can be
	// left with no matching version dir. Remove any `.<ver>.dbsnap` whose
	// base version is not protected (current/target/previous) and has no
	// surviving version dir.
	for _, e := range entries {
		n := e.Name()
		if !strings.HasPrefix(n, ".") || !strings.HasSuffix(n, ".dbsnap") {
			continue
		}
		ver := strings.TrimSuffix(strings.TrimPrefix(n, "."), ".dbsnap")
		if protected[ver] {
			continue
		}
		if _, err := os.Stat(r.versionDir(ver)); err == nil {
			continue // version dir survives; keep its snapshot
		}
		r.logf("upgrade: gc removing orphan DB snapshot %s", n)
		_ = os.RemoveAll(filepath.Join(r.cfg.VersionsDir, n))
	}
	return nil
}

// copyTreeChecksum recomputes the same sha256 stream copyTree produces,
// for a post-copy integrity re-check.
func copyTreeChecksum(dir string) (string, error) {
	h := sha256.New()
	type ent struct {
		rel  string
		path string
		reg  bool
	}
	var ents []ent
	err := filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(dir, p)
		if rerr != nil {
			return rerr
		}
		ents = append(ents, ent{rel: rel, path: p, reg: info.Mode().IsRegular()})
		return nil
	})
	if err != nil {
		return "", err
	}
	sort.Slice(ents, func(i, j int) bool { return ents[i].rel < ents[j].rel })
	for _, e := range ents {
		if !e.reg {
			continue
		}
		f, oerr := os.Open(e.path)
		if oerr != nil {
			return "", oerr
		}
		io.WriteString(h, e.rel+"\x00")
		if _, cerr := io.Copy(h, f); cerr != nil {
			f.Close()
			return "", cerr
		}
		f.Close()
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
