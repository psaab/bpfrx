package stagedgen

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/fsatomic"
)

// copyTreeFsync recursively copies src into dst (which must not exist),
// preserving file modes and fsyncing each file, then fsyncing each created
// directory deepest-first so a child's entries are durable before the parent
// entry referencing it. It mirrors the durability of pkg/upgrade.copyTree and
// pkg/upgrade/runtime.copyTreeFsync; stagedgen keeps its own copy so the
// package has no import cycle back into pkg/upgrade.
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
			// Preserve the SOURCE dir's mode (MkdirAll applies the umask and
			// won't chmod an existing dir) so a generation dir is not silently
			// restricted under a tight operator umask, which would break
			// non-root execution of the copied binaries.
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
	// Fsync created dirs deepest-first (by path-component depth, not string
	// length) so a child's entries are committed before the parent entry.
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
// permission bits PLUS setuid/setgid/sticky. m.Perm() alone masks the special
// bits off. Staged content is 0755 today, so this is forward-looking
// exactness rather than a current bug.
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
	// through the generation dir regardless of the installing process's umask.
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

// atomicRelSymlink atomically points link at a RELATIVE target (a basename in
// the same dir, e.g. current-gen -> <genid>) via temp+rename, then fsyncs the
// dir. NOT `ln -sf`, which unlink-then-creates and leaves a window where the
// link is absent (plan B-P2 / AGY r2-#1a).
func atomicRelSymlink(link, relTarget string) error {
	dir := filepath.Dir(link)
	tmp := filepath.Join(dir, "."+filepath.Base(link)+".tmp")
	// RemoveAll, not Remove: a stale directory at the temp path (manual
	// intervention / a previous failed run) would make os.Remove fail and the
	// subsequent Symlink fail EEXIST.
	_ = os.RemoveAll(tmp)
	if err := os.Symlink(relTarget, tmp); err != nil {
		return fmt.Errorf("create temp symlink: %w", err)
	}
	if err := os.Rename(tmp, link); err != nil {
		_ = os.RemoveAll(tmp)
		return fmt.Errorf("rename symlink into place: %w", err)
	}
	if err := fsatomic.SyncDir(dir); err != nil {
		return fmt.Errorf("fsync symlink dir: %w", err)
	}
	return nil
}
