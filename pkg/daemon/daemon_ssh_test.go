package daemon

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/fsatomic"
)

// TestBuildSSHDConfigKeyExchange verifies the H5 (#2008) ssh key-exchange
// leaf renders to an sshd KexAlgorithms line, that multiple methods are
// comma-joined, and that key-exchange renders independently of root-login.
func TestBuildSSHDConfigKeyExchange(t *testing.T) {
	tests := []struct {
		name string
		ssh  *config.SSHServiceConfig
		want []string // substrings that must be present
		not  []string // substrings that must be absent
		// empty=true means buildSSHDConfig must return ""
		empty bool
	}{
		{
			name:  "nil",
			ssh:   nil,
			empty: true,
		},
		{
			name:  "no-settings",
			ssh:   &config.SSHServiceConfig{},
			empty: true,
		},
		{
			name: "key-exchange-only",
			ssh:  &config.SSHServiceConfig{KeyExchange: []string{"ecdh-sha2-nistp256"}},
			want: []string{"KexAlgorithms ecdh-sha2-nistp256"},
			not:  []string{"PermitRootLogin"},
		},
		{
			name: "multiple-key-exchange-comma-joined",
			ssh: &config.SSHServiceConfig{KeyExchange: []string{
				"ecdh-sha2-nistp256", "curve25519-sha256",
			}},
			want: []string{"KexAlgorithms ecdh-sha2-nistp256,curve25519-sha256"},
		},
		{
			name: "root-login-and-key-exchange",
			ssh: &config.SSHServiceConfig{
				RootLogin:   "deny",
				KeyExchange: []string{"curve25519-sha256"},
			},
			want: []string{"PermitRootLogin no", "KexAlgorithms curve25519-sha256"},
		},
		{
			name: "root-login-only",
			ssh:  &config.SSHServiceConfig{RootLogin: "allow"},
			want: []string{"PermitRootLogin yes"},
			not:  []string{"KexAlgorithms"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildSSHDConfig(tt.ssh)
			if tt.empty {
				if got != "" {
					t.Fatalf("buildSSHDConfig = %q, want empty", got)
				}
				return
			}
			if got == "" {
				t.Fatalf("buildSSHDConfig = empty, want content")
			}
			for _, w := range tt.want {
				if !strings.Contains(got, w) {
					t.Errorf("output missing %q\ngot:\n%s", w, got)
				}
			}
			for _, n := range tt.not {
				if strings.Contains(got, n) {
					t.Errorf("output unexpectedly contains %q\ngot:\n%s", n, got)
				}
			}
		})
	}
}

// sshdSeamRecorder records the FS + reload effects driven through the
// applySSHConfig seam (#2062) and lets a test stub the in-memory drop-in
// contents and the reload result. The recorder backs the package-level
// sshd* function vars during a test and is restored on cleanup.
type sshdSeamRecorder struct {
	// present models the on-disk drop-in: nil == file absent.
	present []byte

	writes  [][]byte // each WriteFileAtomic payload, in order
	removed int      // number of successful Remove calls
	reloads int      // number of reload attempts
	writeN  int      // number of write attempts (including failed ones)

	// readErr, when set, makes sshdReadFile return (nil, readErr) even though
	// present is non-nil — models an existing-but-unreadable drop-in
	// (permission/IO error). Distinct from present==nil (truly absent).
	readErr error

	// reloadErr, when set, makes the NEXT reload fail; reloads after the
	// nth (failNthReload) succeed. failNthReload<=0 means every reload
	// returns reloadErr.
	reloadErr     error
	failNthReload int

	// writeErr, when set, makes the nth write (failNthWrite) fail; other
	// writes succeed. failNthWrite<=0 means every write returns writeErr.
	writeErr     error
	failNthWrite int
}

// installSSHDSeam swaps the package-level seam vars to route through the
// recorder and registers a t.Cleanup that restores the originals when the test
// ends.
func installSSHDSeam(t *testing.T, r *sshdSeamRecorder) {
	t.Helper()
	origPath := sshdConfPath
	origRead := sshdReadFile
	origWrite := sshdWriteFile
	origRemove := sshdRemoveFile
	origMkdir := sshdMkdirAll
	origReload := sshdReloadCmd

	sshdConfPath = "/test/sshd_config.d/xpf.conf"
	sshdReadFile = func(string) ([]byte, error) {
		if r.present == nil {
			return nil, os.ErrNotExist
		}
		// Existing file that cannot be read (permission/IO): present stays
		// non-nil but the read surfaces a non-NotExist error.
		if r.readErr != nil {
			return nil, r.readErr
		}
		// Return a copy so callers cannot mutate the backing store.
		return append([]byte(nil), r.present...), nil
	}
	sshdWriteFile = func(_ string, data []byte, _ os.FileMode, _ ...fsatomic.Option) error {
		r.writeN++
		if r.writeErr != nil && (r.failNthWrite <= 0 || r.writeN == r.failNthWrite) {
			return r.writeErr
		}
		cp := append([]byte(nil), data...)
		r.writes = append(r.writes, cp)
		r.present = cp
		return nil
	}
	sshdRemoveFile = func(string) error {
		if r.present == nil {
			return os.ErrNotExist
		}
		r.present = nil
		r.removed++
		return nil
	}
	sshdMkdirAll = func(string, os.FileMode) error { return nil }
	sshdReloadCmd = func() ([]byte, error) {
		r.reloads++
		if r.reloadErr != nil && (r.failNthReload <= 0 || r.reloads == r.failNthReload) {
			return []byte("bad config"), r.reloadErr
		}
		return nil, nil
	}

	t.Cleanup(func() {
		sshdConfPath = origPath
		sshdReadFile = origRead
		sshdWriteFile = origWrite
		sshdRemoveFile = origRemove
		sshdMkdirAll = origMkdir
		sshdReloadCmd = origReload
	})
}

func sshConfig(ssh *config.SSHServiceConfig) *config.Config {
	cfg := &config.Config{}
	if ssh != nil {
		cfg.System.Services = &config.SystemServicesConfig{SSH: ssh}
	}
	return cfg
}

// TestApplySSHConfig_RemoveOnConfigRemoved verifies that deleting the whole ssh
// stanza removes a previously-written drop-in and reloads sshd so it reverts to
// base-image defaults (#2062 gap 1). Fails pre-fix: the old applySSHConfig
// returned early on a nil ssh stanza, leaving the drop-in in place.
func TestApplySSHConfig_RemoveOnConfigRemoved(t *testing.T) {
	r := &sshdSeamRecorder{present: []byte("# Managed by xpf\nPermitRootLogin no\n")}
	installSSHDSeam(t, r)

	d := &Daemon{}
	d.applySSHConfig(sshConfig(nil)) // ssh stanza gone

	if r.present != nil {
		t.Fatalf("drop-in still present after config removed: %q", r.present)
	}
	if r.removed != 1 {
		t.Errorf("Remove called %d times, want 1", r.removed)
	}
	if r.reloads != 1 {
		t.Errorf("reload called %d times, want 1", r.reloads)
	}
	if len(r.writes) != 0 {
		t.Errorf("unexpected writes on removal: %v", r.writes)
	}
}

// TestApplySSHConfig_RemoveOnConfigEmptied verifies that an ssh stanza with no
// recognised leaves (buildSSHDConfig == "") removes the existing drop-in and
// reloads (#2062 gap 1). Fails pre-fix: the old code returned early when
// content=="" without touching the drop-in.
func TestApplySSHConfig_RemoveOnConfigEmptied(t *testing.T) {
	r := &sshdSeamRecorder{present: []byte("# Managed by xpf\nKexAlgorithms curve25519-sha256\n")}
	installSSHDSeam(t, r)

	d := &Daemon{}
	d.applySSHConfig(sshConfig(&config.SSHServiceConfig{})) // no leaves

	if r.present != nil {
		t.Fatalf("drop-in still present after config emptied: %q", r.present)
	}
	if r.removed != 1 {
		t.Errorf("Remove called %d times, want 1", r.removed)
	}
	if r.reloads != 1 {
		t.Errorf("reload called %d times, want 1", r.reloads)
	}
}

// TestApplySSHConfig_NoOpWhenEmptyAndAbsent verifies that an empty config with
// no existing drop-in does nothing: no remove, no reload (#2062). Fails if the
// remove/reload path runs unconditionally when content=="".
func TestApplySSHConfig_NoOpWhenEmptyAndAbsent(t *testing.T) {
	r := &sshdSeamRecorder{present: nil} // no drop-in on disk
	installSSHDSeam(t, r)

	d := &Daemon{}
	d.applySSHConfig(sshConfig(nil))

	if r.removed != 0 {
		t.Errorf("spurious Remove: %d", r.removed)
	}
	if r.reloads != 0 {
		t.Errorf("spurious reload: %d", r.reloads)
	}
	if len(r.writes) != 0 {
		t.Errorf("spurious writes: %v", r.writes)
	}
}

// TestApplySSHConfig_RevertOnReloadFailureWithPrior verifies that when the
// write succeeds but the reload fails, the drop-in is reverted to its PRIOR
// content rather than left as the bad new content (#2062 gap 2). Fails pre-fix:
// the old code logged the reload error and returned, leaving the bad new
// content on disk.
func TestApplySSHConfig_RevertOnReloadFailureWithPrior(t *testing.T) {
	priorContent := buildSSHDConfig(&config.SSHServiceConfig{RootLogin: "deny"})
	r := &sshdSeamRecorder{
		present:       []byte(priorContent),
		reloadErr:     errors.New("sshd: bad configuration"),
		failNthReload: 1, // first reload (post-write) fails; revert reload succeeds
	}
	installSSHDSeam(t, r)

	d := &Daemon{}
	// New config has a bad free-form key-exchange — write succeeds, reload fails.
	d.applySSHConfig(sshConfig(&config.SSHServiceConfig{
		RootLogin:   "deny",
		KeyExchange: []string{"bogus-kex-algorithm"},
	}))

	if r.present == nil {
		t.Fatalf("drop-in removed on reload failure but a prior existed; want prior restored")
	}
	if string(r.present) != priorContent {
		t.Fatalf("drop-in not reverted to prior content\n got: %q\nwant: %q", r.present, priorContent)
	}
	if strings.Contains(string(r.present), "bogus-kex-algorithm") {
		t.Errorf("bad new content left on disk: %q", r.present)
	}
}

// TestApplySSHConfig_RemoveOnReloadFailureNoPrior verifies that when the write
// succeeds, the reload fails, and there was NO prior drop-in, the bad new
// drop-in is removed (#2062 gap 2). Fails pre-fix: old code left the bad
// content on disk to break the next restart.
func TestApplySSHConfig_RemoveOnReloadFailureNoPrior(t *testing.T) {
	r := &sshdSeamRecorder{
		present:       nil, // no prior drop-in
		reloadErr:     errors.New("sshd: bad configuration"),
		failNthReload: 1,
	}
	installSSHDSeam(t, r)

	d := &Daemon{}
	d.applySSHConfig(sshConfig(&config.SSHServiceConfig{
		KeyExchange: []string{"bogus-kex-algorithm"},
	}))

	if r.present != nil {
		t.Fatalf("bad drop-in left on disk after reload failure with no prior: %q", r.present)
	}
	if r.removed != 1 {
		t.Errorf("Remove called %d times after reload failure, want 1", r.removed)
	}
}

// TestApplySSHConfig_NormalWrite verifies the unchanged happy path: a managed
// config writes the drop-in and reloads once, with no revert.
func TestApplySSHConfig_NormalWrite(t *testing.T) {
	r := &sshdSeamRecorder{present: nil}
	installSSHDSeam(t, r)

	want := buildSSHDConfig(&config.SSHServiceConfig{RootLogin: "deny", KeyExchange: []string{"curve25519-sha256"}})

	d := &Daemon{}
	d.applySSHConfig(sshConfig(&config.SSHServiceConfig{
		RootLogin:   "deny",
		KeyExchange: []string{"curve25519-sha256"},
	}))

	if r.present == nil || string(r.present) != want {
		t.Fatalf("drop-in content = %q, want %q", r.present, want)
	}
	if len(r.writes) != 1 {
		t.Errorf("Write called %d times, want 1", len(r.writes))
	}
	if r.reloads != 1 {
		t.Errorf("reload called %d times, want 1", r.reloads)
	}
	if r.removed != 0 {
		t.Errorf("unexpected Remove: %d", r.removed)
	}
}

// TestApplySSHConfig_RemoveOnConfigRemovedUnreadablePrior verifies that an
// existing-but-UNREADABLE drop-in is treated as present and removed when the
// config is cleared (#2067 fold 1). Fails pre-fix: hadDropIn := priorErr == nil
// treated the read error as "absent", so the content=="" path returned early
// and left the stale drop-in enforcing old settings.
func TestApplySSHConfig_RemoveOnConfigRemovedUnreadablePrior(t *testing.T) {
	r := &sshdSeamRecorder{
		present: []byte("# Managed by xpf\nPermitRootLogin no\n"),
		readErr: os.ErrPermission, // exists, but cannot be read
	}
	installSSHDSeam(t, r)

	d := &Daemon{}
	d.applySSHConfig(sshConfig(nil)) // ssh stanza gone

	if r.present != nil {
		t.Fatalf("unreadable-but-present drop-in not removed on config removal: %q", r.present)
	}
	if r.removed != 1 {
		t.Errorf("Remove called %d times, want 1", r.removed)
	}
	if r.reloads != 1 {
		t.Errorf("reload called %d times, want 1", r.reloads)
	}
}

// TestApplySSHConfig_RevertWriteFailureRemovesBadContent verifies the
// fail-safe in fold 3: when the post-write reload fails AND restoring the prior
// content also fails (the restore write errors), the bad just-written drop-in
// is REMOVED rather than left on disk to break the next sshd restart. Fails
// pre-fix: the restore failure was only logged, leaving the bad content.
func TestApplySSHConfig_RevertWriteFailureRemovesBadContent(t *testing.T) {
	priorContent := buildSSHDConfig(&config.SSHServiceConfig{RootLogin: "deny"})
	r := &sshdSeamRecorder{
		present:       []byte(priorContent),
		reloadErr:     errors.New("sshd: bad configuration"),
		failNthReload: 1, // post-write reload fails
		writeErr:      errors.New("write failed"),
		failNthWrite:  2, // first (new content) write OK; revert write (2nd) fails
	}
	installSSHDSeam(t, r)

	d := &Daemon{}
	d.applySSHConfig(sshConfig(&config.SSHServiceConfig{
		RootLogin:   "deny",
		KeyExchange: []string{"bogus-kex-algorithm"},
	}))

	if r.present != nil {
		t.Fatalf("bad content left on disk after failed restore; want drop-in removed: %q", r.present)
	}
	if r.removed != 1 {
		t.Errorf("Remove called %d times after failed restore, want 1", r.removed)
	}
}

// TestApplySSHConfig_NoChange verifies that re-applying identical content does
// not rewrite or reload (idempotence preserved by #2062).
func TestApplySSHConfig_NoChange(t *testing.T) {
	want := buildSSHDConfig(&config.SSHServiceConfig{RootLogin: "deny"})
	r := &sshdSeamRecorder{present: []byte(want)}
	installSSHDSeam(t, r)

	d := &Daemon{}
	d.applySSHConfig(sshConfig(&config.SSHServiceConfig{RootLogin: "deny"}))

	if len(r.writes) != 0 {
		t.Errorf("unexpected write on no-change: %v", r.writes)
	}
	if r.reloads != 0 {
		t.Errorf("unexpected reload on no-change: %d", r.reloads)
	}
}
