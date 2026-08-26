package daemon

// apply_credential_failclosed_6790_test.go — #6790.
//
// applyTailReconciles ran the five host-credential reconcilers as
//
//	_ = d.applySystemLogin(cfg)
//	_ = d.reconcileSudoers(cfg)
//	_ = d.reconcileAbsentLoginUsers(cfg)
//	_ = d.applySSHConfig(cfg)
//	_ = d.applyRootAuth(cfg)
//
// so EVERY failure they accumulate — an account that could not be created, a
// sudo grant that could not be revoked, a removed operator whose password and
// authorized_keys were NOT revoked, an sshd drop-in that failed validation, a
// root key file that was not written — was discarded and the commit reported
// SUCCESS. #5874 had already made all five RETURN their failures, but only the
// daemon-stop cancel closeout collected them; the ordinary commit path an
// operator actually uses to revoke access kept throwing them away.
//
// These cells drive the REAL applyTailReconciles with exactly ONE owner
// injected to fail and assert the commit result NAMES that owner's failure.
// Because each cell keys on a substring unique to its owner, dropping that
// owner's operand from the tail errors.Join (or reverting its capture to
// `_ =`) reds that cell and only that cell.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/networkd"
	"github.com/psaab/xpf/pkg/vrrp"
)

// credentialTailFixture6790 is the shared harness: a Daemon whose tail can run
// end-to-end with every NON-credential owner (nft lo0 / host-inbound, DNS,
// VRRP, networkd) stubbed clean, and every credential owner pointed at
// throwaway trees so it is clean UNLESS the cell injects a failure.
//
// The control cell below proves the harness really is clean — without it,
// "the tail returns an error" would be satisfied by a harness in which
// something unrelated fails on every run.
type credentialTailFixture6790 struct {
	d    *Daemon
	cfg  *config.Config
	root string
}

func newCredentialTailFixture6790(t *testing.T) *credentialTailFixture6790 {
	t.Helper()
	installFakeNetworkctl(t)

	origNftApply, origNftDelete := nftApplyPayload, nftDeleteTable
	nftApplyPayload = func(string) ([]byte, error) { return nil, nil }
	nftDeleteTable = func(string, string) ([]byte, error) { return nil, nil }
	t.Cleanup(func() { nftApplyPayload, nftDeleteTable = origNftApply, origNftDelete })

	root := t.TempDir()

	origUsersDir, origSudoersDir := provisionedUsersDir, sudoersDir
	origSSHDPath, origHomeBase := sshdConfPath, homeBaseDir
	provisionedUsersDir = filepath.Join(root, "provisioned-users")
	sudoersDir = filepath.Join(root, "sudoers.d")
	sshdConfPath = filepath.Join(root, "sshd_config.d", "xpf.conf")
	homeBaseDir = filepath.Join(root, "home")
	t.Cleanup(func() {
		provisionedUsersDir, sudoersDir = origUsersDir, origSudoersDir
		sshdConfPath, homeBaseDir = origSSHDPath, origHomeBase
	})
	if err := os.MkdirAll(sudoersDir, 0o755); err != nil {
		t.Fatalf("seed sudoers dir: %v", err)
	}
	// applySSHConfig's own mkdir targets the hard-coded production
	// /etc/ssh/sshd_config.d, so the relocated drop-in's parent must exist
	// here or the WRITE fails and masks whatever the cell injected.
	if err := os.MkdirAll(filepath.Dir(sshdConfPath), 0o755); err != nil {
		t.Fatalf("seed sshd drop-in dir: %v", err)
	}

	// A readable, valid identity pair holding only root, so no login user
	// resolves and no credential is ever mutated by a cell that did not ask.
	origPasswd, origShadow := passwdPath, shadowPath
	passwdPath = filepath.Join(root, "passwd")
	shadowPath = filepath.Join(root, "shadow")
	t.Cleanup(func() { passwdPath, shadowPath = origPasswd, origShadow })
	if err := os.WriteFile(passwdPath, []byte("root:x:0:0::/root:/bin/bash\n"), 0o644); err != nil {
		t.Fatalf("seed passwd: %v", err)
	}
	if err := os.WriteFile(shadowPath, []byte("root:!:19000:0:99999:7:::\n"), 0o644); err != nil {
		t.Fatalf("seed shadow: %v", err)
	}

	// No real process ever runs: id/useradd/chown succeed silently unless a
	// cell replaces this, visudo and the sshd validate/reload are stubbed at
	// their own seams.
	origRun := runCommandTimeout
	runCommandTimeout = func(string, ...string) ([]byte, error) { return nil, nil }
	t.Cleanup(func() { runCommandTimeout = origRun })

	origValidateSudoers := validateSudoersFile
	validateSudoersFile = func(string) error { return nil }
	t.Cleanup(func() { validateSudoersFile = origValidateSudoers })

	origSSHDValidate, origSSHDReload := sshdValidateCmd, sshdReloadCmd
	sshdValidateCmd = func() ([]byte, error) { return nil, nil }
	sshdReloadCmd = func() ([]byte, error) { return nil, nil }
	t.Cleanup(func() { sshdValidateCmd, sshdReloadCmd = origSSHDValidate, origSSHDReload })

	d := &Daemon{
		networkd: networkd.NewInDir(t.TempDir()),
		store:    newConfigStore(t, filepath.Join(t.TempDir(), "config.db")),
		vrrpMgr:  vrrp.NewManager(),
		opts:     Options{NoDataplane: true},
	}
	d.setDataplane(&runtimeOnlyApplyTestDP{})
	d.reconcileDNSFn = func(*config.Config, bool) error { return nil }

	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"reth0": {Name: "reth0", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {Name: "trust", Interfaces: []string{"reth0.0"}},
	}
	return &credentialTailFixture6790{d: d, cfg: cfg, root: root}
}

// tail runs the REAL applyTailReconciles with every head-produced deferred
// error nil, so the only operands that can be non-nil are the ones this
// function's own steps produce.
func (f *credentialTailFixture6790) tail() error {
	return f.d.applyTailReconciles(f.cfg, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
}

// breakMarkerRoots6790 makes all three ownership-marker roots unusable by
// putting a regular FILE where their parent directory must be: MkdirAll then
// fails with ENOTDIR, which no amount of privilege can bypass (so the cell
// behaves identically for a root and a non-root test runner).
func breakMarkerRoots6790(t *testing.T, root string) {
	t.Helper()
	blocked := filepath.Join(root, "blocked")
	if err := os.WriteFile(blocked, []byte("not a directory\n"), 0o644); err != nil {
		t.Fatalf("seed the blocking file: %v", err)
	}
	provisionedUsersDir = filepath.Join(blocked, "provisioned-users")
}

// TestApplyTailIsCleanWithHealthyCredentialReconciles6790 is the PAIRED
// control for every failure cell below. With nothing injected the tail must
// return nil — otherwise "the tail surfaces a credential failure" would be
// satisfied by a tail that fails every commit, which is the opposite defect.
func TestApplyTailIsCleanWithHealthyCredentialReconciles6790(t *testing.T) {
	f := newCredentialTailFixture6790(t)
	f.cfg.System.Login = &config.LoginConfig{Users: []*config.LoginUser{
		{Name: "admin", Class: "super-user"},
	}}
	f.cfg.System.Services = &config.SystemServicesConfig{
		SSH: &config.SSHServiceConfig{RootLogin: "deny"},
	}
	if err := f.tail(); err != nil {
		t.Fatalf("applyTailReconciles returned %v with every credential "+
			"reconciler healthy — every commit would now fail closed", err)
	}
}

// TestApplyTailSurfacesSystemLoginFailure6790: the account could not be
// created, so the configured operator cannot log in at all, and the commit
// said success.
func TestApplyTailSurfacesSystemLoginFailure6790(t *testing.T) {
	f := newCredentialTailFixture6790(t)
	f.cfg.System.Login = &config.LoginConfig{Users: []*config.LoginUser{
		{Name: "admin", Class: "super-user"},
	}}
	// `id` reports the account missing and `useradd` then refuses.
	runCommandTimeout = func(string, ...string) ([]byte, error) {
		return []byte("simulated: refused"), os.ErrPermission
	}

	err := f.tail()
	if err == nil {
		t.Fatal("applyTailReconciles returned nil while applySystemLogin FAILED " +
			"to create the configured login account — the commit reports " +
			"success over an operator who cannot log in (#6790)")
	}
	if !strings.Contains(err.Error(), "create user") {
		t.Fatalf("the commit error does not carry the system-login failure "+
			"through the tail errors.Join, got %v", err)
	}
}

// TestApplyTailSurfacesSudoersFailure6790: the NOPASSWD grant could not be
// written, so a configured super-user has no sudo — and, on the revoke side,
// the same accumulator carries a grant that could not be REMOVED, which is a
// demoted operator keeping passwordless root.
func TestApplyTailSurfacesSudoersFailure6790(t *testing.T) {
	f := newCredentialTailFixture6790(t)
	f.cfg.System.Login = &config.LoginConfig{Users: []*config.LoginUser{
		{Name: "admin", Class: "super-user"},
	}}
	sudoersDir = filepath.Join(f.root, "sudoers-missing") // never created → write fails

	err := f.tail()
	if err == nil {
		t.Fatal("applyTailReconciles returned nil while reconcileSudoers FAILED " +
			"to write a super-user grant — the commit reports success (#6790)")
	}
	if !strings.Contains(err.Error(), "write sudoers grant for") {
		t.Fatalf("the commit error does not carry the sudoers failure through "+
			"the tail errors.Join, got %v", err)
	}
}

// TestApplyTailSurfacesAbsentUserRevocationFailure6790 is the cell the issue is
// really about: an operator removed from config whose credentials were NOT
// revoked because the identity database could not be read. The deprovision
// deliberately fails CLOSED (markers kept, retry next apply) — but the commit
// that ordered the revocation still reported success, so the operator believes
// the account is gone while its password and authorized_keys are live.
func TestApplyTailSurfacesAbsentUserRevocationFailure6790(t *testing.T) {
	f := newCredentialTailFixture6790(t)
	// A provisioned account that is no longer in config.
	if err := os.MkdirAll(provisionedUsersDir, 0o700); err != nil {
		t.Fatalf("seed the account registry: %v", err)
	}
	if err := os.WriteFile(filepath.Join(provisionedUsersDir, "ghost"), []byte("4242"), 0o600); err != nil {
		t.Fatalf("seed the ghost marker: %v", err)
	}
	// /etc/passwd unreadable (a directory) → lookupUIDErr returns an error →
	// deprovisionLoginUser keeps the markers and reports the failure.
	passwdPath = filepath.Join(f.root, "passwd-as-dir")
	if err := os.MkdirAll(passwdPath, 0o755); err != nil {
		t.Fatalf("seed an unreadable passwd: %v", err)
	}

	err := f.tail()
	if err == nil {
		t.Fatal("applyTailReconciles returned nil while a REMOVED login user's " +
			"credentials could not be revoked — the commit that ordered the " +
			"deprovision reports success while the password and " +
			"authorized_keys stay live (#6790)")
	}
	if !strings.Contains(err.Error(), "read passwd for removed user") {
		t.Fatalf("the commit error does not carry the absent-user revocation "+
			"failure through the tail errors.Join, got %v", err)
	}
}

// TestApplyTailSurfacesSSHConfigFailure6790: the sshd drop-in failed
// validation, so it was reverted and the committed PermitRootLogin posture is
// NOT what sshd is enforcing.
func TestApplyTailSurfacesSSHConfigFailure6790(t *testing.T) {
	f := newCredentialTailFixture6790(t)
	f.cfg.System.Services = &config.SystemServicesConfig{
		SSH: &config.SSHServiceConfig{RootLogin: "deny"},
	}
	sshdValidateCmd = func() ([]byte, error) {
		return []byte("simulated: bad configuration option"), os.ErrInvalid
	}

	err := f.tail()
	if err == nil {
		t.Fatal("applyTailReconciles returned nil while the sshd drop-in FAILED " +
			"validation and was reverted — sshd keeps the pre-commit " +
			"root-login posture and the commit reports success (#6790)")
	}
	if !strings.Contains(err.Error(), "validate sshd config") {
		t.Fatalf("the commit error does not carry the sshd failure through the "+
			"tail errors.Join, got %v", err)
	}
}

// TestApplyTailSurfacesRootAuthFailure6790: root's authorized_keys were NOT
// written because the ownership marker could not be recorded, so the committed
// root key set is not the one root actually accepts.
func TestApplyTailSurfacesRootAuthFailure6790(t *testing.T) {
	f := newCredentialTailFixture6790(t)
	f.cfg.System.RootAuthentication = &config.RootAuthConfig{
		SSHKeys: []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI6790 test@xpf"},
	}
	breakMarkerRoots6790(t, f.root)

	err := f.tail()
	if err == nil {
		t.Fatal("applyTailReconciles returned nil while applyRootAuth SKIPPED " +
			"the root authorized_keys write — the committed root key set is " +
			"not what root accepts and the commit reports success (#6790)")
	}
	if !strings.Contains(err.Error(), "mark root key provisioned") {
		t.Fatalf("the commit error does not carry the root-auth failure through "+
			"the tail errors.Join, got %v", err)
	}
}

// TestApplyTailRunsEveryCredentialOwnerDespiteAnEarlierFailure6790 binds the
// OTHER half of the contract: fail-closed must not become fail-FAST. A login
// reconcile that fails must not skip root-auth — skipping it would leave root's
// credentials at the pre-commit generation, which is the monotonic-revocation
// violation the fail-closed change exists to prevent.
//
// Both failures are injected at once and BOTH must be named in the single
// joined commit error.
func TestApplyTailRunsEveryCredentialOwnerDespiteAnEarlierFailure6790(t *testing.T) {
	f := newCredentialTailFixture6790(t)
	f.cfg.System.Login = &config.LoginConfig{Users: []*config.LoginUser{
		{Name: "admin", Class: "super-user"},
	}}
	f.cfg.System.RootAuthentication = &config.RootAuthConfig{
		SSHKeys: []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI6790 test@xpf"},
	}
	runCommandTimeout = func(string, ...string) ([]byte, error) {
		return []byte("simulated: refused"), os.ErrPermission
	}
	breakMarkerRoots6790(t, f.root)

	err := f.tail()
	if err == nil {
		t.Fatal("applyTailReconciles returned nil with TWO credential " +
			"reconcilers failing (#6790)")
	}
	if !strings.Contains(err.Error(), "create user") {
		t.Fatalf("the earlier (system-login) failure is missing from the joined "+
			"commit error: %v", err)
	}
	if !strings.Contains(err.Error(), "mark root key provisioned") {
		t.Fatalf("the LATER (root-auth) owner did not run, or its failure was "+
			"dropped, after an earlier credential reconcile failed — "+
			"fail-closed must not become fail-fast: %v", err)
	}
}
