package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #5026: PR #5019 (#5005) added `--` end-of-options separators to every
// root-privileged exec in applySystemLogin (id/useradd/chown) plus a
// fail-closed username re-validation. The id/useradd `--` guards are pinned by
// TestApplySystemLoginUsesEndOfOptions, but the chown `--`
// (`chown -R -- <user>:<user> <sshDir>`) was NOT independently guarded: both
// #5005 revert tests provision a user with NO SSH keys, so the chown branch
// never runs — dropping ONLY the chown `--` left the suite green. This test
// provisions a user WITH an authorized key so the chown branch actually
// executes, and asserts the `--` separates the flags from the operands. Drop
// the chown `--` and this test goes RED.

// stageChownEnv points the account DBs, provisioned-user marker dir, and home
// base at a throwaway tree, seeds /etc/passwd (so lookupUIDGID resolves the
// owner and the SSH-key branch is entered) and a LOCKED /etc/shadow field (so
// reconcileUserPassword takes pwNoop and never execs chpasswd), and stubs
// runCommandTimeout to RECORD every argv while reporting the user already
// EXISTS (`id` returns nil) so the privileged useradd is skipped and the test
// runs unprivileged. The passwd entry uses the CURRENT uid/gid so the
// DurableState authorized_keys write (fsatomic.WithOwner) fchowns the temp fd
// to self and succeeds without root. It returns the recorded-command slice and
// the .ssh dir the chown must target. #5026.
func stageChownEnv(t *testing.T, name string) (*[]recordedCmd, string) {
	t.Helper()
	dir := t.TempDir()
	uid, gid := os.Getuid(), os.Getgid()

	passwd := filepath.Join(dir, "passwd")
	passwdContent := fmt.Sprintf(
		"root:x:0:0:root:/root:/bin/bash\n%s:x:%d:%d:,,,:/home/%s:/bin/bash\n",
		name, uid, gid, name)
	if err := os.WriteFile(passwd, []byte(passwdContent), 0o600); err != nil {
		t.Fatal(err)
	}
	shadow := filepath.Join(dir, "shadow")
	// Locked ("!") field + no configured password ⇒ passwordAction returns
	// pwNoop, so reconcileUserPassword never execs chpasswd.
	shadowContent := fmt.Sprintf("root:*:19000:0:99999:7:::\n%s:!:19000:0:99999:7:::\n", name)
	if err := os.WriteFile(shadow, []byte(shadowContent), 0o600); err != nil {
		t.Fatal(err)
	}

	origShadow, origPasswd, origMarker, origHome := shadowPath, passwdPath, provisionedUsersDir, homeBaseDir
	shadowPath = shadow
	passwdPath = passwd
	provisionedUsersDir = filepath.Join(dir, "provisioned-users")
	homeBaseDir = filepath.Join(dir, "home")
	t.Cleanup(func() {
		shadowPath, passwdPath, provisionedUsersDir, homeBaseDir = origShadow, origPasswd, origMarker, origHome
	})

	var calls []recordedCmd
	origRun := runCommandTimeout
	runCommandTimeout = func(cmd string, args ...string) ([]byte, error) {
		calls = append(calls, recordedCmd{name: cmd, args: append([]string(nil), args...)})
		if cmd == "id" {
			return nil, nil // user exists → useradd skipped
		}
		return nil, nil
	}
	t.Cleanup(func() { runCommandTimeout = origRun })

	return &calls, filepath.Join(homeBaseDir, name, ".ssh")
}

// TestApplySystemLoginChownUsesEndOfOptions is the RED-on-revert guard for the
// chown `--` half of #5005/#5026. It provisions a valid login user WITH an
// authorized SSH key so applySystemLogin enters the key branch and chowns the
// .ssh dir, then asserts the captured chown argv places a `--` end-of-options
// separator immediately before the validated `<user>:<user>` operand (with the
// sshDir after it). Drop the `--` from the chown line and the operand is no
// longer separator-guarded, failing the assertion. The existing
// TestApplySystemLoginUsesEndOfOptions cannot catch this: its user has no SSH
// key, so the chown never runs.
func TestApplySystemLoginChownUsesEndOfOptions(t *testing.T) {
	const name = "keyuser"
	calls, sshDir := stageChownEnv(t, name)

	d := &Daemon{}
	d.applySystemLogin(loginCfg(&config.LoginUser{
		Name:    name,
		Class:   "operator",
		SSHKeys: []string{"ssh-ed25519 AAAAC3Nz keyuser@host"},
	}))

	var chown *recordedCmd
	for i := range *calls {
		if (*calls)[i].name == "chown" {
			chown = &(*calls)[i]
			break
		}
	}
	if chown == nil {
		t.Fatalf("chown was never invoked — the SSH-key branch did not run; captured: %v", *calls)
	}

	operand := name + ":" + name // the validated <user>:<group> operand

	// The `--` must appear, and the FIRST argument after it must be the
	// user:group operand (option-injection guard). Dropping the `--` removes it
	// entirely, so sepIdx stays -1 and the assertion fails: RED on revert.
	sepIdx := -1
	for i, a := range chown.args {
		if a == "--" {
			sepIdx = i
			break
		}
	}
	if sepIdx < 0 {
		t.Fatalf("chown argv = %v, want a `--` end-of-options separator before the %q operand (#5026)", chown.args, operand)
	}
	if sepIdx+1 >= len(chown.args) || chown.args[sepIdx+1] != operand {
		t.Fatalf("chown argv = %v, want %q immediately after `--` (validated user:group operand, #5026)", chown.args, operand)
	}
	// Every argument before the separator must be a flag, never the operand —
	// i.e. the user:group must be introduced ONLY by the `--`.
	for _, a := range chown.args[:sepIdx] {
		if a == operand {
			t.Fatalf("chown argv = %v places the operand %q before the `--` separator (option injection, #5026)", chown.args, operand)
		}
	}
	// The sshDir operand follows the user:group operand, both after the `--`.
	if sepIdx+2 >= len(chown.args) || chown.args[sepIdx+2] != sshDir {
		t.Fatalf("chown argv = %v, want sshDir %q after the operand (#5026)", chown.args, sshDir)
	}
	// The recursive flag is preserved (chown -R on the .ssh dir).
	if chown.args[0] != "-R" {
		t.Errorf("chown argv = %v, want -R as the first flag", chown.args)
	}
}

// TestApplySystemLoginChownSkipsUnsafeName pins the fail-closed username
// re-validation for the chown path: an unsafe (leading-dash) login name that
// slips past the tolerant load carrying an SSH key must be rejected before the
// key branch, so it NEVER reaches the root-privileged chown. A valid peer in
// the same config is still provisioned and chowned. Reverting the
// ValidateLoginUsername skip lets `-r` flow into `chown -R -- -r:-r ...`, so the
// "no chown references the unsafe operand" assertion fails.
func TestApplySystemLoginChownSkipsUnsafeName(t *testing.T) {
	const good = "keyuser"
	calls, _ := stageChownEnv(t, good)

	d := &Daemon{}
	d.applySystemLogin(loginCfg(
		&config.LoginUser{Name: "-r", Class: "operator", SSHKeys: []string{"ssh-ed25519 AAAA evil@host"}},
		&config.LoginUser{Name: good, Class: "operator", SSHKeys: []string{"ssh-ed25519 AAAAC3Nz keyuser@host"}},
	))

	sawGoodChown := false
	for _, c := range *calls {
		if c.name != "chown" {
			continue
		}
		for _, a := range c.args {
			if a == "-r:-r" || a == "-r" {
				t.Fatalf("unsafe username reached chown argv %v — pre-chown re-validation missing (#5026)", c.args)
			}
			if a == good+":"+good {
				sawGoodChown = true
			}
		}
	}
	if !sawGoodChown {
		t.Fatal("valid peer 'keyuser' was never chowned — the skip must not drop good users")
	}
}
