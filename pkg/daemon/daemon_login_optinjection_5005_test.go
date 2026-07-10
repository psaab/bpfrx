package daemon

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #5005: applySystemLogin runs root-privileged id/useradd/chown with the
// config-supplied username as a positional argument. On the tolerant load /
// peer-sync path the strict commit-check for the username is downgraded to a
// warning (#1960), so a leading-dash / otherwise unsafe name can reach the
// account writer. The writer must (a) defensively re-validate the name and skip
// it entirely (mirroring the #4895 sudoers writer), and (b) pass a `--`
// end-of-options separator before the operand so a name is never parsed as an
// option (option injection).

type recordedCmd struct {
	name string
	args []string
}

// withHermeticAccountDB points the passwd/shadow readers at nonexistent temp
// paths so lookupUID/currentShadowHash deterministically report "absent" — the
// reconcile then takes no chpasswd action and applySystemLogin's only external
// effects are the id/useradd calls we capture.
func withHermeticAccountDB(t *testing.T) {
	t.Helper()
	missing := filepath.Join(t.TempDir(), "nonexistent")
	origPasswd, origShadow := passwdPath, shadowPath
	passwdPath = missing
	shadowPath = missing
	t.Cleanup(func() { passwdPath, shadowPath = origPasswd, origShadow })
}

// captureRunCommand stubs the runCommandTimeout seam, recording every argv and
// forcing the "user does not exist" branch (non-nil error from `id`) so the
// useradd call is always exercised.
func captureRunCommand(t *testing.T) *[]recordedCmd {
	t.Helper()
	var calls []recordedCmd
	orig := runCommandTimeout
	runCommandTimeout = func(name string, args ...string) ([]byte, error) {
		calls = append(calls, recordedCmd{name: name, args: append([]string(nil), args...)})
		if name == "id" {
			return nil, fmt.Errorf("id: no such user (stub)")
		}
		return nil, nil
	}
	t.Cleanup(func() { runCommandTimeout = orig })
	return &calls
}

// TestApplySystemLoginSkipsUnsafeName is the RED-on-revert guard for the
// defensive re-validation half of #5005: a leading-dash username must never
// reach id/useradd/chown. Revert the ValidateLoginUsername skip and `-r` flows
// straight into `id -- -r` / `useradd ... -- -r`, so the "no argv references the
// unsafe name" assertion fails.
func TestApplySystemLoginSkipsUnsafeName(t *testing.T) {
	withHermeticAccountDB(t)
	calls := captureRunCommand(t)

	d := &Daemon{}
	cfg := loginCfg(
		&config.LoginUser{Name: "-r", Class: "operator"},    // option-injection attempt
		&config.LoginUser{Name: "admin", Class: "operator"}, // valid peer still provisioned
	)
	d.applySystemLogin(cfg)

	sawAdmin := false
	for _, c := range *calls {
		for _, a := range c.args {
			if a == "-r" {
				t.Fatalf("unsafe username reached %q argv %v — defensive re-validation missing (#5005)", c.name, c.args)
			}
			if a == "admin" {
				sawAdmin = true
			}
		}
	}
	if !sawAdmin {
		t.Fatal("valid peer 'admin' was never provisioned — the skip must not drop good users")
	}
}

// TestApplySystemLoginUsesEndOfOptions is the RED-on-revert guard for the `--`
// half of #5005. It asserts the id and useradd invocations for a valid user
// place a `--` immediately before the username operand. Drop either `--` and
// the operand appears without its separator, failing the assertion.
func TestApplySystemLoginUsesEndOfOptions(t *testing.T) {
	withHermeticAccountDB(t)
	calls := captureRunCommand(t)

	d := &Daemon{}
	d.applySystemLogin(loginCfg(&config.LoginUser{Name: "admin", Class: "operator"}))

	var idArgs, useraddArgs []string
	for _, c := range *calls {
		switch c.name {
		case "id":
			idArgs = c.args
		case "useradd":
			useraddArgs = c.args
		}
	}

	if len(idArgs) != 2 || idArgs[0] != "--" || idArgs[1] != "admin" {
		t.Errorf("id argv = %v, want [-- admin] (missing end-of-options separator, #5005)", idArgs)
	}
	if !endsWithSeparatedOperand(useraddArgs, "admin") {
		t.Errorf("useradd argv = %v, want a `--` immediately before the operand %q (#5005)", useraddArgs, "admin")
	}
}

// endsWithSeparatedOperand reports whether argv ends with "--", operand.
func endsWithSeparatedOperand(argv []string, operand string) bool {
	n := len(argv)
	return n >= 2 && argv[n-2] == "--" && argv[n-1] == operand
}
