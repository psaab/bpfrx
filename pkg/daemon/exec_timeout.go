// Package daemon implements the xpf daemon lifecycle.
package daemon

import (
	"context"
	"io"
	"os/exec"
	"time"
)

// externalCommandTimeout bounds external commands run on the config-apply
// path. 15s mirrors the established FRR precedent (pkg/frr/vtysh.go
// SystemctlReload / VtyshLoad callers and the chrony reload in
// daemon_system.go): apply-path exec sites run while applySem is held,
// so a single hung systemctl/useradd/chown would otherwise wedge every
// CLI/gRPC/HTTP commit and HA config sync indefinitely (#1794).
const externalCommandTimeout = 15 * time.Second

// runCommandTimeout runs an external command under a 15s context timeout
// and returns its combined output. On timeout the process is killed and
// the error reflects the context deadline; callers log the failure and
// continue — apply success/failure semantics are unchanged, failures
// just become visible and bounded.
func runCommandTimeout(name string, args ...string) ([]byte, error) {
	return runCommandStdinTimeout(nil, name, args...)
}

// runCommandStdinTimeout is runCommandTimeout with an optional stdin
// (used by `chpasswd -e`, which reads the user:hash pair from stdin).
func runCommandStdinTimeout(stdin io.Reader, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), externalCommandTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != nil {
		cmd.Stdin = stdin
	}
	// WaitDelay caps the post-SIGKILL pipe-drain window. Without it,
	// CombinedOutput blocks until all write-end holders (e.g. PAM exec
	// helpers spawned by useradd) close their copies of the pipe — which
	// may be long after the main process is killed. 5s is generous for
	// simple admin commands; the hard ceiling becomes 15s+5s=20s per site.
	cmd.WaitDelay = 5 * time.Second
	return cmd.CombinedOutput()
}
