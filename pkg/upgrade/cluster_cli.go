package upgrade

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

// cliCluster is the production RollingCluster backed by the `cli` binary
// (the same surface the existing deploy_rolling driver shells, so it works
// from the upgrade subprocess without an in-process cluster.Manager).
//
// Mutations route through `cli -c "request ..."`; predicate reads parse
// `cli -c "show chassis cluster status"`.
//
// NOTE (validation gate): the strong-drain-predicate field parsing below
// must be validated against the LIVE `show chassis cluster status` output
// on the loss userspace cluster before the rolling path is trusted in
// production. The parsing is defensive (substring matching on documented
// status lines) and conservative (an unrecognized state reads as
// not-drained / not-ready, so the driver ABORTS without cutting rather
// than cutting unsafely).
type cliCluster struct {
	cliBin string
	unit   string
}

// NewCLICluster returns a RollingCluster driving the local node via `cli`.
func NewCLICluster(unit string) RollingCluster {
	return &cliCluster{cliBin: "cli", unit: unit}
}

func (c *cliCluster) cli(cmd string) (string, error) {
	out := &bytes.Buffer{}
	x := exec.Command(c.cliBin, "-c", cmd)
	x.Stdout = out
	x.Stderr = out
	if err := x.Run(); err != nil {
		return out.String(), fmt.Errorf("cli %q: %w (output: %s)", cmd, err, strings.TrimSpace(out.String()))
	}
	return out.String(), nil
}

func (c *cliCluster) status() (string, error) {
	return c.cli("show chassis cluster status")
}

func (c *cliCluster) PeerAlive() (bool, error) {
	s, err := c.status()
	if err != nil {
		return false, err
	}
	// "Remote node: healthy ..." indicates the peer is alive.
	return containsLine(s, "Remote node:", "healthy"), nil
}

func (c *cliCluster) SyncEstablished() (bool, error) {
	s, err := c.status()
	if err != nil {
		return false, err
	}
	// A clean sync shows neither an "unsynced" nor "sync hold" marker and a
	// healthy remote. Conservative: require healthy remote and no negative
	// markers.
	if strings.Contains(strings.ToLower(s), "unsynced") {
		return false, nil
	}
	return containsLine(s, "Remote node:", "healthy"), nil
}

func (c *cliCluster) HAProtocolCompatible() (bool, error) {
	s, err := c.status()
	if err != nil {
		return false, err
	}
	// An explicit incompatibility marker fails closed; otherwise compatible.
	low := strings.ToLower(s)
	if strings.Contains(low, "protocol mismatch") || strings.Contains(low, "incompatible") {
		return false, nil
	}
	return true, nil
}

func (c *cliCluster) PeerTakeoverReady() (bool, error) {
	s, err := c.status()
	if err != nil {
		return false, err
	}
	// Peer is takeover-ready when it is healthy and shows no hold / monitor
	// failure. Conservative: require healthy remote and absence of blockers.
	low := strings.ToLower(s)
	if strings.Contains(low, "monitor: fail") || strings.Contains(low, "takeover hold") {
		return false, nil
	}
	return containsLine(s, "Remote node:", "healthy"), nil
}

func (c *cliCluster) ForceSecondary() error {
	_, err := c.cli("request system software in-service-upgrade")
	return err
}

func (c *cliCluster) DrainComplete() (bool, error) {
	s, err := c.status()
	if err != nil {
		return false, err
	}
	// STRONG predicate: the local node must be SECONDARY for all RGs (peer
	// owns them) — i.e. no "primary:node<local>" line — AND the remote is
	// healthy (peer present to own them). VRRP-backup / rg_active-false are
	// the downstream consequences of the SECONDARY RG state (rg_state.go),
	// reflected in the status block. Conservative: any sign the local node
	// still owns an RG fails the predicate.
	low := strings.ToLower(s)
	if !strings.Contains(low, "secondary") {
		return false, nil
	}
	// If the status still reports the local node primary for any RG, not
	// drained.
	if strings.Contains(low, "primary:node") {
		// Could be the peer's primary line; require that the LOCAL node is
		// not primary. The status formats peer/local lines; absent a
		// structured query we treat any local-primary indication as
		// not-drained. This is the field that MUST be validated live.
		return false, nil
	}
	return containsLine(s, "Remote node:", "healthy"), nil
}

func (c *cliCluster) ResetFailover() error {
	// Reset all RGs. RG 0 and 1 are the standard cluster RGs; reset both
	// (a missing RG is a harmless NotFound the driver tolerates).
	var firstErr error
	for _, rg := range []int{0, 1} {
		if _, err := c.cli(fmt.Sprintf(
			"request chassis cluster failover reset redundancy-group %d", rg)); err != nil {
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

func (c *cliCluster) LocalPrimary() (bool, error) {
	s, err := c.status()
	if err != nil {
		return false, err
	}
	return strings.Contains(strings.ToLower(s), "primary"), nil
}

// containsLine reports whether any line of s contains all the given
// substrings (case-insensitive on the whole line).
func containsLine(s string, subs ...string) bool {
	for _, line := range strings.Split(s, "\n") {
		ll := strings.ToLower(line)
		all := true
		for _, sub := range subs {
			if !strings.Contains(ll, strings.ToLower(sub)) {
				all = false
				break
			}
		}
		if all {
			return true
		}
	}
	return false
}
