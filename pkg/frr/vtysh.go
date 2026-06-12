// vtysh.go holds the FRR shell-out surface for the package.
//
// All vtysh + frr-reload.py shell-outs go through the frrExecutor
// interface so tests can inject fakes. realExecutor wraps os/exec and
// is the production default; New() pre-populates Manager.exec with it.
//
// Symbols:
//   - frrExecutor interface (Vtysh / FrrReloadPy / VtyshLoad)
//   - realExecutor (production implementation, exec.Command-backed)
//   - Manager.ExecVtysh (public)
//   - Thin raw-output shells: GetBFDPeers, GetRouteMapList,
//     GetISISAdjacencyDetail, GetISISDatabase, GetISISRoutes,
//     GetOSPFNeighborDetail, GetOSPFDatabase, GetOSPFInterface,
//     GetOSPFRoutes, GetBGPNeighborReceivedRoutes,
//     GetBGPNeighborAdvertisedRoutes, GetBGPNeighborDetail.
package frr

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"syscall"
	"time"
)

// vtyshTimeout bounds every `vtysh -c` shell-out. Vtysh backs the
// show/clear operational paths (status_parse.go, ExecVtysh via
// gRPC/CLI), not the apply path — but a wedged vtysh (zebra hung, FRR
// mid-restart) would hang those gRPC/CLI handlers indefinitely, the
// same hang class #1794 bounded elsewhere. Same 15s budget as
// reloadTimeout (manager.go), which already covers FrrReloadPy /
// VtyshLoad via caller-supplied contexts. #1794/#1800.
const vtyshTimeout = 15 * time.Second

// frrReloadScript is the FRR diff-reload engine (frr-pythontools
// package). Invoked DIRECTLY — never via `systemctl reload frr`: on
// FRR 10.6 the unit's ExecReload (frrinit.sh reload) unconditionally
// restarts watchfrr, which is the Type=forking unit's MainPID, so every
// systemd-mediated reload cancels its own job, parks frr.service in
// stop-sigterm for TimeoutStopSec (2 minutes), and ends with systemd
// SIGKILLing every FRR daemon (#1880). Bypassing the systemd job
// machinery keeps the unit state untouched.
const frrReloadScript = "/usr/lib/frr/frr-reload.py"

// frrReloadOutputTail bounds how much frr-reload.py output a failure
// message carries (the interesting part is at the tail).
const frrReloadOutputTail = 1024

// frrExecutor is the package-private indirection that all vtysh and
// frr-reload.py shell-outs route through. Production code uses
// realExecutor; tests inject a fake. The interface is intentionally
// minimal: it covers only the three call shapes that exist in pkg/frr
// today.
type frrExecutor interface {
	// Vtysh runs `vtysh -c <command>` and returns stdout. Errors include
	// the captured stderr in the message string.
	Vtysh(command string) (string, error)

	// FrrReloadPy runs `frr-reload.py --reload <conf>` with the supplied
	// context (which carries the 15s reload timeout). The config path is
	// a parameter so tests that override Manager.frrConf exercise the
	// real wiring. A nil return means the FULL diff (including removals)
	// converged. (#1880 — replaces the retired SystemctlReload.)
	FrrReloadPy(ctx context.Context, conf string) error

	// VtyshLoad runs `vtysh -f <conf>` with the supplied context and
	// returns CombinedOutput (so the caller can include stderr in error
	// messages — preserves the historical behavior). NOTE: vtysh -f is
	// ADDITIVE — it re-applies every desired line but cannot remove
	// stale config; it is the degraded fallback only.
	VtyshLoad(ctx context.Context, conf string) ([]byte, error)
}

// realExecutor is the production frrExecutor. It is intentionally
// zero-field so it can be returned as a value from the zero-value
// accessor on Manager.
type realExecutor struct{}

// Vtysh runs `vtysh -c <command>` under vtyshTimeout and returns
// stdout. Output/error shape is identical to the historical vtyshCmd
// free function (frr.go:1597-1605 pre-split); the timeout bound was
// added in #1800 (U3).
func (realExecutor) Vtysh(command string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), vtyshTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "vtysh", "-c", command)
	// WaitDelay caps the post-SIGKILL pipe-drain window.
	cmd.WaitDelay = 5 * time.Second
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("vtysh %q: %w: %s", command, err, stderr.String())
	}
	return stdout.String(), nil
}

// FrrReloadPy runs `frr-reload.py --reload <conf>` under ctx.
//
// Process-group teardown contract (#1880): frr-reload.py spawns vtysh
// children to apply the diff; exec.CommandContext's default Cancel
// kills only the direct python process, which could leave a child
// vtysh writer racing the fallback `vtysh -f`. Setpgid puts the whole
// tree in its own process group and Cancel SIGKILLs the group, so by
// the time Run returns (bounded by WaitDelay) no child writer
// survives.
func (realExecutor) FrrReloadPy(ctx context.Context, conf string) error {
	cmd := exec.CommandContext(ctx, frrReloadScript, "--reload", conf)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		// Negative pid = the whole process group (Setpgid above).
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	// WaitDelay caps the post-SIGKILL pipe-drain window; the fallback
	// is only entered after Run (i.e. Wait) returns.
	cmd.WaitDelay = 5 * time.Second
	out, err := cmd.CombinedOutput()
	if err != nil {
		if len(out) > frrReloadOutputTail {
			out = out[len(out)-frrReloadOutputTail:]
		}
		return fmt.Errorf("%s --reload %s: %w: %s", frrReloadScript, conf, err, out)
	}
	return nil
}

// VtyshLoad runs `vtysh -f <conf>` under ctx and returns CombinedOutput.
// Mirrors the historical reload() fallback (frr.go:1068-1069 pre-split).
func (realExecutor) VtyshLoad(ctx context.Context, conf string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "vtysh", "-f", conf)
	// WaitDelay caps the post-SIGKILL pipe-drain window (apply-reachable
	// via the FRR reload fallback).
	cmd.WaitDelay = 5 * time.Second
	return cmd.CombinedOutput()
}

// ExecVtysh runs an arbitrary vtysh command and returns the output.
func (m *Manager) ExecVtysh(command string) (string, error) {
	return m.executor().Vtysh(command)
}

// GetBFDPeers returns BFD peer status from FRR.
func (m *Manager) GetBFDPeers() (string, error) {
	return m.executor().Vtysh("show bfd peers")
}

// GetRouteMapList returns the route-map configuration from FRR.
func (m *Manager) GetRouteMapList() (string, error) {
	return m.executor().Vtysh("show route-map")
}

// GetISISAdjacencyDetail returns detailed IS-IS adjacency output.
func (m *Manager) GetISISAdjacencyDetail() (string, error) {
	return m.executor().Vtysh("show isis neighbor detail")
}

// GetISISDatabase returns raw IS-IS link-state database output.
func (m *Manager) GetISISDatabase() (string, error) {
	return m.executor().Vtysh("show isis database detail")
}

// GetISISRoutes returns raw IS-IS route output.
func (m *Manager) GetISISRoutes() (string, error) {
	return m.executor().Vtysh("show isis route")
}

// GetOSPFNeighborDetail returns detailed OSPF neighbor output.
func (m *Manager) GetOSPFNeighborDetail() (string, error) {
	return m.executor().Vtysh("show ip ospf neighbor detail")
}

// GetOSPFDatabase returns raw OSPF database output.
func (m *Manager) GetOSPFDatabase() (string, error) {
	return m.executor().Vtysh("show ip ospf database")
}

// GetOSPFInterface returns raw OSPF interface output.
func (m *Manager) GetOSPFInterface() (string, error) {
	return m.executor().Vtysh("show ip ospf interface")
}

// GetOSPFRoutes returns raw OSPF route output.
func (m *Manager) GetOSPFRoutes() (string, error) {
	return m.executor().Vtysh("show ip ospf route")
}

// GetBGPNeighborReceivedRoutes returns received routes for a BGP neighbor.
func (m *Manager) GetBGPNeighborReceivedRoutes(ip string) (string, error) {
	if ip == "" {
		return "", fmt.Errorf("neighbor IP required")
	}
	return m.executor().Vtysh("show bgp neighbor " + ip + " received-routes")
}

// GetBGPNeighborAdvertisedRoutes returns advertised routes for a BGP neighbor.
func (m *Manager) GetBGPNeighborAdvertisedRoutes(ip string) (string, error) {
	if ip == "" {
		return "", fmt.Errorf("neighbor IP required")
	}
	return m.executor().Vtysh("show bgp neighbor " + ip + " advertised-routes")
}

// GetBGPNeighborDetail returns detailed info for a specific BGP neighbor,
// or all neighbors if ip is empty.
func (m *Manager) GetBGPNeighborDetail(ip string) (string, error) {
	cmd := "show bgp neighbor"
	if ip != "" {
		cmd += " " + ip
	}
	return m.executor().Vtysh(cmd)
}
