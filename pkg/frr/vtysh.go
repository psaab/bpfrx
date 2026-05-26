// vtysh.go holds the FRR shell-out surface for the package.
//
// All vtysh + systemctl shell-outs go through the frrExecutor interface
// so tests can inject fakes. realExecutor wraps os/exec and is the
// production default; New() pre-populates Manager.exec with it.
//
// Symbols:
//   - frrExecutor interface (Vtysh / SystemctlReload / VtyshLoad)
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
)

// frrExecutor is the package-private indirection that all vtysh and
// systemctl shell-outs route through. Production code uses realExecutor;
// tests inject a fake. The interface is intentionally minimal: it covers
// only the three call shapes that exist in pkg/frr today.
type frrExecutor interface {
	// Vtysh runs `vtysh -c <command>` and returns stdout. Errors include
	// the captured stderr in the message string.
	Vtysh(command string) (string, error)

	// SystemctlReload runs `systemctl reload frr` with the supplied
	// context (which carries the 15s reload timeout). Output is dropped;
	// only error is returned (mirrors the historical cmd.Run() shape).
	SystemctlReload(ctx context.Context) error

	// VtyshLoad runs `vtysh -f <conf>` with the supplied context and
	// returns CombinedOutput (so the caller can include stderr in error
	// messages — preserves the historical behavior).
	VtyshLoad(ctx context.Context, conf string) ([]byte, error)
}

// realExecutor is the production frrExecutor. It is intentionally
// zero-field so it can be returned as a value from the zero-value
// accessor on Manager.
type realExecutor struct{}

// Vtysh runs `vtysh -c <command>` and returns stdout. Bytes-identical to
// the historical vtyshCmd free function (frr.go:1597-1605 pre-split).
func (realExecutor) Vtysh(command string) (string, error) {
	cmd := exec.Command("vtysh", "-c", command)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("vtysh %q: %w: %s", command, err, stderr.String())
	}
	return stdout.String(), nil
}

// SystemctlReload runs `systemctl reload frr` under ctx. Mirrors the
// historical reload() systemctl branch (frr.go:1061-1064 pre-split).
func (realExecutor) SystemctlReload(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "systemctl", "reload", "frr")
	return cmd.Run()
}

// VtyshLoad runs `vtysh -f <conf>` under ctx and returns CombinedOutput.
// Mirrors the historical reload() fallback (frr.go:1068-1069 pre-split).
func (realExecutor) VtyshLoad(ctx context.Context, conf string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "vtysh", "-f", conf)
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
