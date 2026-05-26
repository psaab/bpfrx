// Package frr generates FRR configuration and queries routing state via vtysh.
//
// The package is split across sibling files:
//   - manager.go:        Manager lifecycle + top-level types + ApplyFull
//     orchestration + writeManagedSection + reload.
//   - config_render.go:  Non-protocol config rendering (interface settings,
//     static routes, generate-routes, DHCP defaults,
//     backup-router, cluster-mode defaults, ECMP).
//   - policy_render.go:  Protocols + policy rendering (OSPF/OSPFv3/BGP/RIP/
//     ISIS, policy-options, redistribute, BFD profile
//     dedup, ifaceNetwork helper).
//   - vtysh.go:          frrExecutor interface + realExecutor + thin raw
//     Get* shells.
//   - status_parse.go:   Parsed Get* methods + their public types +
//     parseRouteJSON / FormatRouteDetail.
package frr

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

const (
	// DefaultFRRConf is the main FRR config file.
	DefaultFRRConf = "/etc/frr/frr.conf"

	markerBegin = "! BEGIN BPFRX MANAGED CONFIG - do not edit this section"
	markerEnd   = "! END BPFRX MANAGED CONFIG"

	// reloadTimeout is the maximum time we wait for `systemctl reload frr`
	// or the `vtysh -f` fallback to complete before giving up. The systemd
	// unit has TimeoutStopSec=20 as the outer safety net; this timeout is
	// the inner shutdown-correctness invariant documented in
	// docs/engineering-style.md.
	reloadTimeout = 15 * time.Second
)

// Manager handles FRR config generation and state queries.
type Manager struct {
	frrConf string
	// exec drives every vtysh / systemctl shell-out. Initialized in New().
	// Tests inject a fake. A nil exec is tolerated via the executor()
	// accessor — see executor() below.
	exec frrExecutor
}

// New creates a new FRR manager.
func New() *Manager {
	return &Manager{
		frrConf: DefaultFRRConf,
		exec:    realExecutor{},
	}
}

// executor returns m.exec if set, or a default realExecutor otherwise.
// This preserves the contract that `var m frr.Manager; m.ExecVtysh(...)`
// (a zero-value Manager) does not panic — useful for same-package tests
// and historical callers that constructed a literal Manager.
func (m *Manager) executor() frrExecutor {
	if m.exec == nil {
		return realExecutor{}
	}
	return m.exec
}

// InstanceConfig pairs routing config with a VRF name for per-instance generation.
type InstanceConfig struct {
	VRFName           string
	OSPF              *config.OSPFConfig
	OSPFv3            *config.OSPFv3Config
	BGP               *config.BGPConfig
	RIP               *config.RIPConfig
	ISIS              *config.ISISConfig
	StaticRoutes      []*config.StaticRoute
	Inet6StaticRoutes []*config.StaticRoute
}

// DHCPRoute represents a default route learned via DHCP.
type DHCPRoute struct {
	Gateway   string // "10.0.2.1" or "fe80::1"
	Interface string // needed for IPv6 link-local gateways
	IsIPv6    bool
}

// FullConfig holds the complete routing config for a single FRR apply.
type FullConfig struct {
	OSPF              *config.OSPFConfig
	OSPFv3            *config.OSPFv3Config
	BGP               *config.BGPConfig
	RIP               *config.RIPConfig
	ISIS              *config.ISISConfig
	StaticRoutes      []*config.StaticRoute
	Inet6StaticRoutes []*config.StaticRoute // rib inet6.0 static routes
	GenerateRoutes    []*config.GenerateRoute
	DHCPRoutes        []DHCPRoute
	Instances         []InstanceConfig
	PolicyOptions     *config.PolicyOptionsConfig

	// ForwardingTableExport is the export policy for the forwarding table (ECMP).
	ForwardingTableExport string

	// BackupRouter is the fallback default gateway (system backup-router).
	// Installed with admin distance 250 so it's only used when all other defaults fail.
	BackupRouter    string // next-hop IP (e.g. "192.168.50.1")
	BackupRouterDst string // destination prefix (e.g. "192.168.0.0/16"), default "0.0.0.0/0"

	// InterfaceBandwidths maps interface names to bandwidth in bits per second.
	// FRR emits "bandwidth <kbps>" in interface blocks (used by OSPF auto-cost).
	InterfaceBandwidths map[string]uint64

	// InterfacePointToPoint maps interface names to point-to-point flag.
	// When true and no explicit OSPF network-type is set, emits "ip ospf network point-to-point".
	InterfacePointToPoint map[string]bool

	// RethMap maps reth name → physical member name (e.g. "reth0" → "ge-0-0-1").
	// Used to translate RETH interface names in static routes to kernel names.
	RethMap map[string]string

	// IPv6NextHopInterfaces maps VRF name -> IPv6 next-hop -> interface for
	// global and per-instance static routes that omit an explicit interface.
	// Values may still be logical interface names (for example, "reth0.50");
	// any later translation to kernel/physical names is handled separately via
	// RethMap. The global table uses the empty-string VRF key.
	IPv6NextHopInterfaces map[string]map[string]string

	// ConsistentHash is set when the forwarding-table export policy uses
	// "load-balance consistent-hash". The daemon should set
	// net.ipv4.fib_multipath_hash_policy=1 for L4 ECMP hashing.
	//
	// NOTE: ApplyFull mutates this field as a side effect of resolveECMP().
	// See resolveECMP() in config_render.go.
	ConsistentHash bool

	// ClusterMode adds a blackhole default route with high admin distance
	// (250) as a safety net for active/active per-RG failover.  When the
	// WAN VIP moves to the peer, FRR withdraws the real default route
	// (next-hop unreachable).  The blackhole default makes bpf_fib_lookup
	// return BPF_FIB_LKUP_RET_BLACKHOLE instead of NOT_FWDED, triggering
	// zone-encoded fabric redirect for new connections.  The real default
	// route (AD 5 or 200) always takes priority when present.
	ClusterMode bool
}

// Apply generates an FRR config from OSPF/BGP settings and reloads FRR.
func (m *Manager) Apply(ospf *config.OSPFConfig, bgp *config.BGPConfig) error {
	return m.ApplyFull(&FullConfig{
		OSPF: ospf,
		BGP:  bgp,
	})
}

// ApplyWithInstances generates an FRR config with optional per-VRF routing
// instances and reloads FRR.
func (m *Manager) ApplyWithInstances(ospf *config.OSPFConfig, bgp *config.BGPConfig, instances []InstanceConfig) error {
	return m.ApplyFull(&FullConfig{
		OSPF:      ospf,
		BGP:       bgp,
		Instances: instances,
	})
}

// ApplyFull generates the complete FRR config including static routes,
// DHCP-learned defaults, per-VRF routes, and dynamic protocols, then
// reloads FRR.
//
// Emission order (preserved as a contract — many FRR parsers depend on
// it; in particular, interface bandwidth must precede OSPF so auto-cost
// picks it up):
//
//  1. global static routes
//  2. generate-routes (blackhole)
//  3. inet6 static routes
//  4. DHCP-learned defaults (admin distance 200)
//  5. backup-router (admin distance 250)
//  6. cluster-mode blackhole defaults (admin distance 250)
//  7. per-VRF static routes
//  8. policy-options (prefix-lists, route-maps, communities)
//  9. interface settings (bandwidth, point-to-point)
//  10. global dynamic protocols (OSPF/OSPFv3/BGP/RIP/ISIS)
//  11. per-VRF dynamic protocols
func (m *Manager) ApplyFull(fc *FullConfig) error {
	if fc == nil {
		return m.Clear()
	}

	hasContent := fc.OSPF != nil || fc.OSPFv3 != nil || fc.BGP != nil || fc.RIP != nil || fc.ISIS != nil ||
		len(fc.StaticRoutes) > 0 || len(fc.Inet6StaticRoutes) > 0 || len(fc.GenerateRoutes) > 0 || len(fc.DHCPRoutes) > 0 || fc.BackupRouter != "" || fc.ClusterMode
	for _, inst := range fc.Instances {
		if inst.OSPF != nil || inst.OSPFv3 != nil || inst.BGP != nil || inst.RIP != nil || inst.ISIS != nil || len(inst.StaticRoutes) > 0 || len(inst.Inet6StaticRoutes) > 0 {
			hasContent = true
			break
		}
	}
	if !hasContent {
		return m.Clear()
	}

	var b strings.Builder
	b.WriteString("! xpf managed config - do not edit\n")
	b.WriteString("!\n")

	// 1. Global static routes
	if len(fc.StaticRoutes) > 0 {
		for _, sr := range fc.StaticRoutes {
			b.WriteString(m.generateStaticRoute(sr, "", fc.RethMap, fc.IPv6NextHopInterfaces))
		}
		b.WriteString("!\n")
	}

	// 2. Generate (aggregate) routes — rendered as blackhole static routes
	renderGenerateRoutes(&b, fc)

	// 3. IPv6 RIB static routes (rib inet6.0)
	if len(fc.Inet6StaticRoutes) > 0 {
		for _, sr := range fc.Inet6StaticRoutes {
			b.WriteString(m.generateStaticRoute(sr, "", fc.RethMap, fc.IPv6NextHopInterfaces))
		}
		b.WriteString("!\n")
	}

	// 4. DHCP-learned default routes (admin distance 200).
	renderDHCPDefaults(&b, fc)

	// 5. Backup router: fallback default gateway with admin distance 250
	renderBackupRouter(&b, fc)

	// 6. Cluster mode: blackhole default route as fallback for fabric redirect.
	renderClusterModeDefaults(&b, fc)

	// 7. Per-VRF static routes
	for _, inst := range fc.Instances {
		if len(inst.StaticRoutes) > 0 || len(inst.Inet6StaticRoutes) > 0 {
			for _, sr := range inst.StaticRoutes {
				b.WriteString(m.generateStaticRoute(sr, inst.VRFName, fc.RethMap, fc.IPv6NextHopInterfaces))
			}
			for _, sr := range inst.Inet6StaticRoutes {
				b.WriteString(m.generateStaticRoute(sr, inst.VRFName, fc.RethMap, fc.IPv6NextHopInterfaces))
			}
			b.WriteString("!\n")
		}
	}

	// 8. Policy options: prefix-lists and route-maps
	if fc.PolicyOptions != nil {
		b.WriteString(m.generatePolicyOptions(fc.PolicyOptions))
	}

	// Resolve forwarding-table export policy for ECMP. Sets fc.ConsistentHash
	// as a side effect when the policy uses "load-balance consistent-hash".
	ecmpMaxPaths := resolveECMP(fc)

	// 9. Interface-level settings (bandwidth, point-to-point)
	b.WriteString(m.generateInterfaceSettings(fc))

	// 10. Global dynamic protocols
	if fc.OSPF != nil || fc.OSPFv3 != nil || fc.BGP != nil || fc.RIP != nil || fc.ISIS != nil {
		b.WriteString(m.generateProtocols(fc.OSPF, fc.OSPFv3, fc.BGP, fc.RIP, fc.ISIS, "", ecmpMaxPaths, fc.PolicyOptions))
	}

	// 11. Per-VRF dynamic protocols
	for _, inst := range fc.Instances {
		if inst.OSPF != nil || inst.OSPFv3 != nil || inst.BGP != nil || inst.RIP != nil || inst.ISIS != nil {
			b.WriteString(m.generateProtocols(inst.OSPF, inst.OSPFv3, inst.BGP, inst.RIP, inst.ISIS, inst.VRFName, ecmpMaxPaths, fc.PolicyOptions))
		}
	}

	section := b.String()

	if err := m.writeManagedSection(section); err != nil {
		return err
	}

	slog.Info("FRR config written", "path", m.frrConf)

	// Reload FRR (frr-reload.py diffs running vs on-disk config)
	if err := m.reload(); err != nil {
		slog.Warn("FRR reload failed", "err", err)
		return err
	}

	return nil
}

// Clear removes the xpf managed section from frr.conf and reloads FRR.
func (m *Manager) Clear() error {
	if err := m.writeManagedSection(""); err != nil {
		return err
	}
	_ = m.reload()
	return nil
}

// writeManagedSection replaces the xpf-managed section in frr.conf.
// If section is empty, the managed block is removed entirely.
func (m *Manager) writeManagedSection(section string) error {
	existing, err := os.ReadFile(m.frrConf)
	if err != nil {
		if os.IsNotExist(err) {
			existing = []byte("log syslog informational\n")
		} else {
			return fmt.Errorf("read frr.conf: %w", err)
		}
	}

	// Strip existing managed section
	content := string(existing)
	if start := strings.Index(content, markerBegin); start >= 0 {
		end := strings.Index(content, markerEnd)
		if end >= 0 {
			end += len(markerEnd)
			// Also consume the trailing newline
			if end < len(content) && content[end] == '\n' {
				end++
			}
			content = content[:start] + content[end:]
		}
	}

	// Append new managed section
	if section != "" {
		content = strings.TrimRight(content, "\n") + "\n"
		content += markerBegin + "\n"
		content += section
		content += markerEnd + "\n"
	}

	if err := os.WriteFile(m.frrConf, []byte(content), 0644); err != nil {
		return fmt.Errorf("write frr.conf: %w", err)
	}
	return nil
}

// reload reloads FRR via systemctl, falling back to vtysh -f if systemctl
// reload fails. The 15s context timeout is the inner shutdown-correctness
// invariant — see reloadTimeout for the rationale.
func (m *Manager) reload() error {
	ctx, cancel := context.WithTimeout(context.Background(), reloadTimeout)
	defer cancel()

	// Try systemctl reload first (runs frr-reload.py which diffs running vs frr.conf)
	if err := m.executor().SystemctlReload(ctx); err == nil {
		slog.Info("FRR reloaded via systemctl")
		return nil
	}

	// Fallback: load config directly via vtysh
	output, err := m.executor().VtyshLoad(ctx, m.frrConf)
	if err != nil {
		return fmt.Errorf("vtysh reload: %w: %s", err, string(output))
	}
	slog.Info("FRR config loaded via vtysh")
	return nil
}
