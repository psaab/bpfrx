package daemon

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/vishvananda/netlink"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// applyDataplaneAndHACore runs the ordering-entangled dataplane-apply and
// RETH-MAC / VRRP-VIP / AF_XDP-worker-rebind critical section of a config
// apply (#4407). Extracted verbatim from applyConfigLocked; the head-produced
// state that the earlier decoupled phases do not touch stays local here —
// rethMACPending and the deferred-worker-startup flag/defer are self-contained
// — and the two values the tail still needs are returned: the ip-monitoring
// commit overlay (fed to applyRoutingRules and the FRR render), the captured
// networkd write error, and the DEFERRED ordinary dataplane-apply error
// (#5679) — both threaded into applyTailReconciles' Join. The three early
// error returns — the two #2926 context-abort boundaries (ctx.Err() before
// ApplyConfig and before the FRR reload) and the compileErrorMustAbortApply
// dataplane abort on an ApplyConfig failure — are preserved; the caller bails
// (via the terminal `err` return) without running the routing / service / tail
// reconciles, exactly as the inline `return err` did.
//
// applyErr (#5679) is DISTINCT from that terminal `err`: an ORDINARY (non-abort
// -class) ApplyConfig failure does NOT disarm the dataplane — the OLD compiled
// config stays live and forwarding — so the tail reconciles MUST still run
// (fail-closed but complete, exactly like networkdErr / ifaceErr). It is
// returned as a deferred error the caller joins at the tail so the commit
// reports FAILURE rather than silently succeeding against the stale policy,
// instead of aborting the rest of the apply. commitOverlay, networkdErr, and
// applyErr are named returns so the pre-networkd boundaries can return them
// (nil) before the networkd / apply phases assign them. Runs in the same slot,
// after the fabric-IPVLAN reconcile and before the routing rules.
func (d *Daemon) applyDataplaneAndHACore(ctx context.Context, cfg *config.Config) (commitOverlay []config.RouteOverlayEntry, networkdErr error, applyErr error, err error) {
	// 1.9. Pre-check: will RETH MAC programming require a link cycle?
	// If yes, tell the userspace DP to skip initial worker startup during
	// ApplyConfig(). Workers will be started by NotifyLinkCycle() after MAC
	// programming is done. This avoids the double-bind that causes EBUSY
	// on mlx5 zero-copy queues.
	rethMACPending := false
	deferWorkersActive := false
	var clearDeferWorkers func()
	if d.cluster != nil && cfg.Chassis.Cluster != nil && d.dataplane() != nil {
		cc := cfg.Chassis.Cluster
		for rethName, physName := range cfg.RethToPhysical() {
			rethCfg, ok := cfg.Interfaces.Interfaces[rethName]
			if !ok || rethCfg == nil || rethCfg.RedundancyGroup <= 0 {
				continue
			}
			linuxName := config.LinuxIfName(physName)
			link, err := netlink.LinkByName(linuxName)
			if err != nil {
				continue
			}
			mac := cluster.RethMAC(cc.ClusterID, rethCfg.RedundancyGroup, cc.NodeID)
			if !bytes.Equal(link.Attrs().HardwareAddr, mac) {
				rethMACPending = true
				break
			}
		}
		if rethMACPending {
			d.setDataplaneDeferWorkers(true)
			deferWorkersActive = true
			clearDeferWorkers = func() {
				d.setDataplaneDeferWorkers(false)
			}
			defer func() {
				if deferWorkersActive {
					clearDeferWorkers()
				}
			}()
		}
	}

	policySchedulerApplyTime := time.Now()
	policySchedulerActiveState := d.policySchedulerActiveStateForApplyLocked(cfg, policySchedulerApplyTime)
	d.seedPolicySchedulerActiveStateLocked(policySchedulerActiveState)

	// 1.95. Refresh the dataplane's ip-monitoring overlay cache from
	// the engine BEFORE the full snapshot build (#1827, AGY r2-2): an
	// operator commit while a policy is FAILED must rebuild routes
	// with the active overlay instead of wiping the injected failover
	// route until the next engine tick. The overlay is filtered
	// against the INCOMING config (Codex PR #1843 HIGH-1) so a commit
	// that removes or edits a policy never republishes the stale
	// entries; the same filtered view feeds the FRR render in step 3.
	commitOverlay = d.commitOverlayForConfig(cfg)
	if setter, ok := d.dataplane().(routeOverlaySetter); ok {
		setter.SetRouteOverlay(commitOverlay)
	}

	// 1.95. Reconcile the running dynamic-address feed-producer set against
	// this config generation BEFORE reading its overlay (#5036). This is what
	// makes a day-2 feed-server add/remove/edit take effect: the feed manager
	// is constructed unconditionally at boot, and this hash-gated Apply starts
	// the replacement producers (and joins removed ones) whenever the
	// feed-server config changes. A feed CONTENT refresh leaves the hash
	// unchanged, so it does not restart the fetchers. Must run before the
	// SetFeedSnapshots overlay push below so the overlay reflects the
	// reconciled generation (the fresh snapshot lands asynchronously and its
	// onUpdate re-applies, exactly as at boot).
	d.reconcileFeeds(cfg)

	// 1.96. Refresh the dataplane's dynamic-address feed overlay from the
	// feed manager BEFORE the full snapshot build (#2049). The feed manager
	// fetches threat-feed/allowlist prefixes and its onUpdate callback
	// re-enters applyConfig against the SAME *config.Config; without this
	// hand-off the address book the helper enforces would never see the
	// feed prefixes (the never-enforced gap #2049 closes). The overlay is
	// joined against the INCOMING config's bindings so a commit that removes
	// a binding stops enforcing its feed. Mirrors SetRouteOverlay above.
	if setter, ok := d.dataplane().(feedSnapshotSetter); ok {
		setter.SetFeedSnapshots(d.feedSnapshotsForConfig(cfg))
	}

	// #2926 boundary C2: before the dataplane apply (the Rust control-socket
	// sync push). The fabric-IPVLAN / VRF / tunnel / bond netlink reconciles
	// above are idempotent and have each run to completion, so bailing here
	// leaves a consistent kernel state with the dataplane untouched. Once
	// the dataplane ApplyConfig and the RETH MAC / VIP / worker-rebind sequence that
	// follows it begin, they run as one unit (no mid-sequence abort) — the
	// next boundary is before the FRR reload.
	if err := ctx.Err(); err != nil {
		return commitOverlay, networkdErr, nil, err
	}

	// 2. Apply dataplane config through the runtime config sink.
	var applyResult *dataplane.ApplyResult
	if rt := d.dataplane(); rt != nil {
		var err error
		if applyResult, err = rt.ApplyConfig(context.Background(), cfg); err != nil {
			d.recordCompileFailure(err)
			if compileErrorMustAbortApply(err) {
				return commitOverlay, networkdErr, nil, err
			}
			// #5679: an ORDINARY (non-abort-class) full-apply failure does
			// NOT disarm the dataplane — the dataplane ApplyConfig leaves the OLD
			// compiled policy live and forwarding while store.Commit has
			// already promoted+persisted the NEW config. Left unhandled the
			// commit reported SUCCESS against stale enforcement (a tightening
			// commit — e.g. a new deny — appeared applied while the looser old
			// policy was still on the wire), a fail-open-to-stale on the main
			// config-apply path. Capture the failure as a DEFERRED commit error
			// (threaded into the tail Join, fail-closed but complete like
			// networkdErr / ifaceErr) so the operator sees the commit fail; the
			// applied config never advanced, so an identical re-commit / the
			// feed onUpdate retry (#5646, via applyConfigResult) re-applies and
			// self-heals a transient helper / control-socket error.
			applyErr = err
		} else {
			d.recordCompileSuccess()
		}
	}
	policySchedulerActiveState = d.reconcilePolicySchedulerLockedAt(cfg, policySchedulerApplyTime)
	d.publishInitialPolicySchedulerStateLocked(cfg, policySchedulerActiveState, applyResult)

	// Clear defer flag after ApplyConfig so subsequent applies (where MAC
	// is already set) don't skip workers.
	if deferWorkersActive {
		clearDeferWorkers()
		deferWorkersActive = false
	}

	// 2.1. Wire aggressive session aging config to GC.
	if d.gc != nil {
		d.gc.SetAgingConfig(
			cfg.Security.Flow.AgingEarlyAgeout,
			cfg.Security.Flow.AgingHighWatermark,
			cfg.Security.Flow.AgingLowWatermark,
		)

		// Enable per-IP session counting if any screen profile has session limits.
		sessionLimitEnabled := false
		for _, sp := range cfg.Security.Screen {
			if sp.LimitSession.SourceIPBased > 0 || sp.LimitSession.DestinationIPBased > 0 {
				sessionLimitEnabled = true
				break
			}
		}
		d.gc.SetSessionLimitEnabled(sessionLimitEnabled)
	}

	// 2.2. Build zone→RG map for per-RG session sync.
	if ss := d.getSessionSync(); ss != nil && applyResult != nil {
		ss.SetZoneRGMap(buildZoneRGMap(cfg, applyResult.ZoneIDs))
	}

	// 2.45. #1956 V-4: managed->unmapped teardown MUST run BEFORE
	// networkd.Apply so its stale-file sweep has nothing to half-clean.
	// No-op idempotent when nothing transitioned (zero churn on an
	// unrelated commit).
	//
	// A genuine teardown failure (rename-back EBUSY/collision or networkctl
	// reload failure) is now RETURNED and RETAINS the durable .link/.network
	// markers (#5309). It is captured into networkdErr (the interface-management
	// error already threaded into the tail commit join) so the commit fails
	// CLOSED instead of reporting success while the wrong live interface name
	// persists and the retry debt is destroyed. errors.Join preserves any error
	// the later networkd.Apply also records.
	if cfg.Chassis.DeviceMap.Active() {
		if err := teardownUnmappedManaged(cfg.Chassis.DeviceMap, protectedForConfig(cfg)); err != nil {
			slog.Warn("device-map teardown failed; retaining durable state, failing commit closed",
				"err", err)
			networkdErr = errors.Join(networkdErr, err)
		}
	}

	// 2.5. Write systemd-networkd config for managed interfaces.
	//
	// An empty ManagedInterfaces set is NOT a no-op (#2988): when the last
	// xpf-managed interface is removed, networkd.Apply must still run so its
	// stale `10-xpf-*` sweep cleans the now-orphaned .network/.link/.netdev
	// snippets (otherwise the next reload resurrects stale addresses/bonds/
	// renames). The previous `len(...) > 0` guard shadowed the sweep, leaving
	// the library fix dead on the live reconcile path. The lifeline is still
	// protected end-to-end: SetProtectedResolver (daemon_run.go) feeds
	// resolveProtectedInterfaces, which derives the mgmt set from
	// ActiveConfig independently of ManagedInterfaces, so the empty-set sweep
	// preserves the management NIC's files. The `applyResult != nil` guard
	// stays — a nil result (no dataplane) means there is nothing to reconcile
	// and the daemon's own startup/Clear paths own the files.
	//
	// A write failure is captured (not swallowed, #2987) and returned at the
	// tail of applyConfigLocked so the commit reports failure (fail-closed),
	// mirroring dhcpServerErr: every downstream reconcile step still runs so a
	// networkd write error does not skip RETH MAC programming, VRRP VIP
	// reconcile, FRR, RA, IPsec, etc. and leave HA state half-applied.
	if d.networkd != nil && applyResult != nil {
		if err := d.networkd.Apply(applyResult.ManagedInterfaces); err != nil {
			slog.Warn("failed to apply networkd config", "err", err)
			// errors.Join (not assignment) so a device-map teardown failure
			// recorded just above (#5309) is not clobbered — both fail-closed.
			networkdErr = errors.Join(networkdErr, fmt.Errorf("apply networkd config: %w", err))
		}
	}

	// 2.6. Program deterministic virtual MACs on RETH member interfaces.
	// Each node gets a per-node MAC (02:bf:72:CC:RR:NN) to avoid FDB conflicts
	// when both nodes' members are on the same L2 domain. VRRP + gratuitous NA
	// handle failover; RA goodbye packets handle IPv6 default gateway transitions.
	// Must run AFTER networkd.Apply() so .link renames are applied first.
	needLinkCycleRecovery := false
	if d.cluster != nil && cfg.Chassis.Cluster != nil {
		cc := cfg.Chassis.Cluster
		rethToPhys := cfg.RethToPhysical()

		// PrepareLinkCycle is called on-demand after programRethMAC reports
		// an actual link DOWN/UP cycle. Most drivers (mlx5, virtio) support
		// IFF_LIVE_ADDR_CHANGE so no cycle is needed and workers keep running.

		for rethName, physName := range rethToPhys {
			rethCfg, ok := cfg.Interfaces.Interfaces[rethName]
			if !ok || rethCfg == nil || rethCfg.RedundancyGroup <= 0 {
				continue
			}
			linuxName := config.LinuxIfName(physName)
			// If the interface doesn't exist under its config name,
			// find it by RETH virtual MAC and rename it.
			if _, err := netlink.LinkByName(linuxName); err != nil {
				mac := cluster.RethMAC(cc.ClusterID, rethCfg.RedundancyGroup, cc.NodeID)
				if oldName := renameRethMember(linuxName, mac); oldName != "" {
					slog.Info("renamed RETH member interface",
						"from", oldName, "to", linuxName)
					fixRethLinkFile(linuxName, oldName)
				}
			}
			// Ensure the .link file uses OriginalName= (not MACAddress=)
			// for stable matching across reboots. The bootstrap .link
			// files may use MACAddress= which breaks after virtual MAC
			// programming — the interface reboots with physical MAC but
			// the MACAddress= line might reference the wrong one.
			ensureRethLinkOriginalName(linuxName)
			setRethIPv6Knobs(linuxName)
			mac := cluster.RethMAC(cc.ClusterID, rethCfg.RedundancyGroup, cc.NodeID)
			linkCycled, err := programRethMAC(linuxName, mac)
			if err != nil {
				slog.Warn("failed to set RETH MAC", "iface", linuxName, "mac", mac, "err", err)
			}
			if linkCycled && !needLinkCycleRecovery {
				// First link cycle — stop workers NOW (they may have
				// been accessing UMEM during the DOWN/UP). The rebind
				// in NotifyLinkCycle will restart them.
				if rt := d.dataplane(); rt != nil {
					slog.Info("userspace: stopping workers after RETH MAC link cycle")
					rt.Link().PrepareLinkCycle()
				}
			}
			needLinkCycleRecovery = needLinkCycleRecovery || linkCycled
			clearDadFailed(linuxName)
			removeAutoLinkLocal(linuxName)
			// Re-add link-local if this parent interface has IPv6 on unit 0.
			// NDP Neighbor Solicitation requires a link-local source address.
			if rethUnitHasIPv6(rethCfg, 0) {
				ensureRethLinkLocal(linuxName)
			}

			// Re-disable VLAN RX offload after MAC programming.
			// The iavf VF driver resets ethtool features (including
			// rx-vlan-offload) during the link down/up cycle that
			// programRethMAC requires. Without this, XDP cannot see
			// VLAN tags in the packet data and drops VLAN traffic.
			if out, err := runCommandTimeout("ethtool", "-K", linuxName, "rxvlan", "off"); err != nil {
				slog.Warn("failed to re-disable rxvlan after RETH MAC",
					"interface", linuxName, "err", err, "output", strings.TrimSpace(string(out)))
			} else {
				slog.Info("re-disabled VLAN RX offload after RETH MAC", "interface", linuxName)
			}

			// Propagate MAC change to VLAN sub-interfaces.
			// Linux VLAN sub-interfaces don't always inherit the
			// parent's MAC change after link down/up.
			if parentLink, err := netlink.LinkByName(linuxName); err == nil {
				parentIdx := parentLink.Attrs().Index
				links, _ := netlink.LinkList()
				for _, l := range links {
					if l.Attrs().ParentIndex != parentIdx {
						continue
					}
					subName := l.Attrs().Name
					// Suppress auto link-local on VLAN sub-interfaces too.
					setVLANSubAddrGenMode(subName)
					if !bytes.Equal(l.Attrs().HardwareAddr, mac) {
						if err := netlink.LinkSetHardwareAddr(l, mac); err != nil {
							slog.Warn("failed to propagate MAC to VLAN sub-interface",
								"iface", subName, "err", err)
						} else {
							slog.Info("propagated RETH MAC to VLAN sub-interface",
								"iface", subName, "mac", mac)
						}
					}
					// Strip any stale auto link-local, then re-add a stable one
					// if this VLAN sub-interface carries IPv6. The kernel suffix
					// is the unit's vlan-id (e.g. "ge-7-0-1.180"), which may
					// differ from the logical unit number rethCfg.Units is keyed
					// by (`unit 80 vlan-id 180`); the repair resolves the vlan-id
					// back to its unit(s) before checking for IPv6 — indexing
					// Units[vid] directly silently skipped the repair (#5107).
					// The whole decision+action lives in rethSubIfaceLinkLocalRepair
					// (spy-tested); this loop only enumerates the child netdevs.
					rethSubIfaceLinkLocalRepair(rethCfg, subName)
				}
			}
		}
	}

	// 2.6b. Reconcile VRRP VIPs and stable link-locals after RETH MAC
	// programming. Only needed when programRethMAC had to bring the
	// interface DOWN/UP (link cycle), which removes all addresses
	// including VRRP VIPs and stable link-locals.
	if needLinkCycleRecovery && d.isNoRethVRRP() {
		// Direct mode: re-add VIPs + stable link-locals for each RG
		// where we are primary.
		if d.cluster != nil {
			for _, rg := range cfg.Chassis.Cluster.RedundancyGroups {
				if d.cluster.IsLocalPrimary(rg.ID) {
					d.directAddVIPs(rg.ID)
					d.addStableRethLinkLocal(rg.ID)
					d.scheduleDirectAnnounce(rg.ID, "link-cycle-recovery")
				}
			}
		}
	} else if needLinkCycleRecovery && d.vrrpMgr != nil {
		d.vrrpMgr.ReconcileVIPs()
		// Re-add stable link-locals for active RGs after MAC bounce.
		if d.cluster != nil && cfg.Chassis.Cluster != nil {
			for _, rg := range cfg.Chassis.Cluster.RedundancyGroups {
				s := d.getOrCreateRGState(rg.ID)
				if s.IsActive() {
					d.addStableRethLinkLocal(rg.ID)
				}
			}
		}
	}

	// 2.6b2. Rebind AF_XDP sockets after RETH MAC programming.
	// Only needed when PrepareLinkCycle was called (macChangeNeeded=true
	// or rethMACPending=true). Calling NotifyLinkCycle without a prior
	// PrepareLinkCycle causes a spurious rebind that gets EBUSY on mlx5
	// zero-copy queues because the first bind is still in progress.
	if rt := d.dataplane(); rt != nil && needLinkCycleRecovery {
		// Actual link DOWN/UP occurred — old XSK sockets are dead.
		// Rebind to create fresh sockets on the reinitialized queues.
		rt.Link().NotifyLinkCycle()
		if d.ra != nil {
			d.ra.ResendBurst()
		}
	} else if rt != nil && rethMACPending && !needLinkCycleRecovery {
		// MAC set live (no link cycle) but workers were deferred.
		// Trigger a re-apply to start workers with the now-correct MAC.
		// This is cheaper than NotifyLinkCycle (no stop_workers/rebind).
		d.reapplyAfterDeferredMAC(cfg)
	}

	// NOTE: stable link-local cleanup for secondary RGs is handled by
	// the reconcile loop (reconcileRGState) after election settles,
	// not here — we don't know who's primary during config apply.

	// 2.6c. Reconcile proxy ARP/NDP entries for NAT addresses. Factored into
	// reconcileProxyARP so the always-on periodic re-assert loop (#2197 item
	// 2) can re-run the identical reconcile after a non-commit link cycle.
	d.reconcileProxyARP(cfg)

	// 2.7. Re-bind management VRF interfaces after networkd.Apply().
	// networkctl reconfigure strips VRF master bindings because networkd
	// considers the daemon-created vrf-mgmt device "unmanaged" and ignores
	// the VRF= directive. Re-bind here to restore VRF membership. This is the
	// AUTHORITATIVE management-VRF bind (post-networkd): #5700 surfaces its
	// failure into commit truth (joined into networkdErr — mirroring the #1956
	// device-map-teardown joins above) instead of swallowing at WARN, so a
	// genuine bind failure fails the commit closed rather than reporting the
	// management VRF configured while the interface carries no VRF membership.
	// The management interfaces (fxp*/fab*/em*) exist by this phase, so the bind
	// is transient-free (unlike the pre-networkd best-effort bind and the
	// routing-instance tunnel-member binds in applyVRFReconcile).
	if mgmtSet := d.mgmtVRFIfaceSet(); d.routing != nil && len(mgmtSet) > 0 {
		if err := d.rebindManagementVRFIfaces(); err != nil {
			networkdErr = errors.Join(networkdErr, err)
		}
		// Restart heartbeat after VRF rebind — networkd reconfigure moves
		// the control interface (em0) out of vrf-mgmt temporarily, which
		// invalidates the heartbeat UDP sockets. Without this restart,
		// the recovering node stops receiving peer heartbeats and declares
		// split-brain after the grace period expires.
		if d.cluster != nil {
			d.cluster.RestartHeartbeat()
		}
	}

	// #2926 boundary C3: before the FRR reload. The dataplane apply and the
	// RETH MAC / VIP / worker-rebind sequence above have completed; FRR still
	// holds the previous render. Bailing here skips the FRR reload and the
	// remaining service reconciles (IPsec, DHCP, RA, VRRP, syslog, exporters);
	// on the next boot the boot-time apply re-renders FRR and re-runs every
	// service step against the active config, so the skip converges. (After
	// store.Commit the store already holds the new config, so this is a clean
	// "apply the rest on next start" boundary, not a divergence.)
	if err := ctx.Err(); err != nil {
		return commitOverlay, networkdErr, nil, err
	}

	return commitOverlay, networkdErr, applyErr, nil
}

func (d *Daemon) setDataplaneDeferWorkers(deferWorkers bool) {
	rt := d.dataplane()
	if rt == nil {
		return
	}
	type deferSetter interface{ SetDeferWorkers(bool) }
	if setter, ok := rt.(deferSetter); ok {
		setter.SetDeferWorkers(deferWorkers)
		return
	}
	rt.Link().SetDeferWorkers(deferWorkers)
}

// reapplyAfterDeferredMAC runs the MANDATORY dataplane re-apply that arms the
// deferred AF_XDP workers after a live RETH virtual-MAC change with no link
// cycle (#5134). The first apply of this commit published a workerless
// DeferWorkers=true snapshot (worker startup was deferred so the double-bind
// does not EBUSY on mlx5 zero-copy queues); this re-apply — now with the
// correct MAC and DeferWorkers cleared — is what actually starts the workers.
//
// If the re-apply fails, the error MUST NOT be swallowed into a successful
// commit: the userspace manager only advances its snapshot bookkeeping on a
// successful publish, so a failed re-apply leaves the workerless snapshot as
// the published/last state and status reconciliation replays it forever —
// workers never bind and forwarding is silently down on this node. Record
// generation debt so the status reconcile loop retries the DeferWorkers=false
// publish until the workers bind, self-healing a transient helper /
// control-socket error.
func (d *Daemon) reapplyAfterDeferredMAC(cfg *config.Config) {
	rt := d.dataplane()
	if rt == nil {
		return
	}
	if _, err := rt.ApplyConfig(context.Background(), cfg); err != nil {
		slog.Warn("failed to re-apply after deferred MAC; recording worker-arm debt for retry",
			"err", err)
		d.recordDataplaneWorkerArmDebt()
	}
}

// recordDataplaneWorkerArmDebt records the #5134 deferred-MAC worker-arm debt on
// the dataplane so status reconciliation retries the DeferWorkers=false publish.
// Mirrors setDataplaneDeferWorkers: assert the recorder directly on the
// dataplane, else reach it through the link controller.
func (d *Daemon) recordDataplaneWorkerArmDebt() {
	rt := d.dataplane()
	if rt == nil {
		return
	}
	type debtRecorder interface{ RecordDeferredWorkerArmDebt() }
	if r, ok := rt.(debtRecorder); ok {
		r.RecordDeferredWorkerArmDebt()
		return
	}
	if r, ok := rt.Link().(debtRecorder); ok {
		r.RecordDeferredWorkerArmDebt()
	}
}
