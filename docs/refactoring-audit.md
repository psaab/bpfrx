# Refactoring Audit: Large Files and Mixed Responsibilities

Generated: 2026-04-03

## Summary

13 Go files exceed 2000 lines, 5 Rust files exceed 2000 lines, and 1 test file
exceeds 10K lines. The largest offenders have clear internal boundaries where
splitting would improve navigability without disrupting the package API.

---

## Go Files (sorted by severity)

### 1. `pkg/grpcapi/server.go` — 8411 lines, 93 functions

**Problem:** Single file implements ALL 48+ gRPC RPCs plus server lifecycle,
config mode, completion, and utility helpers. Sessions were already split to
`server_sessions.go` — the same pattern should apply to other domains.

**Proposed split:**

| New file | Functions to move | Lines (est.) |
|----------|-------------------|-------------|
| `server_config.go` | `EnterConfigure`, `ExitConfigure`, `GetConfigModeStatus`, `Set`, `handleCopyRename`, `handleInsert`, `Delete`, `Load`, `Commit`, `CommitCheck`, `CommitConfirmed`, `ConfirmCommit`, `Rollback`, `ShowConfig`, `ShowCompare`, `ShowRollback`, `ListHistory` | ~1200 |
| `server_show.go` | `GetStatus`, `GetGlobalStats`, `GetZones`, `GetPolicies`, `GetScreen`, `GetEvents`, `GetInterfaces`, `ShowInterfacesDetail`, `showInterfacesTerse`, `writeKernelStats`, `GetSystemInfo`, `ShowText` | ~1500 |
| `server_nat.go` | `GetNATSource`, `GetNATDestination`, `GetNATPoolStats`, `GetNATRuleStats`, `GetVRRPStatus`, `GetPersistentNAT` | ~400 |
| `server_routing.go` | `GetRoutes`, `GetOSPFStatus`, `GetBGPStatus`, `GetRIPStatus`, `GetISISStatus`, `GetIPsecSA` | ~500 |
| `server_diag.go` | `Ping`, `Traceroute`, `streamDiagCmd`, `MonitorPacketDrop`, `MonitorInterface`, `proxyMonitorInterface`, `dialPeer`, `proxyPeerSystemAction`, `SystemAction` | ~600 |
| `server_dhcp.go` | `GetDHCPLeases`, `GetDHCPClientIdentifiers`, `ClearDHCPClientIdentifier` | ~200 |
| `server_cluster.go` | `buildInterfacesInput`, `MatchPolicies`, `matchPolicyAddr*`, `matchShowPolicy*`, `grpcResolveAddress`, `Complete`, `completePipeFilter`, `completeOperationalPairs`, `completeConfigPairs`, `valueProvider`, `ClearCounters` | ~800 |
| `server_helpers.go` | `resolveFabricParent`, `allInterfaceNames`, `policyActionStr`, `protoName`, `ntohs`, `uint32ToIP`, `resolveAppName`, `lookupAppFilter`, `screenChecks`, `fmtPref`, `boolStatus`, `writeChronyTracking`, `neighStateStr`, `writeNeighSummary`, `peerForwardedFromContext` | ~400 |

**What stays in `server.go`:** `Config` struct, `Server` struct, `NewServer`,
`Run`, `RunFabricListener`, `configLockInterceptor`, `peerSessionID`,
`userspaceDataplaneStatus`, `userspaceDataplaneControl` (~800 lines).

---

### 2. `pkg/cli/cli_show.go` — 7887 lines, 119 functions

**Problem:** Every `show` subcommand handler is in one file. This is the single
largest non-generated Go file. Functions fall into clear domain groups.

**Proposed split:**

| New file | Functions to move | Lines (est.) |
|----------|-------------------|-------------|
| `cli_show_security.go` | `showPoliciesHitCount`, `showPoliciesDetail`, `showZonesDisplay`, `showScreen*`, `showStatistics`, `showSecurityLog`, `showSecurityAlarms`, `showMatchPolicies`, `showALG` | ~1200 |
| `cli_show_nat.go` | `showNATSource*`, `showNATDestination*`, `showNATStatic`, `showNAT64`, `showNPTv6`, `showPersistentNAT*` | ~800 |
| `cli_show_flow.go` | `showFlowSession`, `showFlowTimeouts`, `showFlowStatistics`, `showFlowTraceoptions`, `showFlowMonitoring`, `showTopTalkers` | ~600 |
| `cli_show_routing.go` | `showRoutes`, `showRouteTerse`, `showRoutesForInstance`, `showRoutesForVRF`, `showRoutesForProtocol`, `showRoutesForPrefix`, `showRouteSummary`, `showRouteDetail`, `showOSPF`, `showBGP`, `showRIP`, `showISIS`, `showBFD`, `showRouteMap`, `showPolicyOptions`, `showRoutingOptions`, `showRoutingInstances` | ~1200 |
| `cli_show_interfaces.go` | `showInterfaces`, `showInterfacesDetail`, `showInterfacesTerse`, `showInterfacesExtensive*`, `showInterfacesStatistics`, `showVlans` | ~600 |
| `cli_show_system.go` | `showSystemBuffers*`, `showCoreDumps`, `showTask`, `showBackupRouter`, `showSystemNTP`, `showSystemServices`, `showSystemSyslog`, `showSystemUptime`, `showSystemBootMessages`, `showSystemMemory`, `showSystemProcesses`, `showSystemStorage`, `showSystemUsers`, `showSystemConnections`, `showVersion` | ~800 |
| `cli_show_cluster.go` | `showChassis`, `showChassisCluster*`, `showChassisEnvironment`, `showChassisHardware`, `showVRRP` | ~600 |
| `cli_show_services.go` | `showIPsec*`, `showIKE`, `showTunnelInterfaces`, `showDHCPLeases`, `showDHCPClientIdentifier`, `showDHCPRelay`, `showDHCPServer`, `showSNMP*`, `showLLDP*`, `showRPMProbeResults`, `showSchedulers`, `showDynamicAddress`, `showFirewallFilter*`, `showClassOfServiceInterface`, `showForwardingOptions`, `showPortMirroring`, `showEventOptions` | ~1000 |

**What stays in `cli_show.go`:** `showOperationalHelp`, `showConfigHelp`,
`showDaemonLog`, `showAddressBook`, `showApplications` (~500 lines).

---

### 3. `pkg/config/compiler.go` — 5878 lines, 63 functions

**Problem:** One function per Junos config stanza (security, interfaces,
protocols, routing, firewall, system, services, etc.) all in one file. NAT
compilation was already extracted to `compiler_nat.go`.

**Proposed split:**

| New file | Functions to move | Lines (est.) |
|----------|-------------------|-------------|
| `compiler_security.go` | `compileSecurity`, `compileZones`, `compilePolicies`, `compilePolicy`, `compileScreen`, `compileAddressBook`, `compileLog`, `compileFlow`, `compileALG` | ~1200 |
| `compiler_interfaces.go` | `compileInterfaces`, `parseMSSValue` | ~520 |
| `compiler_protocols.go` | `compileProtocols`, `compileRouterAdvertisement`, `namedInstances`, `parsePrefixLimit`, `parseExportExtensions`, `peerFromPointToPoint`, `parseBandwidthBps`, `parseBandwidthLimit`, `parseBurstSizeLimit` | ~750 |
| `compiler_ipsec.go` | `compileIKE`, `parseDeadPeerDetectionNode`, `compileIPsec` | ~380 |
| `compiler_routing.go` | `compileRoutingOptions`, `compileStaticRoutes`, `parseNextTableInstance`, `compileRoutingInstances`, `compilePolicyOptions`, `parsePolicyTerm*` | ~700 |
| `compiler_firewall.go` | `compileFirewall`, `compileFilterFrom`, `compileFilterThen` | ~420 |
| `compiler_system.go` | `compileSystem`, `compileDPDKDataplane`, `compileUserspaceDataplane`, `compileSNMP`, `compileSNMPv3`, `parseSNMPv3UserKeys`, `compileSchedulers`, `compileChassis` | ~800 |
| `compiler_services.go` | `compileDHCPLocalServer`, `compileDynamicAddress`, `compileServices`, `compileRPM`, `compileFlowMonitoring`, `compileForwardingOptions`, `compilePortMirroring`, `compileSampling*`, `compileDHCPRelay`, `compileEventOptions`, `compileBridgeDomains` | ~700 |

**What stays in `compiler.go`:** `CompileConfig`, `CompileConfigForNode`,
`compileExpanded`, `ValidateConfig`, `compileApplications`, `parseApplicationTerms`,
`normalizeProtocol`, `validatePortSpec`, `validateProtocol`, `nodeVal`,
and the top-level dispatch switch (~600 lines).

---

### 4. `pkg/cli/cli.go` — 4874 lines, 111 functions

**Problem:** Dispatch logic, config mode handlers, clear handlers, request
handlers, test handlers, session filtering, utility functions, and ping/traceroute
all in one file.

**Proposed split:**

| New file | Functions to move | Lines (est.) |
|----------|-------------------|-------------|
| `cli_clear.go` | `handleClear`, `handleClearSystem`, `handleClearArp`, `handleClearIPv6`, `handleClearSecurity`, `clearFilteredSessions`, `clearPeerSessions`, `handleClearFirewall`, `handleClearDHCP`, `clearPersistentNAT` | ~500 |
| `cli_request.go` | `handleRequest`, `handleRequestChassis`, `handleRequestChassisClusterFailover`, `handleRequestChassisClusterDataPlane`, `handleRequestDHCP`, `handleRequestProtocols`, `handleRequestSystem`, `handleRequestSystemSoftware`, `handleRequestSystemConfiguration`, `handleRequestSecurity` | ~600 |
| `cli_test_cmd.go` | `handleTest`, `testPolicy`, `testRouting`, `testSecurityZone` | ~300 |
| `cli_dispatch.go` | `dispatch`, `extractPipe`, `dispatchWithPipe`, `dispatchWithPager`, `dispatchOperational`, `dispatchConfig`, `handleShow`, `handleShowSecurity`, `handleShowScreen`, `handleShowNAT`, `handleShowRoute`, `handleShowProtocols`, `handleShowSystem`, `handleShowClassOfService`, `handleShowServices`, `handleShowIPv6`, `handleMonitor`, `handleMonitorTraffic` | ~1200 |
| `cli_config.go` | `handleConfigShow`, `handleCopyRename`, `handleInsert`, `handleLoad`, `handleCommit`, `refreshPrompt`, `reloadSyslog`, `applyToDataplane` | ~400 |
| `cli_helpers.go` | `resolveAppName`, `parseSessionFilter`, `sessionFilter` methods, `protoNameFromNum`, `protoNameToID`, `splitAddrPort`, `uint32ToIP`, `sessionStateName`, `ntohs`, `monotonicSeconds`, `matchPolicyAddr*`, `matchSingleApp`, `capitalizeFirst`, `enabledStr`, `parsePolicyZoneFilter`, `resolveAddress*`, `printAppDetail`, `fmtPref`, `fmtBytes`, `neighState`, `valueProvider`, `readLinkSpeed`, `readLinkDuplex`, `formatSpeed`, `formatDuplex` | ~800 |

**What stays in `cli.go`:** `CLI` struct, `New`, setters, `Run`, `checkPermission`,
completer, `resolveCommand`, prompt functions, peer dial, cluster helpers (~1000 lines).

---

### 5. `pkg/dataplane/userspace/manager.go` — 4772 lines, 123 functions

**Problem:** Snapshot building, process management, BPF map syncing, status
polling, and neighbor resolution all in one file.

**Proposed split:**

| New file | Functions to move | Lines (est.) |
|----------|-------------------|-------------|
| `snapshot.go` | `buildSnapshot`, `snapshotContentHash`, `neighborsEqual`, `buildZoneSnapshots`, `buildFabricSnapshots`, `buildFabricPeerMAC`, `buildInterfaceSnapshots`, `buildTunnelEndpointSnapshots`, `buildInterfaceZoneMap`, `snapshotLinuxName`, `buildLinkSnapshot`, `buildConfiguredAddressSnapshots`, `mergeInterfaceAddressSnapshots`, `buildInterfaceAddressSnapshots`, `userspaceRXQueueCount`, `buildRouteSnapshots`, `buildInterfaceRouteTables`, `connectedPrefixesForInterface`, `normalizeRouteSnapshotFamily`, `buildSourceNATSnapshots`, `buildStaticNATSnapshots`, `buildDestinationNATSnapshots`, `buildNAT64Snapshots`, `buildNptv6Snapshots`, `hasNonNptv6StaticNAT`, `buildScreenSnapshots`, `userspaceSupportsScreenProfiles`, `buildFilterTermSnapshots`, `buildPolicerSnapshots`, `buildPolicySnapshots`, `policyActionString`, `buildNeighborSnapshots`, `neighborStateString`, `appPortsFromSpec` | ~1800 |
| `capability.go` | `deriveUserspaceConfig`, `deriveUserspaceCapabilities`, `userspaceSupportsSecurityPolicies`, `userspacePolicyAddressesSupported`, `expandUserspacePolicyAddresses`, `isUserspaceLiteralAddress`, `normalizeUserspaceLiteralAddress`, `resolveUserspaceAddressBookEntry`, `userspacePolicyApplicationsSupported`, `expandUserspacePolicyApplications`, `resolveUserspaceApplicationNames`, `normalizeUserspaceApplicationProtocol`, `userspaceSupportsSourceNAT` | ~500 |
| `maps_sync.go` | `syncSnapshotLocked`, `programBootstrapMapsLocked`, `setupUserspaceCPUMapLocked`, `syncIngressIfaceMapLocked`, `syncLocalAddressMapsLocked`, `syncInterfaceNATAddressMapsLocked`, `buildLocalAddressEntries`, `buildInterfaceNATAddressEntries`, `buildUserspaceIngressIfindexes`, `snapshotBindingPlanKey`, `buildUserspaceIngressBindingAliases`, `userspaceSkipsIngressInterface`, `snapshotHasNativeGRE`, `buildNATTranslatedLocalAddressExclusions`, `pickInterfaceSnapshotV4`, `pickInterfaceSnapshotV6`, `verifyBindingsMapLocked` | ~600 |
| `process.go` | `ensureProcessLocked`, `tuneSocketBuffers`, `findBinary`, `requestDetailedLocked`, `sessionSocketPath`, `requestSessionSync`, `requestLocked`, `applyHelperStatusLocked`, `readFallbackStatsLocked`, `entryProgramsLocked`, `ensureStatusLoopLocked`, `statusLoop`, `bootstrapNAPIQueuesAsyncLocked`, `stopLocked`, `bootstrapNAPIQueuesLocked`, `proactiveNeighborResolveLocked`, `sendICMPProbeFromManager`, `sendICMPProbeWithID`, `sendUDPProbeForNAPI`, `proactiveNeighborResolveAsyncLocked`, `disableUserspaceCtrlLocked`, `reEnableUserspaceCtrlLocked`, `DisableAndStopHelper`, `PrepareLinkCycle`, `NotifyLinkCycle`, `StartFIBSync` | ~800 |

**What stays in `manager.go`:** `Manager` struct, `New`, `Load`, `Close`,
`Teardown`, `Compile`, `syncInterfaceAttachments`, `Mode`, setters, public
query methods, `configEqual` (~1000 lines).

---

### 6. `pkg/daemon/daemon.go` — 4506 lines, 73 functions

**Problem:** The main daemon file contains `Run()` (800+ lines), RETH/MAC
management, DHCP client management, neighbor resolution, flow export, syslog
config, DNS config, NTP config, hostname, kernel tuning, nftables lo0 filter,
SSH config, login management, timezone, config archiving, link monitoring.

**Proposed split:**

| New file | Functions to move | Lines (est.) |
|----------|-------------------|-------------|
| `daemon_system.go` | `applyHostname`, `isProcessDisabled`, `applySystemDNS`, `restartResolved`, `renderChronySources`, `renderChronyThreshold`, `reconcileManagedFile`, `reloadChronyRuntime`, `applySystemNTP`, `applyDNSService`, `applyKernelTuning`, `applyTimezone`, `applySSHKnownHosts`, `applySSHConfig`, `applyRootAuth`, `applySystemLogin`, `applySystemSyslog`, `applySyslogFiles`, `archiveConfig` | ~1000 |
| `daemon_reth.go` | `fixRethLinkFile`, `ensureRethLinkOriginalName`, `deriveKernelName`, `pciAddrFromPath`, `pciAddrToEnp`, `renameRethMember`, `programRethMAC`, `clearDadFailed`, `removeAutoLinkLocal`, `ensureRethLinkLocal`, `rethUnitHasConfiguredLinkLocal`, `rethUnitHasIPv6` | ~400 |
| `daemon_neighbor.go` | `preinstallSnapshotNeighbors`, `resolveNeighbors`, `resolveNeighborsInner`, `cleanFailedNeighbors`, `runPeriodicNeighborResolution`, `maintainClusterNeighborReadiness` | ~400 |
| `daemon_flow.go` | `startFlowExporter`, `stopFlowExporter`, `startIPFIXExporter`, `stopIPFIXExporter`, `applySyslogConfig`, `resolveSourceAddr`, `applyAggregator`, `applyFlowTrace`, `updateFlowTrace`, `parseAddrPair`, `parseHost`, `parseSrcPort`, `parseProtocol` | ~500 |
| `daemon_nft.go` | `applyLo0Filter`, `nftRuleFromTerm`, `nftDSCPValue` | ~200 |

**What stays in `daemon.go`:** `Daemon` struct, `New`, `Run`, `enableForwarding`,
`isInteractive`, `resolveInterfaceAddr`, `parseLiteralIP`, `selectClusterBindAddr`,
`resolveClusterInterfaceAddr`, `bootstrapFromFile`, `applyConfig`,
`buildRAConfigs`, `startDHCPClients`, `dhcpLeaseChangeRequiresRecompile`,
`resolveJunosIfName`, `collectDHCPRoutes`, `applyMgmtVRFRoutes`, `logFinalStats`,
`monitorLinkState` (~2000 lines).

---

### 7. `pkg/daemon/daemon_ha.go` — 4194 lines, 125 functions

**Problem:** This is the most complex file in the codebase. It mixes:
session sync callbacks, userspace session conversion (20+ functions),
fabric IPVLAN management, VRRP event handling, RG state reconciliation,
blackhole route injection, RETH service management, VIP ownership,
GARP/announce scheduling, IPsec SA sync, and config sync.

**Proposed split:**

| New file | Functions to move | Lines (est.) |
|----------|-------------------|-------------|
| `daemon_ha_sync.go` | `stopSyncReadyTimer`, `armSyncReadyTimer`, `onSessionSyncPeerConnected`, `onSessionSyncBulkReceived`, `onSessionSyncBulkAckReceived`, `onSessionSyncPeerDisconnected`, `shouldSuppressPeerHeartbeatTimeout`, `syncPrimeProgressObserved`, `startSessionSyncPrimeRetry`, `bulkSyncViaEventStreamOrFallback`, `syncConfigToPeer`, `pushConfigToPeer`, `handleConfigSync`, `startClusterComms`, `stopClusterComms`, `clusterTransportFromConfig` | ~700 |
| `daemon_ha_userspace.go` | `buildZoneIDs`, `daemonMonotonicSeconds`, `userspaceSessionTimeout`, `userspaceHostToNetwork16`, `userspaceNetworkToHost16`, `userspaceReverseKeyV4`, `userspaceForwardWireKeyV4`, `effectiveUserspaceNATSrcPort`, `effectiveUserspaceNATDstPort`, `userspaceReverseKeyV6`, `userspaceParseSyncMAC`, `userspaceSessionFromDeltaV4`, `userspaceForwardWireAliasFromDeltaV4`, `userspaceSessionFromDeltaV6`, `userspaceForwardWireKeyV6`, `userspaceForwardWireAliasFromDeltaV6`, `shouldSyncUserspaceDelta`, `buildZoneRGMap`, `rgHasRETH`, `syncUserspaceSessionDeltas`, `runUserspaceEventStream`, `handleEventStreamDelta`, `handleEventStreamFullResync`, `eventStreamFallbackLoop`, `queueUserspaceSessionDeltas`, `drainUserspaceSessionDeltasWithConfig`, `exportUserspaceOwnerRGSessionsWithConfig`, `tryPrepareUserspaceRGDemotion`, `acquireUserspaceRGDemotionPrep`, `releaseUserspaceRGDemotionPrep`, `prepareUserspaceRGDemotion`, `wrapUserspaceManualFailoverPrepareError`, `userspaceManualFailoverTransferReadinessError`, `userspaceTransferReadiness`, `prepareUserspaceManualFailover`, `prepareUserspaceRGDemotionWithTimeout`, `userspaceRGConfigured`, `checkUserspaceTakeoverReadiness`, `userspaceDataplaneActive` | ~1100 |
| `daemon_ha_fabric.go` | `ensureFabricIPVLAN`, `reconcileIPVLANAddrs`, `CleanupFabricIPVLANs`, `resolveFabricParent`, `populateFabricFwd`, `probeFabricNeighbor`, `sendICMPProbe`, `sendIPv6MulticastProbe`, `logFabricRefreshFailure`, `refreshFabricFwd`, `clearFabricFwd0`, `populateFabricFwd1`, `refreshFabricFwd1`, `clearFabricFwd1`, `RefreshFabricFwd`, `overlayOrParent`, `monitorFabricState`, `triggerFabricRefresh` | ~900 |
| `daemon_ha_vip.go` | `directVIPOwnershipDesired`, `shouldOwnDirectVIPs`, `directVIPOwnershipApplied`, `addDirectVIPs`, `removeDirectVIPs`, `addDirectStableLinkLocal`, `removeDirectStableLinkLocal`, `reconcileDirectVIPOwnership`, `applyDirectVIPOwnership`, `directAddVIPs`, `directRemoveVIPs`, `addStableRethLinkLocal`, `removeStableRethLinkLocal`, `addStableLLToInterface`, `removeStableLLFromInterface`, `directAnnounceActive`, `cancelDirectAnnounce`, `scheduleDirectAnnounce`, `directSendGARPs`, `checkVIPReadiness`, `checkNoRethTakeoverReadiness`, `takeoverReadinessForRG`, `checkVIPReadinessForConfig`, `isNoRethVRRP` | ~700 |

**What stays in `daemon_ha.go`:** `watchClusterEvents`, `watchVRRPEvents`,
`reconcileRGStateLoop`, `triggerReconcile`, `reconcileRGState`,
`getOrCreateRGState`, `syncRGStrictVIPOwnershipMode`, `isRethMasterState`,
`isAnyRethInstanceMaster`, `snapshotRethMasterState`, RG service management,
blackhole routes, IPsec SA sync, `warmNeighborCache` (~800 lines).

---

### 8. `pkg/cluster/sync.go` — 3577 lines, 97 functions

**Problem:** Session sync connection management, send/receive loops, message
encoding/decoding, failover protocol, stale session reconciliation, and
formatting all in one file. `sync_bulk.go` was already extracted.

**Proposed split:**

| New file | Functions to move | Lines (est.) |
|----------|-------------------|-------------|
| `sync_codec.go` | `encodeSessionV4`, `encodeRawMessage`, `encodeSessionV4Payload`, `encodeSessionV6`, `encodeSessionV6Payload`, `encodeDeleteV4`, `encodeDeleteV6`, `decodeSessionV4Payload`, `decodeSessionV6Payload`, `encodeIPsecSAPayload`, `decodeIPsecSAPayload`, `writeMsg`, `writeFull`, `encodeFailoverBatchRequestPayload`, `decodeFailoverBatchRequestPayload`, `encodeFailoverBatchAckPayload`, `decodeFailoverBatchAckPayload` | ~500 |
| `sync_failover.go` | `SendFailover`, `SendFailoverBatch`, `failoverAckError`, `SendFailoverCommit`, `SendFailoverCommitBatch`, `failoverCommitAckBatchError`, `failoverCommitAckError`, `SendFence`, `SendPrepareActivation`, `handleRemoteFailover`, `handleRemoteFailoverBatch`, `handleRemoteFailoverCommit`, `handleRemoteFailoverCommitBatch`, `sendFailoverResult`, `sendFailoverBatchResult`, `completeFailoverWait`, `completeFailoverBatchWait`, `completeFailoverCommitWait`, `completeFailoverBatchCommitWait`, `validateFailoverProtocolRGID`, `validateFailoverProtocolRGIDs`, `failoverRGInUseLocked`, `validateFailoverBatchRGCount`, `rgSetOverlap` | ~700 |
| `sync_conn.go` | `acceptLoop`, `fabricConnectLoop`, `handleNewConnection`, `handleDisconnect`, `sendLoop`, `receiveLoop`, `handleMessage`, `configureSessionSyncConn`, `shouldInitiateFabricDial`, `connRemoteAddrString`, `connLocalAddrString`, `activeConnLocked`, `getActiveConn` | ~600 |

**What stays in `sync.go`:** `SessionSync` struct, constructors, `Start`,
`Stop`, `StartSyncSweep`, sweep logic, queue methods, `QueueSession*`,
`QueueDelete*`, `QueueConfig`, `QueueIPsecSA`, `ShouldSyncZone`,
`WaitForIdle`, `reconcileStaleSessions`, `FormatStats`, `PeerIPsecSAs`,
stats methods, clock sync, `monotonicSeconds`, `rebaseTimestamp` (~1800 lines).

---

### 9. `pkg/dataplane/compiler.go` — 3486 lines, 46 functions

**Problem:** BPF map compilation for all subsystems in one file.

**Proposed split:**

| New file | Functions to move | Lines (est.) |
|----------|-------------------|-------------|
| `compiler_filters.go` | `compileFirewallFilters`, `expandFilterTerm`, `setFilterAddr`, `computeFilterProtoPrefilter`, `resolvePortRange`, `forwardingClassToDSCP`, `resolvePortName` | ~700 |
| `compiler_nat_dp.go` | `compileNAT`, `compileStaticNAT`, `nptv6Adjustment`, `compileNPTv6`, `compileNAT64` | ~500 |

**What stays in `compiler.go`:** Interface compilation, address books,
applications, policies, flow/timeout config, port mirroring, utility
helpers (~2300 lines). This is borderline — further splitting adds minimal
value since the remaining functions are closely related.

---

### 10. `pkg/config/ast.go` — 2914 lines, 69 functions

**Problem:** AST node types, group expansion, tree manipulation (set/delete/copy/
rename/insert), formatting (hierarchical, set, JSON, XML), and comparison all
in one file.

**Proposed split:**

| New file | Functions to move | Lines (est.) |
|----------|-------------------|-------------|
| `ast_format.go` | `Format`, `canonicalOrder`, `formatNodes`, `FormatPath`, `FormatSet`, `FormatPathSet`, `formatSetNodes`, `joinQuotedKeys`, `FormatCompare`, `diffNodes`, `nodesEqual`, `formatPrefixed`, `formatPrefixedChildren`, `FormatJSON`, `FormatPathJSON`, `FormatXML`, `FormatPathXML`, `formatXMLNodes`, `formatXMLLeaf`, `xmlTag`, `xmlEscape`, `nodesToJSON` | ~800 |
| `ast_groups.go` | `ExpandGroups`, `ExpandGroupsTagged`, `ExpandGroupsWithVars`, `resolveVars`, `expandGroups`, `stripApplyGroups`, `stripApplyGroupsInNodes`, `walkGroupToContext`, `expandGroupsRecursive`, `mergeNodes`, `keysContainWildcard`, `keysMatchWildcard`, `hasMatchingLeaf`, `matchNodeKeys`, `FormatInheritance`, `FormatPathInheritance`, `formatNodesInheritance`, `tagNodesInherited`, `navigatePath` | ~800 |

**What stays in `ast.go`:** Node/ConfigTree types, `Clone`, `FindChild`,
`SetPath`, `DeletePath`, `CopyPath`, `RenamePath`, `InsertBefore/After`,
schema, completion (~1300 lines).

---

### 11. `cmd/cli/main.go` — 3623 lines, 91 functions

**Problem:** The remote CLI client duplicates much of `pkg/cli`'s dispatch
structure (show, clear, request handlers) in a single file.

**Proposed split:**

| New file | Functions to move | Lines (est.) |
|----------|-------------------|-------------|
| `show.go` | `handleShow`, `handleShowSecurity`, `handleShowServices`, `showZones`, `showPoliciesFiltered`, `showScreen`, `showFlowSession`, `showSessionSummary`, `handleShowNAT`, `showMatchPolicies`, `showVRRP`, `showNATSourceSummary`, `showNATPoolStats`, `showNATRuleStats`, `showNATDestinationSummary`, `showNATDestinationPool`, `showNATDNATRuleStats`, `showEvents`, `showStatistics`, `showFlowStatistics`, `showIKE`, `showIPsec`, `showInterfaces`, `showDHCPLeases`, `showDHCPClientIdentifier`, `showRoutes`, `handleShowProtocols`, `handleShowSystem`, `showText*`, `showSystemInfo`, `showPoliciesBrief` | ~1500 |
| `request.go` | `handleRequest`, `handleRequestChassis*`, `handleRequestDHCP`, `handleRequestProtocols`, `handleRequestSecurity` | ~400 |
| `clear.go` | `handleClear`, `handleClearSystem`, `handleClearInterfaces`, `handleClearArp`, `handleClearIPv6`, `handleClearSecurity`, `handleClearFirewall`, `handleClearDHCP` | ~300 |
| `monitor.go` | `handleMonitor`, `handleMonitorInterface`, `handleInteractiveMonitorInterfaceSummary`, `handleMonitorSecurity*`, `remoteMonitorSummaryMode*`, `setMonitorRawMode`, `restoreMonitorTermMode`, `monitorInputIsTTY`, `isMonitorQuitKey` | ~400 |

**What stays in `main.go`:** `main`, `ctl` struct, `dispatch`, `dispatchOperational`,
`dispatchConfig`, config mode handlers, prompt, completion, test, load, commit,
`printSessionEntries`, `printSessionSummaryBlock`, helpers (~1000 lines).

---

### 12. `pkg/cluster/cluster.go` — 2184 lines, 73 functions

**Problem:** Cluster manager, heartbeat, election, failover requests, event
history, and status formatting all in one file. Some areas (heartbeat, election,
garp) are already in separate files, but `cluster.go` still has mixed concerns.

**Proposed split:**

| New file | Functions to move | Lines (est.) |
|----------|-------------------|-------------|
| `format.go` | `FormatStatus`, `FormatInformation`, `FormatStatistics`, `FormatControlPlaneStatistics`, `FormatDataPlaneStatistics`, `FormatDataPlaneInterfaces`, `FormatIPMonitoringStatus`, `FormatInterfaces` | ~500 |
| `failover.go` | `ManualFailover`, `RequestPeerFailover`, `commitRequestedPeerFailover`, `abortRequestedPeerFailover`, `notePeerTransferCommitted`, `FinalizePeerTransferOut`, `ForceSecondary`, `ResetFailover`, `Set*Func` (all 7 setter methods) | ~400 |

**What stays in `cluster.go`:** Manager struct, constructor, `Start`, `Stop`,
`UpdateConfig`, `electSingleNode`, weight management, `GroupStates`, event
dispatch, `RecordEvent`, `EventHistoryFor`, sync stats, heartbeat start/stop
(~1300 lines).

---

### 13. `pkg/api/handlers.go` — 2112 lines, 66 functions

**Problem:** All HTTP handlers in one file. Borderline case — only slightly
above threshold. Could split config-mode handlers from read-only handlers.

**Proposed split (optional):**

| New file | Functions to move | Lines (est.) |
|----------|-------------------|-------------|
| `handlers_config.go` | `configEnterHandler`, `configExitHandler`, `configStatusHandler`, `configSetHandler`, `configDeleteHandler`, `configCommitHandler`, `configCommitCheckHandler`, `configRollbackHandler`, `configShowHandler`, `configExportHandler`, `configCompareHandler`, `configHistoryHandler`, `configSearchHandler`, `configLoadHandler`, `configCommitConfirmedHandler`, `configConfirmHandler`, `configShowRollbackHandler`, `configAnnotateHandler` | ~600 |

**What stays:** All read-only handlers + helpers (~1500 lines). This is
a low-priority split.

---

## Rust Files

### 14. `userspace-dp/src/afxdp.rs` — 8425 lines, 107 functions

**Problem:** This is the main coordinator for the AF_XDP dataplane. It contains
the `Coordinator` struct (public API, ~1200 lines), `BindingWorker` internals
(~4700 lines of core packet processing), and ~2350 lines of tests. However,
much has already been extracted into the `afxdp/` submodule (24 files).

**Proposed split:**

| New file | Functions/blocks to move | Lines (est.) |
|----------|-------------------------|-------------|
| `afxdp/coordinator.rs` | `Coordinator` struct + all `impl Coordinator` methods (lines 226-1500) | ~1280 |
| `afxdp/worker.rs` | `BindingWorker` struct + `impl BindingWorker` + `poll_binding` + `worker_loop` + all free functions that operate on bindings (`retry_pending_neigh`, `build_live_forward_request*`, `learn_dynamic_neighbor*`, `flush_session_deltas`, `record_*`, `update_last_resolution`, `purge_queued_flows_for_closed_deltas`, `binding_by_index_mut`, `find_target_binding_mut`) | ~4400 |
| `afxdp/coordinator_test.rs` | All `#[cfg(test)]` code (lines 6078-8425) | ~2350 |

**What stays in `afxdp.rs`:** Module declarations, imports, constants,
`XskBindMode` enum + impl, `BindingLiveSnapshot`, `fabric_queue_hash`,
`push_recent_*` helpers (~400 lines).

**Note:** `afxdp/frame.rs` (7123 lines) is also very large, but ~4100 lines
are tests. The production code (~3000 lines) is all frame building/rewriting
which is a single cohesive responsibility. Same for `forwarding.rs` (3330 lines)
and `session_glue.rs` (2994 lines) — these are already well-scoped submodules.

---

### 15. `userspace-dp/src/afxdp/frame.rs` — 7123 lines, 71 functions

The production code (~3000 lines) handles frame parsing, building, rewriting,
and NAT application. This is cohesive. The 4100+ lines of tests could be
extracted to `afxdp/frame_test.rs` to reduce file size, but this is lower
priority since tests don't affect navigability of production code.

---

### 16. `userspace-dp/src/session.rs` — 2185 lines, 79 functions

Contains session table, key types, GC, delta tracking, and timeout management.
This is cohesive — all session-related. No split needed.

---

## Test Files

### 17. `pkg/config/parser_test.go` — 16,956 lines, 331 tests

**Problem:** By far the largest test file. Tests cover lexing, parsing,
compilation, formatting, validation, and every Junos config stanza.

**Proposed split:**

| New file | Tests to move | Lines (est.) |
|----------|--------------|-------------|
| `compiler_test.go` | All `TestCompile*`, `TestValidate*`, plus per-stanza compilation tests (TestRoutingConfigParsing, TestNAT64, TestFirewallFilter, TestChassisCluster*, TestIPsec*, TestSchedulers, etc.) | ~10000 |
| `ast_test.go` | `TestFormat*`, `TestFormatSet*`, `TestSetPath*`, `TestDeletePath`, `TestInsertBefore*`, `TestCopyRename*`, `TestFormatCompare*`, `TestFormatJSON*`, `TestFormatXML*` | ~3000 |

**What stays in `parser_test.go`:** `TestLexer*`, `TestBracketList`,
`TestParseHierarchical`, `TestSetCommand`, basic roundtrip tests (~4000 lines).

---

### 18. `pkg/cluster/sync_test.go` — 3433 lines

Large but tests a single complex subsystem. Could extract codec and failover
tests to match the proposed source splits, but this is low priority.

---

## Priority Order

| Priority | File | Lines | Impact |
|----------|------|-------|--------|
| **P1** | `pkg/config/compiler.go` | 5878 | Cleanest split — each stanza compiler is independent |
| **P1** | `pkg/daemon/daemon_ha.go` | 4194 | Most complex file, clear domain boundaries |
| **P1** | `pkg/grpcapi/server.go` | 8411 | Largest file, already has precedent (server_sessions.go) |
| **P2** | `pkg/cli/cli_show.go` | 7887 | Many small functions, easy to split by domain |
| **P2** | `pkg/daemon/daemon.go` | 4506 | System config functions are clearly separable |
| **P2** | `pkg/dataplane/userspace/manager.go` | 4772 | Snapshot building is 1800+ lines of pure functions |
| **P2** | `pkg/config/ast.go` | 2914 | Format + groups are independent of tree manipulation |
| **P3** | `pkg/cli/cli.go` | 4874 | Dispatch is intertwined — split is harder |
| **P3** | `cmd/cli/main.go` | 3623 | Remote CLI mirrors local CLI — same pattern applies |
| **P3** | `pkg/cluster/sync.go` | 3577 | Codec + failover protocol are cleanly separable |
| **P3** | `userspace-dp/src/afxdp.rs` | 8425 | Coordinator vs worker split is clean |
| **P4** | `pkg/config/parser_test.go` | 16956 | Test file — split per source file convention |
| **P4** | `pkg/cluster/cluster.go` | 2184 | Slightly over threshold, format functions are easy |
| **P4** | `pkg/api/handlers.go` | 2112 | Borderline — config handlers are optional split |
