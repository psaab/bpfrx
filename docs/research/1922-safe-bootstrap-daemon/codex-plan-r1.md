# Codex hostile plan review R1 - #1922 SAFE-BOOTSTRAP daemon

Verdict: PLAN-NEEDS-CHANGES

I could not PLAN-KILL the plan: the required current-code grounding is mostly accurate, and Item 1 is a real service-mode safety bug. I do not think v1 is PLAN-READY because the corrupt-DB lifeline path and the never-committed marker representation are still material design decisions, not engineer-time details.

## Findings

### High - Corrupt-DB lifeline and "protected under corrupt config" are not actually designed

Evidence:

```go
pkg/daemon/daemon_run.go:208: if err := d.store.Load(); err != nil {
pkg/daemon/daemon_run.go:209:     if errors.Is(err, configstore.ErrConfigDBUnreadable) {
pkg/daemon/daemon_run.go:213:         return fmt.Errorf("config DB is present but unreadable; refusing to "+
pkg/daemon/daemon_run.go:217:             dbPath, err)
pkg/daemon/daemon_run.go:231: // Enumerate PCI NICs and assign vSRX-style names (fxp0, em0, ge-X-0-Y)
pkg/daemon/daemon_run.go:233: if !d.opts.NoDataplane {
pkg/daemon/daemon_run.go:292:     if err := enumerateAndRenameInterfaces(nodeID, clusterMode, userspaceWorkers, rssEnabled, rssAllowed); err != nil {
```

```go
pkg/daemon/daemon_run.go:513: if cfg := d.store.ActiveConfig(); cfg != nil {
pkg/daemon/daemon_run.go:515:     d.applyConfig(cfg)
pkg/dataplane/compiler.go:151: func CompileConfig(dp DataPlane, cfg *config.Config, isRecompile bool) (*CompileResult, error) {
pkg/dataplane/compiler.go:152:     if cfg == nil {
pkg/dataplane/compiler.go:153:         return nil, fmt.Errorf("nil config")
```

The plan says case 4 remains fatal but also says the lifeline `.network` is written/preserved before fatal or the predicate runs before fatal. Current code exits at `Load()` before `bootstrapFromFile`, before `enumerateAndRenameInterfaces`, before `applyConfig`, and before `compileZones`. Therefore Item 4's claim that protected-set enforcement is effective under corrupt config cannot be satisfied by `compileZones()` alone.

This is not structurally impossible, but v1 must choose the mechanism. Option 1 would need a tiny pre-`Load()` fail-safe lifeline writer that does not depend on compiled config and defines whether it writes a current-name `.network`, an `fxp0` `.network`, and whether it calls `networkctl reload`. Option 2 must explicitly narrow the guarantee to previously booted systems with an existing lifeline record. Option 3 must admit that a never-booted corrupt-DB box has no lifeline. Leaving this as OQ-A is a plan-readiness blocker because it is the central fail-closed safety story.

### Med - Step-0 marker is achievable, but v1 leaves a load-bearing storage format undecided

Evidence:

```go
pkg/configstore/store.go:113: return &Store{
pkg/configstore/store.go:114:     active:   &config.ConfigTree{},
pkg/configstore/store.go:119:     nodeID:   -1,
pkg/configstore/store.go:136: tree, err := s.db.ReadActive()
pkg/configstore/store.go:146: if tree == nil {
pkg/configstore/store.go:147:     return nil // start fresh with empty config
pkg/configstore/store.go:1290: func (s *Store) ActiveConfig() *config.Config {
pkg/configstore/store.go:1293:     return s.compiled
```

```go
pkg/configstore/store.go:197: func (s *Store) writeActive(tree *config.ConfigTree) error {
pkg/configstore/store.go:201:     return s.db.WriteActive(tree)
pkg/configstore/store.go:292: err := s.writeActive(s.active)
pkg/configstore/db.go:171: // Wrap the (possibly-encrypted) body in the config compatibility
pkg/configstore/db.go:175: data = wrapEnvelope(data, db.writerVersion)
pkg/configstore/envelope.go:214: default:
pkg/configstore/envelope.go:215:     // Unknown fields are tolerated (additive forward-compat); the
pkg/configstore/envelope.go:216:     // v=/min-reader gate is what governs readability.
```

The committed-empty vs never-committed distinction is achievable without breaking #1799 or #1917, but only if the representation is chosen now. A marker outside `s.active` must participate in `writeActive` and the #1799 retry loop, which currently retries only `s.active`. A marker in the envelope header must handle older floor readers: unknown header fields are ignored, so a generation field that older readers ignore does not preserve the semantic unless `min-reader`/format gating is used deliberately. A presence/absence active-record design needs a migration rule for existing empty active records. The plan names these constraints, but OQ-F still leaves implementors without the invariant they must preserve.

### Med - Cluster secondary misclassification is avoided by current scripts, not by a structural predicate

Evidence:

```go
pkg/daemon/daemon.go:398: // Read cluster node ID from file.
pkg/daemon/daemon.go:401: if data, err := os.ReadFile(nodeIDFile); err == nil {
pkg/daemon/daemon.go:405:     store.SetNodeID(nodeID)
pkg/daemon/daemon_run.go:256: if cfg := d.store.ActiveConfig(); cfg != nil {
pkg/daemon/daemon_run.go:257:     if cfg.Chassis.Cluster != nil {
pkg/daemon/daemon_run.go:258:         clusterMode = true
pkg/daemon/daemon_run.go:259:         nodeID = cfg.Chassis.Cluster.NodeID
```

```sh
test/incus/cluster-setup.sh:886: # Push the single unified HA config (same file for both nodes)
test/incus/cluster-setup.sh:890: incus file push "$CLUSTER_CONF" "${rinst}/etc/xpf/xpf.conf"
test/incus/cluster-setup.sh:892: # Clear configstore DB so daemon bootstraps from the new text file.
test/incus/cluster-setup.sh:894: incus exec "$rinst" -- rm -rf /etc/xpf/.configdb
test/incus/cluster-setup.sh:899: # Ensure node-id file exists
test/incus/cluster-setup.sh:900: incus exec "$rinst" -- bash -c "echo $idx > /etc/xpf/node-id"
test/incus/cluster-setup.sh:909: incus exec "$rinst" -- systemctl enable --now xpfd
```

The plan's belief is true for the current cluster deploy path: config and node-id are present before xpfd starts, and `.configdb` is cleared so case 2 imports the text config. But the code only knows `clusterMode=true` after a compiled active config with `Chassis.Cluster`; a node-id-only boot is not structurally a cluster boot in `daemon_run.go`. If bootstrap mode suppresses dataplane/FRR/VRRP on that node, it will not be failover-ready. This does not kill the plan, but OQ-E needs a crisp invariant and test: either "node-id without DB/xpf.conf is bootstrap/fail-safe and HA availability is not promised" or an explicit cluster predicate/fatal path.

### Low - Item 1 is real, but the gRPC/REST forward commit path is already serialized

Evidence:

```go
pkg/cli/cli.go:284: // Register auto-rollback handler for commit confirmed.
pkg/cli/cli.go:289: c.store.SetCentralRollbackHandler(func(cfg *config.Config) {
pkg/configstore/store.go:1209: fn := s.centralRollbackFn
pkg/configstore/store.go:1215: if fn != nil && prevCfg != nil {
pkg/configstore/store.go:1216:     fn(prevCfg)
```

```go
pkg/daemon/daemon_run.go:943: CommitConfirmedFn: func(ctx context.Context, minutes int) (*config.Config, error) {
pkg/daemon/daemon_run.go:944:     return d.commitConfirmedAndApply(ctx, minutes, false)
pkg/daemon/daemon_run.go:1103: CommitConfirmedFn: func(ctx context.Context, minutes int) (*config.Config, error) {
pkg/daemon/daemon_run.go:1104:     return d.commitConfirmedAndApply(ctx, minutes, true)
pkg/daemon/daemon_apply.go:136: func (d *Daemon) commitConfirmedAndApply(ctx context.Context, minutes int, syncPeer bool) (*config.Config, error) {
pkg/daemon/daemon_apply.go:137:     if err := d.applySem.Acquire(ctx, 1); err != nil {
pkg/daemon/daemon_apply.go:142:     compiled, err := d.store.CommitConfirmed(minutes)
pkg/daemon/daemon_apply.go:146:     if err := d.applyConfigLocked(compiled); err != nil {
```

The service-mode timeout rollback executor is mis-wired exactly as the plan says: the only production registration is in `CLI.Run`, and the timer later calls `centralRollbackFn` outside store lock. But the initial gRPC/REST `commit confirmed` path already goes through daemon-owned `commitConfirmedAndApply` and holds `applySem` across commit and apply. The implementation plan should keep the scope precise: fix the timeout rollback transaction and first-commit rollback target, not the already-correct forward commit path.

### Low - Required file:line citations are materially correct

I found no material wrong file:line citation in the required plan areas. Minor precision: `daemon_run.go:231-307` is only the first startup `!NoDataplane` block for rename/tunables; the routing/FRR/dataplane initialization continues after that (`daemon_run.go:309+`). The plan also says "and the dataplane/FRR/VRRP init that follows", so this is not a contradiction.

## Required Check Results

1. COMMIT-CONFIRMED SERVICE-MODE: PASS.

Evidence: `SetCentralRollbackHandler` is registered in `CLI.Run` at `pkg/cli/cli.go:284-299`; `rg SetCentralRollbackHandler` found no other production registration. `performAutoRollback` mutates store state at `pkg/configstore/store.go:1178-1179`, persists it at `:1197`, then obtains/calls `fn` at `:1209-1216`. `d.applyConfig` only acquires `applySem` around its own apply at `pkg/daemon/daemon_apply.go:66-70`; `commitConfirmedAndApply` separately proves the intended commit/apply lock shape at `:136-148`, and `apply_serialize_test.go:1-15` documents that contract. The first-commit hole is confirmed: fresh stores start with empty `active` and nil `compiled` (`store.go:113-119`); `CommitConfirmed` captures `confirmPrevTree = s.active.Clone()` and `confirmPrevCfg = s.compiled` (`:1095-1097`); rollback writes that empty tree (`:1178`, `:1197`) and skips the handler when `prevCfg == nil` (`:1215`).

2. FIVE-CASE BOOT PREDICATE: FAIL as plan-ready; code grounding mostly PASS.

Evidence: D1 is merged: `ErrConfigDBUnreadable` is defined at `pkg/configstore/envelope.go:11-18`; `Store.Load` wraps present-DB read failures with it at `pkg/configstore/store.go:136-144`; daemon startup makes it fatal at `pkg/daemon/daemon_run.go:208-217`. Absent DB still returns nil/start-fresh at `store.go:146-147`, and `bootstrapFromFile` runs when `ActiveConfig()==nil` at `daemon_run.go:222-226`. Existing test/cluster deploy case 2 is a genuine no-op if imports are clean: standalone deploy pushes `xpf-test.conf` and clears `.configdb` at `test/incus/setup.sh:406-413`; cluster deploy pushes `xpf.conf`, clears `.configdb`, writes node-id, then enables xpfd at `test/incus/cluster-setup.sh:886-909`. The FAIL is the unresolved case-4 lifeline/protected-under-corrupt design and the unchosen step-0 marker representation described above.

3. PCI-KEYED LIFELINE: FAIL as plan-ready; code grounding PASS.

Evidence: `enumeratePCINICs` extracts and stores PCI bus address in `pciNIC` (`pkg/daemon/linksetup.go:20-24`, `:161-175`) and sorts by bus address at `:178-185`. `writeBootstrapFxp0Network` is DHCP-only (`linksetup.go:288-306`). The OQ-A attack succeeds against current code: corrupt DB exits at `daemon_run.go:208-217` before the interface/lifeline area at `:231-307`. The plan can still be made viable, but a never-booted corrupt box does not currently get a lifeline, and v1 has not chosen the pre-fatal write/preserve/accept-gap option.

4. PROTECTED-SET ENFORCEMENT: PASS for current-code facts, with dependency on Finding 1.

Evidence: `compileZones` marks unconfigured kernel NICs `Unmanaged=true` at `pkg/dataplane/compiler_iface.go:1060-1065` and `:1127-1132`, with no `fxp0` or management-interface exemption in the skip check (`:1094-1099`). `daemonOwned` includes `vrf-mgmt`, routing VRFs, tunnels, fabric, and bridges (`:1065-1092`), not a management NIC. The immediate strip/down path is at `:1134-1149`. `networkd` renders `ActivationPolicy=always-down` when `Unmanaged` or `Disable` is true at `pkg/networkd/networkd.go:400-414`. This validates Item 4's proposed enforcement site for normal applies, but corrupt-DB protection cannot rely only on this path because no compile/apply happens after the fatal `Load` return.

## Additional Attacks

- OQ-E cluster: current deploy scripts make case 2 safe, but node-id alone is not enough for `clusterMode=true`; add an explicit predicate test or define node-id-only boot behavior.
- Bootstrap-mode gate placement: PASS for cases 1-3/5 if placed in `daemon_run.go` after `Load()` plus `bootstrapFromFile()` and before `daemon_run.go:231`. That preserves case 2/3 normal behavior. Case 4 needs a pre-`Load`/pre-fatal lifeline exception or an explicit no-lifeline admission.
- Already-done/mis-cited: no material line-citation kill. Do not spend implementation effort "fixing" gRPC/REST forward commit serialization; fix timeout rollback ownership.
- OQ-G split: yes. Ship Item 1 first if possible. It fixes a confirmed rollback bug with a bounded configstore/daemon test surface. Items 2-4 depend on the OQ-A and marker-format decisions and touch startup, link naming, networkd ownership, and cluster availability.
