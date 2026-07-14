# agy Review Audit 004 - Core Connection Tracking, NAT, Policy & Feed Validation

## 1. Base Commit Reviewed

- Repository: `/home/ps/git/gemini-xpf`
- Base commit: `9419bbc2c59e3eda4f6f258a30d1d4e62d32d9a9`
- Pull status: `git pull --rebase` returned `Already up to date.`
- Output path: `/tmp/agy-review-004.md`

## 2. Duplicate Suppression Summary

- Prior `/tmp/codex-review*.md` / `/tmp/agy-review*.md` files cross-referenced:
  - `/tmp/codex-review-001.md`
  - `/tmp/codex-review-002.md`
  - `/tmp/codex-review-121.md`
  - `/tmp/codex-review-122.md`
  - `/tmp/codex-review-123.md`
  - `/tmp/agy-review-001.md`
  - `/tmp/agy-review-002.md`
  - `/tmp/agy-review-003.md`
  - `/tmp/agy-review-121.md`
  - `/tmp/agy-review-122.md`
- Suppressed Findings (present in prior reviews):
  - **Ingress Physical Interface Index Override Lookup Bypass in Fast-Path Host-Inbound Admission** (Suppressed as duplicate of H04: "Per-interface host-inbound override likely misses VLAN logical interfaces on AF_XDP LocalDelivery").

---

## 3. High Confidence Findings

### AGY-004-01 - Go Memory Model Data Race on Connection Tracking GC Configuration Fields

- **Severity**: High
- **Subsystem**: Connection Tracking & Session Management Garbage Collector
- **Exact File Pointer & Quoted Code Snippet**:
  - File: [pkg/conntrack/gc.go:168-196](file:///home/ps/git/gemini-xpf/pkg/conntrack/gc.go#L168-L196)

```go
// SetAgingConfig updates the aggressive aging parameters.
// earlyAgeout is the shortened timeout in seconds (0 = disabled).
// highWM/lowWM are utilization percentages of MaxSessions (0 = disabled).
func (gc *GC) SetAgingConfig(earlyAgeout, highWM, lowWM int) {
	gc.mu.Lock()
	defer gc.mu.Unlock()
	if earlyAgeout < 0 {
		earlyAgeout = 0
	}
	gc.earlyAgeout = uint64(earlyAgeout)
	gc.highWatermark = highWM
	gc.lowWatermark = lowWM
	if highWM == 0 || earlyAgeout == 0 {
		gc.agingActive = false
	}
}

// SetSessionLimitEnabled enables or disables per-IP session counting
// during GC sweeps. When enabled, GC accumulates per-src/dst counts
// and pushes them to BPF maps for xdp_screen session limiting.
func (gc *GC) SetSessionLimitEnabled(enabled bool) {
	gc.mu.Lock()
	defer gc.mu.Unlock()
	gc.sessionLimitEnabled = enabled
}
```

- **Step-by-Step Technical Failure & Execution Trace**:
  1. **Initialization**: The GC daemon is started, spawning a background goroutine running `gc.Run(ctx)` which loops continuously and invokes `gc.sweep()`.
  2. **Concurrent Config Update**: The operator modifies and applies a new security configuration. The main daemon thread handles this by calling `d.gc.SetAgingConfig(...)` and `d.gc.SetSessionLimitEnabled(...)` in `pkg/daemon/daemon_apply.go`.
  3. **Locking Contention**: The configuration update threads acquire `gc.mu.Lock()`.
  4. **Lock-Free Read / Mutation in Sweep**:
     - Concurrently, inside `gc.sweep()`, the loop evaluates session expiration times and reads `gc.sessionLimitEnabled`, `gc.agingActive`, and `gc.earlyAgeout` without acquiring `gc.mu` (neither `Lock()` nor `RLock()`).
     - At the end of `gc.sweep()`, the watermark evaluation logic evaluates:
       ```go
       if !gc.agingActive && pct >= gc.highWatermark {
           gc.agingActive = true
       ```
       This modifies `gc.agingActive` directly without holding `gc.mu`.
  5. **Memory Visibility / Register Caching**: The Go compiler caches the non-volatile fields `gc.agingActive` and `gc.earlyAgeout` in registers (e.g. `RAX`) during map iteration loops (`ForEachV4`), preventing the sweep goroutine from observing updates performed by `SetAgingConfig`. On 32-bit architectures, the concurrent read and write of the 64-bit value `gc.earlyAgeout` causes **read tearing**, resulting in corrupted deadlines.

- **Irrefutability Proof & Upstream Verification**:
  - Upstream caller verification: `gc.Run()` runs on a dedicated background thread spawned at startup:
    ```go
    // pkg/daemon/daemon_run.go:792
    go gc.Run(ctx)
    ```
  - Mutexes: No `gc.mu` read locks are acquired anywhere in the body of `sweep()` or `nextSweepDelayAt()`, which directly accesses these fields.
  - Go Memory Model Specification: Concurrent read and write operations on the same memory location without synchronizing barriers (channels, mutexes, or atomic variables) constitute a data race.

- **vSRX Parity & Systems Impact**:
  - Can cause aggressive aging configurations to be ignored, leading to session table saturation.
  - Watermark updates will clobber manual configuration changes, leading to unstable aging state or memory corruption due to read tearing.

- **Suggested Fix Direction & Labels**:
  - Wrap read operations in `sweep()` and `nextSweepDelayAt()` with `gc.mu.RLock()` / `gc.mu.RUnlock()`, or transition the configuration fields to atomic types (e.g., `atomic.Bool` and `atomic.Uint64`).
  - Labels: `concurrency`, `bug`, `connection-tracking`, `garbage-collector`

---

### AGY-004-02 - Static NAT Rule Shadowing and Overwrite Bug in `StaticNatTable::from_snapshots`

- **Severity**: High
- **Subsystem**: NAT Engine (Static NAT)
- **Exact File Pointer & Quoted Code Snippet**:
  - File: [userspace-dp/src/nat/static_nat.rs:376-405](file:///home/ps/git/gemini-xpf/userspace-dp/src/nat/static_nat.rs#L376-L405)

```rust
            let entry = StaticNatEntry {
                external_ip,
                internal_ip,
                from_zone: snap.from_zone.clone(),
                from_interface: snap.from_interface.clone(),
                from_routing_instance: snap.from_routing_instance.clone(),
                match_dst_port,
                mapped_port,
                source: SourceConstraint::from_list(&snap.source_addresses),
                hit_counter: nat_counters.rule_counter(snap.counter_id),
            };
            // DNAT keyed by the external (pre-translation) destination port.
            table.dnat.insert((external_ip, match_dst_port), entry.clone());
            ...
            let snat_port = mapped_port.or(match_dst_port);
            table.snat.insert((internal_ip, snat_port), entry);
```

- **Step-by-Step Technical Failure & Execution Trace**:
  1. **Configuration**: The operator configures two split-horizon Static NAT rules for external IP `192.0.2.1` on port `443` associated with different source constraints or interfaces:
     - **Rule A**: Ingress from interface `ge-0/0/0.0` $\to$ internal IP `10.0.0.1:443`.
     - **Rule B**: Ingress from interface `ge-0/0/1.0` $\to$ internal IP `10.0.0.2:443`.
  2. **Compilation**: The snapshots are compiled, generating two `StaticNATRuleSnapshot` entries with `external_ip = "192.0.2.1"` and `match_destination_port = 443`.
  3. **Table Insertion Overwrite**:
     - During `from_snapshots`, the loop processes **Rule A** and executes:
       `table.dnat.insert((192.0.2.1, Some(443)), entry_A)`
     - Next, the loop processes **Rule B** and executes:
       `table.dnat.insert((192.0.2.1, Some(443)), entry_B)`
     - This overwrites **Rule A** in the map because the map key is only `(IpAddr, Option<u16>)`.
  4. **Traffic Failure**:
     - A packet arrives on interface `ge-0/0/0.0` (matching **Rule A**'s source) with destination `192.0.2.1:443`.
     - The NAT engine performs a lookup for `(192.0.2.1, Some(443))`, returning `entry_B`.
     - It checks if `entry_B.from_interface` (`ge-0/0/1.0`) matches the packet's ingress interface (`ge-0/0/0.0`). The check fails.
     - The packet bypasses destination translation and is routed untranslated, leaking internal details and causing connection failures.

- **Irrefutability Proof & Upstream Verification**:
  - Map Definition: `dnat` and `snat` in `StaticNatTable` are defined as `FxHashMap<(IpAddr, Option<u16>), StaticNatEntry>`.
  - Unlike `DnatTable` (which groups entries by key in a `Vec`), `StaticNatTable` holds only a single entry per key, guaranteeing overwrites on overlapping keys.

- **vSRX Parity & Systems Impact**:
  - Junos supports multiple static NAT rules targeting the same external IP/port under different ingress interfaces or zone stanzas. Overwriting these rules breaks split-horizon NAT deployments and causes traffic leaks.

- **Suggested Fix Direction & Labels**:
  - Modify `dnat` and `snat` to store a vector of entries:
    `dnat: FxHashMap<(IpAddr, Option<u16>), Vec<StaticNatEntry>>`
  - Update `match_dnat` to iterate over the vector and match the first entry that satisfies the interface, zone, and source constraints.
  - Labels: `bug`, `nat-engine`, `static-nat`, `vsrx-parity`

---

### AGY-004-03 - Commit/Apply Split & Simulator Discrepancy on Signed Port Specifications

- **Severity**: High
- **Subsystem**: Policy Compiler & Dataplane Parser
- **Exact File Pointer & Quoted Code Snippet**:
  - File: [pkg/config/compiler_applications.go:568-575](file:///home/ps/git/gemini-xpf/pkg/config/compiler_applications.go#L568-L575)

```go
	port, err := strconv.Atoi(spec)
	if err != nil {
		return fmt.Errorf("invalid port %q: not a number or known service", spec)
	}
	if port < 1 || port > 65535 {
		return fmt.Errorf("invalid port %d: must be 1-65535", port)
	}
```

  - File: [pkg/dataplane/userspace/capabilities.go:477-481](file:///home/ps/git/gemini-xpf/pkg/dataplane/userspace/capabilities.go#L477-L481)

```go
	p, err := strconv.ParseUint(spec, 10, 16)
	if err != nil {
		return false
	}
	return p != 0
```

  - File: [userspace-dp/src/policy.rs:3319-3326](file:///home/ps/git/gemini-xpf/userspace-dp/src/policy.rs#L3319-L3326)

```rust
    let port = normalized.parse::<u16>().ok()?;
    if port == 0 {
        return None;
    }
    Some(vec![PortRange {
```

- **Step-by-Step Technical Failure & Execution Trace**:
  1. **Configuration**: An operator configures a destination port specification with a leading plus sign (e.g. `+80`):
     `set applications application my-app term t1 protocol tcp destination-port +80`
  2. **Go Commit Validation**: `validatePortSpec` uses `strconv.Atoi("+80")`, which successfully parses to `80`. The configuration commits with no errors or warnings.
  3. **Go Snapshot Compilation**: During snapshot compilation, `userspacePortSpecRepresentable("+80")` is called. It uses `strconv.ParseUint("+80", 10, 16)`, which rejects the leading sign and returns a syntax error.
  4. **Policy Downgrade**: The builder marks the application as `__unsupported__`.
  5. **Dataplane Rejection**: The Rust dataplane receives the snapshot. `parse_applications` encounters `__unsupported__` and rejects the entire snapshot application, freezing security policy updates.
  6. **Simulation Divergence**: The simulation engine evaluates rules using `portMatches("+80", 80)` via `strconv.Atoi`, asserting that the packet matches, while the actual dataplane has discarded the update.

- **Irrefutability Proof & Upstream Verification**:
  - `strconv.Atoi` supports optional signs (`+`/`-`), whereas `strconv.ParseUint` and Rust's `str::parse::<u16>()` do not accept signs.
  - An application spec containing a leading plus sign commits successfully but triggers a silent policy reload failure on the dataplane.

- **vSRX Parity & Systems Impact**:
  - Divergences between config commit validation and dataplane parsers cause silent rule freezes, leading to inconsistencies where policies are not applied.

- **Suggested Fix Direction & Labels**:
  - Replace `strconv.Atoi` in `compiler_applications.go` with `strconv.ParseUint(spec, 10, 16)` to reject signed ports at commit time.
  - Labels: `bug`, `policy-compiler`, `validation-split`

---

### AGY-004-04 - Tolerant-Load Validation Bypass for Undefined Feeds on Empty/Slash-Only Feed Servers

- **Severity**: Medium
- **Subsystem**: Dynamic Address Feeds & nftables Daemon Backend
- **Exact File Pointer & Quoted Code Snippet**:
  - File: [pkg/config/compiler_validate_strict.go:515-523](file:///home/ps/git/gemini-xpf/pkg/config/compiler_validate_strict.go#L515-L523)

```go
func feedServerBaseURLEmpty(fs *FeedServer) bool {
	if fs.URL != "" {
		return strings.TrimRight(fs.URL, "/") == ""
	}
	if fs.Hostname != "" {
		return false
	}
	return true
}
```

- **Step-by-Step Technical Failure & Execution Trace**:
  1. **Configuration**: An operator configures a feed-server with an empty URL (e.g. `url "/"`) and binds an address-name to it:
     ```
     set security dynamic-address feed-server empty-fs url "/"
     set security dynamic-address address-name my-addr profile feed-name empty-fs
     ```
  2. **Lenient Load Pipeline**:
     - During peer synchronization or backup recovery under "lenient-load", `validateDynamicAddressFeedServerEndpointStrict` is executed.
     - `feedServerBaseURLEmpty(empty-fs)` evaluates `strings.TrimRight("/", "/") == ""` and returns `true`.
     - Because it is a lenient load, the warning is suppressed, and `empty-fs` is added to the compiled configuration model (`da.FeedServers`).
     - `validateDynamicAddressFeedReferencesStrict` runs next. It populates `declared["empty-fs"] = true`.
     - The binding check for `my-addr` sees `empty-fs` in `declared` and returns no error, allowing the commit to succeed.
  3. **Runtime Execution**:
     - At runtime, `feeds.Manager.Apply` initializes the feed and calls `resolveBaseURL(empty-fs)`.
     - `resolveBaseURL` evaluates `strings.TrimRight("/", "/")`, returning `""`.
     - Since the base URL is empty, the feed is silently skipped and never registered.
     - The security policy referencing `my-addr` now binds to a non-existent runtime feed, leaving the policy open without source constraints.

- **Irrefutability Proof & Upstream Verification**:
  - `feedServerBaseURLEmpty` returns `true` for slash-only URLs, but `validateDynamicAddressFeedReferencesStrict` accepts the server as a valid reference if it is present in the `FeedServers` list, masking the downstream omission.

- **vSRX Parity & Systems Impact**:
  - Causes security policies to compile without address restrictions, leaving them open to arbitrary external traffic.

- **Suggested Fix Direction & Labels**:
  - Enforce feed-server validation checks uniformly across both strict and lenient load paths, or skip rules referencing unresolvable feed sources rather than generating open bypasses.
  - Labels: `bug`, `feeds`, `security`, `validation-bypass`
