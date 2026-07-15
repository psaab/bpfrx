# Triage result — ps-review-037-A10-b1

- **Subsystem:** A10 — Services (DHCP/DHCPRelay/DHCPServer/DDNS) + policymatch simulator + CLI/show/monitor + build/deploy tooling (`scripts/deploy/xpf-deploy.py`)
- **Review base:** d4506d4450e23f9a3fc572206b3c82f6b6c99029
- **Triaged against master SHA:** 57d24d9aed4b64680831a1765a128921e79c00f7 (origin/master, fetched)
- **Source:** REAL bpfrx (all cited files/lines exist on master; no avacado confabulation tells — real paths, real line numbers, symbols present)
- **Outcome counts:** 2 actionable findings + 22 self-labelled NEGATIVE.
  - GENUINE-RESIDUAL: 2 (A10-01 LOW, A10-02 MEDIUM/LOW-MED)
  - DUP: 0 · ALREADY-FIXED: 0 · CONFABULATED: 0 · NEGATIVE (author-verified-correct, spot-checked): 22

---

## A10-01 — `monitor traffic count` accepts negative / unbounded via Atoi (Low) → GENUINE-RESIDUAL (LOW, cosmetic)

**Symbol exists.** `pkg/cli/cli_request.go:556-558` on master:
```go
count = args[i]
if _, cerr := strconv.Atoi(count); cerr != nil {
    return "", "", "", fmt.Errorf("monitor traffic: 'count' requires a numeric value, got %q", count)
}
```
and `buildMonitorTrafficArgv` (`cli_request.go:586-589`) appends `-c <count>` verbatim when `count != "0"`. `strconv.Atoi("-1")` and `strconv.Atoi("999999999")` both succeed, so the count-parse gate only rejects non-numeric — it does NOT reject negatives or apply an upper bound. Confirmed unguarded path.

**Contrast verified.** Sibling `monitor security packet-drop` at `pkg/cli/monitor.go:869-875` bounds `err != nil || v < 1 || v > 8192` → "count must be 1..8192". So the inconsistency the finding cites is real.

**Reachability:** `monitor traffic` is gated to `PermControl` (per N-A10-20 / #4067), so only an operator with control rights reaches it.

**Why GENUINE but LOW (materiality is UX-only, not security/availability):**
- `count -1` → argv `tcpdump ... -c -1 -- <filter>`. tcpdump's own optarg validation rejects a non-positive count with an opaque "invalid packet count" error. The failure is clean; the only defect is that the error text comes from tcpdump instead of the CLI. No injection — the `-c -1` is a value bound to `-c`, not a smuggled option (and the `--` separator already fences the filter tokens, #4524).
- `count 999999999` (huge positive) is behaviourally identical to `count 0` = unlimited, which is an **already-supported mode**. So the "operator self-DoS with a giant count" angle is undercut — the operator can already run an unbounded capture by design. There is no new capability or blast radius.
- Net: a real input-validation *consistency* gap (negatives should be rejected CLI-side to match sibling commands), but the impact is limited to error-message quality. No dataplane, no privilege, no DoS beyond the already-allowed unlimited mode.

**Why not higher:** RBAC-gated; no injection (filter fencing intact); huge-count == already-allowed unlimited; negative == clean tcpdump-side error. **Why not dismissed:** it is a genuine unguarded numeric leaf that diverges from the project's own sibling-command bounding convention (monitor.go 1..8192, flow file size 10240..1073741824, files 2..1000) — a legitimate LOW.

**Dedup:** #4540 fixed missing-value / keyword-swallowing on `interface`/`count`/`matching` but explicitly did not add a numeric range. Not in the #4517-#4581 session backlog, not in #4556/#4549. Novel.

**Fix (lane=go, non-cargo):** at `cli_request.go:556`, after Atoi, reject `v < 0` and cap the upper bound (e.g. `v > 1000000`, or 8192 to mirror packet-drop), keeping `0 = unlimited`.

---

## A10-02 — day-0 config ISO created world-readable (0o644) in CWD, embeds all day-0 secrets (Medium) → GENUINE-RESIDUAL (MEDIUM, leans LOW-MED)

**Symbol exists.** `scripts/deploy/xpf-deploy.py`:
- `:296` `iso = os.path.join(os.getcwd(), f"{ap['name']}-day0.iso")`
- `:317` staging dir `tempfile.mkdtemp(prefix="xpf-day0-")` (mode 0o700 — safe)
- `:320` `os.chmod(os.path.join(stage, "xpf.conf"), 0o644)` (staged copy, but inside the 0o700 dir → protected)
- `:329` `run_capture(argv)` — xorriso/genisoimage writes the final ISO to CWD under the process umask (typically 0o022 → **0o644**), and there is **no `os.chmod(iso, 0o600)` anywhere in the file** (grep confirms only the two staging chmods, no ISO chmod).

The ISO contains `xpf.conf`, which is the most secret-bearing artifact in the system: `system root-authentication` hash, `security ike ... pre-shared-key`, `snmp community`, DDNS `tsig`/provider `api-token`/`password`, etc. Any co-located UID can `isoinfo -R -i <name>-day0.iso -x /xpf.conf` and extract them. The ISO persists in CWD until `destroy_incus`/`destroy_libvirt` (`:749`/`:765`) removes it — and deploys are frequently not followed by a destroy, so the artifact can persist indefinitely.

**Reachability:** every `deploy` (`deploy_incus :475`, `deploy_libvirt :630`) calls `build_config_drive` and materialises the world-readable ISO. Real exposure on multi-user build hosts / shared CI runners / jump hosts.

**Why GENUINE but bounded to MEDIUM/LOW-MED:**
- Blast radius is maximal IF exploited (full day-0 secret set), which justifies Medium over Low.
- BUT it is **local-only** — requires a second UID with read access on the build host. On a single-user workstation there is no other principal.
- The plaintext source config (`cfg_path`) already lives on the same build host at whatever mode the operator gave it; the ISO is a *second* copy. The genuine defect is that the tool **silently downgrades** to 0o644 even when the operator kept the source at 0o600 — a secret-at-rest hygiene regression, not a brand-new secret location. This is why it sits at LOW-MED rather than a clean Medium.
- Not a dataplane / privilege-escalation / remote issue — pure defense-in-depth.

**Why not higher (HIGH):** no remote vector, no privilege escalation, requires local co-located UID, and secrets are already present on the build host in the source config. **Why not dismissed:** the tool creates a NEW world-readable copy of maximally-sensitive material and provides no way to avoid it; one-line `os.chmod(iso, 0o600)` closes it. Legitimate Medium-with-caveats.

**Dedup:** the fable-165 deploy audit filed many `xpf-deploy.py` issues (#4188 hostdev, #4189 anti-rollback, #4190 fetch path, #4204 traceback/H-21, #4205 --no-start/H-26, #4206 preflight-destroy/H-27, #4211 gate test coverage) but **none** touch ISO file mode / secret-at-rest. The world-readable-secret issues in history (#3909 syn_cookie state.json, #64098 rollback/rescue 0644, #4175/#65515 day-0 *loader* on the appliance) are all *appliance-side* or configstore, not the build-host deploy ISO. Not in #4517-#4581. Novel.

**Fix (lane=go, non-cargo — Python deploy tooling, no cargo/shim gate):** after `run_capture(argv)` at `:329`, add `os.chmod(iso, 0o600)`; optionally tighten the staged `xpf.conf` chmod at `:320` from 0o644 to 0o600 for consistency (the 0o700 dir already protects it, so this is cosmetic defense-in-depth).

---

## NEGATIVE findings (author-verified-correct)

N-A10-01..22 are the reviewer's own "verified correct, no bug" block covering DHCPRelay giaddr/hopcount/allow-list/delivery-matrix, DHCP renewal-overflow/degenerate-mask/NAK/classless-RFC3442, DDNS PrevAddr/Cloudflare/DHCID/martian/redaction/source-bind/httpcache/withdraw/state-durability, policymatch simulator parity, CLI test-policy SSOT / monitor injection-closed / permissions-redaction / trace rotation, and deploy safe-load/shlex/fetch-verify/NIC-order/preflight/signing. These are assertions of correctness (not bug claims); spot-checked representative ones (monitor.go count bound, `--` filter fence, `os.chmod` staging) are consistent with the code on master. No action — recorded as NEGATIVE, no residual.

---

## Bottom line

2 genuine residuals, both LOW-ish and both non-cargo Python/Go one-liners:
- **A10-01 (LOW):** add negative/upper-bound check to `monitor traffic count` at `cli_request.go:556` to match sibling-command bounding. Materiality is UX/consistency only (huge==already-allowed-unlimited; negative==clean tcpdump error).
- **A10-02 (MEDIUM/LOW-MED):** `os.chmod(iso, 0o600)` after `run_capture` at `xpf-deploy.py:329` — the day-0 ISO is world-readable in CWD and embeds the full day-0 secret set; local-only, bounded by the source config already living on the build host.

No High. No confabulation. No dup against the session backlog.
