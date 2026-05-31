# Plan: #1713 — systemd-resolved renderer drops domain-search when domain-name is set

- **Status**: PLAN-READY v2 — Codex PLAN-NEEDS-MINOR (addressed), AGY
  PLAN-READY, Claude-SMR PLAN-READY. v2 fixes the resolved.conf ordering
  rationale, the de-dup precision, and the empty-search-element guard.
- **Issue**: #1713
- **Branch**: refactor/1713-resolved-dns-renderer
- **Coordinate with**: #1715 (DNS-ownership research; converged PLAN-READY
  Path A). #1715 sequences AFTER #1713 and builds `RenderResolvConf` /
  `reconcileDNS` on the `pkg/daemon/system/dns.go` seam this PR creates.
- **Mode**: /engineer (triple-review) — drives to MERGE.

## 1. Issue framing

`pkg/daemon/daemon_system.go` `applySystemDNS` (~:253-256) renders the
systemd-resolved drop-in `/etc/systemd/resolved.conf.d/xpf.conf`. The
`Domains=` line is emitted with an `else if`:

```go
if cfg.System.DomainName != "" {
    fmt.Fprintf(&b, "Domains=%s\n", cfg.System.DomainName)
} else if len(cfg.System.DomainSearch) > 0 {
    fmt.Fprintf(&b, "Domains=%s\n", strings.Join(cfg.System.DomainSearch, " "))
}
```

The config grammar accepts BOTH `system domain-name` and
`system domain-search` simultaneously (verified by `parser_ast_test`).
When both are set the `else if` silently drops the search list: the
operator's `domain-search [ corp.example.com lab.example.com ]` never
reaches resolved. systemd-resolved's `Domains=` directive accepts a
single space-separated list mixing the routing domain and search
domains (`Domains=example.com corp.example.com lab.example.com`), so
both SHOULD render on one line.

## 2. Honest scope / value framing

This is a small correctness fix (Medium correctness risk per the issue),
not a perf refactor. The win is: an operator who configures both
`domain-name` and `domain-search` gets a working search list instead of
silently losing it — no perf dimension. The secondary value is the
renderer-extraction seam that #1715 explicitly depends on (it needs the
same pure `pkg/daemon/system/dns.go` plus a `RenderResolvConf` built on
top). If reviewers conclude the renderer extraction is unjustified churn
for a one-line `else if` fix, PLAN-KILL of the *extraction* is an
acceptable verdict — but the `Domains=` combine fix itself is a real
correctness bug with a config path that reaches it, so killing the whole
issue would need a counter-argument that the combined-list semantics are
wrong (see §11 Q1).

## 3. systemd-resolved `Domains=` semantics (verified)

Per `resolved.conf(5)`: `Domains=` takes a space-separated list of
domains processed **in the specified order**. A bare domain is a
**search domain** (a suffix appended to single-label lookups, tried in
list order). A domain prefixed with `~` is a **routing-only domain**
(used for split-DNS routing, NOT search). xpf's `domain-name` is the Junos
primary domain — it functions as both the host's primary domain and a
search domain in classic resolv.conf (`domain` + `search` semantics).
Rendering it as the FIRST bare entry in the combined list preserves the
"primary domain is also searched" behavior and matches what the current
code does in the `domain-name`-only case (it already emits
`Domains=example.com` as a bare search domain). So the combined form is:

```
Domains=<domain-name> <search-domain-1> <search-domain-2> ...
```

with `domain-name` first (when set), followed by each `domain-search`
entry in config order. Because bare entries are an **ordered** search
list, putting `domain-name` first preserves its primary-domain
precedence (it is searched before the explicit search domains), and the
relative order of the distinct search domains is unchanged.

**De-duplication (precise rule):** skip a `domain-search` entry ONLY
when `domain-name` is non-empty AND the search entry string-equals it.
This removes the redundant *second* occurrence of the primary domain
(its first occurrence already leads the list) without reordering any
distinct suffix. The guard is `if domainName != "" && d == domainName`
(not bare `d == domainName`) so an empty `domain-name` never causes an
empty-string search element to be silently dropped — that path is
parser-unreachable today but the guard keeps the renderer total and
prevents a latent divergence from the old code's
`strings.Join(search, " ")`.

## 4. What already exists

- `applySystemDNS` (daemon_system.go:235-272): the apply path. Writes
  the drop-in, compares-before-write for idempotence, calls
  `restartResolved()`.
- `cfg.System.NameServers []string`, `DomainName string`,
  `DomainSearch []string` (config/types.go:587-590) — the inputs.
- No `pkg/daemon/system/` package exists yet. No render unit test exists
  for the drop-in.
- #1715 (research/1715-dns-resolv-ownership) is PLAN-READY and explicitly
  states (§7): "#1713 lands first as the renderer-extraction seam (small,
  isolated, pure-function + test), then #1715 builds the ownership
  reconciler on top of `pkg/daemon/system/dns.go`."

## 5. Concrete design

### 5a. New file `pkg/daemon/system/dns.go` — pure renderer

```go
// Package system holds pure, testable renderers for system-level
// config artifacts the daemon writes (DNS resolver config, etc.).
package system

import (
	"fmt"
	"strings"
)

// ResolvedDropinInput is the subset of system config that drives the
// systemd-resolved drop-in render. Kept a plain value type so the
// renderer is a pure function with no daemon/config dependency.
type ResolvedDropinInput struct {
	NameServers  []string
	DomainName   string
	DomainSearch []string
}

// Empty reports whether there is no DNS config to render (the caller
// uses this to decide between writing and removing the drop-in).
func (in ResolvedDropinInput) Empty() bool {
	return len(in.NameServers) == 0 && in.DomainName == "" && len(in.DomainSearch) == 0
}

// RenderResolvedDropin returns the full text of the
// /etc/systemd/resolved.conf.d/xpf.conf drop-in for the given input.
// It combines domain-name and domain-search into a single Domains=
// list (domain-name first, then search domains in order, de-duplicated)
// so a config that sets both does not silently drop the search list
// (#1713). Returns "" when Empty().
func RenderResolvedDropin(in ResolvedDropinInput) string {
	if in.Empty() {
		return ""
	}
	var b strings.Builder
	b.WriteString("# Generated by xpfd — do not edit\n[Resolve]\n")
	if len(in.NameServers) > 0 {
		fmt.Fprintf(&b, "DNS=%s\n", strings.Join(in.NameServers, " "))
	}
	domains := combinedDomains(in.DomainName, in.DomainSearch)
	if len(domains) > 0 {
		fmt.Fprintf(&b, "Domains=%s\n", strings.Join(domains, " "))
	}
	return b.String()
}

// combinedDomains builds the Domains= list: domain-name first (when
// set), then each search domain in order, skipping any search entry
// equal to the domain-name to avoid a duplicate.
func combinedDomains(domainName string, search []string) []string {
	out := make([]string, 0, 1+len(search))
	if domainName != "" {
		out = append(out, domainName)
	}
	for _, d := range search {
		if domainName != "" && d == domainName {
			continue
		}
		out = append(out, d)
	}
	return out
}
```

### 5b. `applySystemDNS` rewires to call the renderer

The byte-for-byte output for existing single-input cases is preserved
(the header, `DNS=`, and the `domain-name`-only / `domain-search`-only
forms are identical to today). Only the both-set case changes (from
dropping search to combining). The apply wrapper keeps the
empty→remove, compare-before-write, MkdirAll, write, and
`restartResolved()` behavior exactly as today:

```go
func (d *Daemon) applySystemDNS(cfg *config.Config) {
	const dropinDir = "/etc/systemd/resolved.conf.d"
	const dropinPath = dropinDir + "/xpf.conf"

	content := system.RenderResolvedDropin(system.ResolvedDropinInput{
		NameServers:  cfg.System.NameServers,
		DomainName:   cfg.System.DomainName,
		DomainSearch: cfg.System.DomainSearch,
	})

	if content == "" {
		// Remove drop-in if no DNS config and file exists.
		if _, err := os.Stat(dropinPath); err == nil {
			os.Remove(dropinPath)
			restartResolved()
		}
		return
	}

	current, _ := os.ReadFile(dropinPath)
	if string(current) == content {
		return // no change
	}

	os.MkdirAll(dropinDir, 0755)
	if err := os.WriteFile(dropinPath, []byte(content), 0644); err != nil {
		slog.Warn("failed to write resolved drop-in", "path", dropinPath, "err", err)
		return
	}
	slog.Info("DNS config applied via resolved", "domain", cfg.System.DomainName,
		"search", cfg.System.DomainSearch, "servers", cfg.System.NameServers)
	restartResolved()
}
```

### 5c. New test `pkg/daemon/system/dns_test.go`

Table-driven, covering: empty (→ ""), DNS-only, domain-name only,
domain-search only, DNS+domain-name, DNS+domain-search, COMBINED
domain-name + domain-search (the #1713 case), and the de-dup case
(domain-name repeated in domain-search). Each asserts the exact rendered
string — pinning both the `DNS=`-before-`Domains=` line ordering and the
combined-list content.

## 6. Public API preservation

- `applySystemDNS(cfg *config.Config)` signature unchanged (method on
  `*Daemon`).
- `restartResolved()`, drop-in path constant, file mode 0644, dir 0755,
  idempotence comparison — all unchanged.
- New exported surface: `system.ResolvedDropinInput`,
  `system.RenderResolvedDropin`, `ResolvedDropinInput.Empty()`. Additive
  only; nothing else imports `pkg/daemon/system` yet (#1715 will).

## 7. Hidden invariants preserved

- **Byte-identical output for all currently-rendered cases.** The header
  string, `[Resolve]` section, `DNS=` line, and the two single-domain
  forms are emitted exactly as today. Only the previously-buggy both-set
  case changes output (intentionally). The render test pins the existing
  forms so the extraction cannot silently alter them.
- **Empty-config → remove semantics.** The `Empty()` predicate is the
  exact same boolean as the current guard at :239 (`NameServers == 0 &&
  DomainName == "" && DomainSearch == 0`), so the remove path is
  unchanged.
- **Idempotence / no-churn.** compare-before-write stays in the wrapper;
  `restartResolved()` only fires on actual change or removal.
- **No new restart churn.** Combining domains changes the rendered bytes
  only for already-both-set configs, which is a one-time content change
  on upgrade for affected boxes (correct — they were getting wrong
  output before).
- **No daemon/config coupling in the pure layer.** The renderer takes a
  plain value struct, so #1715 can call it from a reconciler without
  importing daemon internals.

## 8. Risk assessment

| Class | Level | Notes |
|-------|-------|-------|
| Behavioral regression | LOW | Only the both-set case changes output, and that change fixes the bug. All other cases byte-identical (pinned by test). |
| Lifetime / borrow | N/A | Go; no lifetime concerns. No new goroutines/locks. |
| Performance regression | NONE | Control-plane render on commit only; not a hot path. |
| Architectural mismatch | LOW | The extraction shape is exactly what #1715 (PLAN-READY) asked for in §7. Risk is over-engineering a one-liner — mitigated by keeping the renderer minimal and the wrapper thin. Reviewers may PLAN-KILL the extraction in favor of an in-place `else`→combined fix; see §11 Q3. |

## 9. Test plan

- `GOCACHE=/dev/shm/cache GOTMPDIR=/dev/shm go test ./pkg/daemon/...` —
  new `pkg/daemon/system` tests pass + existing daemon tests pass.
- `go vet ./pkg/daemon/...`.
- Full Go suite `go test ./...` (30 packages) — prove no regression.
  Pre-existing `pkg/dataplane/userspace` sandbox failures are known
  artifacts; prove pre-existing by running the same on origin/master.
- NO cluster smoke — this is a control-plane DNS-render change with no
  dataplane/CoS/forwarding surface. The gate is the Go suite + the new
  render unit tests (stated explicitly per the engineer scope).

## 10. Out of scope (explicitly — all #1715)

- resolv.conf symlink ownership / dangling-symlink repair.
- systemd-resolved disable/mask vs enable logic (`applyDNSService`).
- `reconcileDNS` / `reconcileDNSLocked` / `reconcileDNSFromDHCP`.
- `RenderResolvConf` (the plain `/etc/resolv.conf` renderer) — #1715 adds
  it to the same `pkg/daemon/system/dns.go` file.
- The DHCP `installDNS` notify-not-write change.
- Removing legacy `bpfrx.conf` drop-in.
- The apply-order race between `applySystemDNS` and `applyDNSService`.

This PR touches ONLY the resolved drop-in renderer + the `Domains=`
combine fix + the new pure-renderer seam + its test.

## 11. Open questions for adversarial review (each can invite PLAN-KILL)

1. **Combined-list semantics.** Is rendering
   `Domains=<domain-name> <search...>` (domain-name first, bare entries)
   the correct systemd-resolved semantics for Junos `domain-name` +
   `domain-search`? Specifically: should `domain-name` be a routing-only
   `~`-prefixed entry instead of a bare search entry? (I argue NO — Junos
   `domain-name` is the primary/search domain, and the current code
   already emits it bare; making it routing-only would change existing
   single-domain behavior. KILL if this reasoning is wrong.)
2. **De-dup correctness.** Is dropping a `domain-search` entry equal to
   `domain-name` safe? resolved processes bare `Domains=` entries as an
   **ordered** search list, so order does matter — but removing the
   redundant *later* occurrence of the primary domain (which already
   leads the list) does NOT reorder any distinct suffix, so resolution
   order of the real search domains is preserved. The guard is scoped
   to `domainName != "" && d == domainName` so no empty-string element
   is ever dropped.
3. **Extraction vs in-place fix.** Is extracting `pkg/daemon/system/dns.go`
   justified for #1713 alone, or is it churn that should wait for #1715?
   (#1715's plan §7 explicitly requests #1713 create this seam first.
   PLAN-KILL the extraction → fall back to in-place `else`→combined and
   let #1715 do the extraction; acceptable but contradicts the
   converged #1715 sequencing.)
4. **Byte-identical claim.** Walk the proposed `RenderResolvedDropin`
   against the current `applySystemDNS` for the DNS-only, domain-name-
   only, and domain-search-only cases — is the output truly identical
   (header, newlines, spacing)? A mismatch would churn drop-ins on
   upgrade for boxes that aren't hitting the bug.
5. **Empty() equivalence.** Is `ResolvedDropinInput.Empty()` exactly the
   negation of the write condition, i.e. does moving the empty check
   into the renderer preserve the remove-drop-in path for every input
   the old `:239` guard caught?
6. **Does #1715 actually want this shape?** Verify against
   `docs/research/1715-dns-resolv-ownership/plan.md` §7 that a pure
   value-struct renderer in `pkg/daemon/system/dns.go` is compatible
   with #1715 adding `RenderResolvConf` to the same file. If #1715 needs
   a different signature, align now to avoid a rework.
