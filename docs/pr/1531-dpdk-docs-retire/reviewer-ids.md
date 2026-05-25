# Reviewer IDs — PR #1534 (#1531 DPDK docs retirement)

Branch: `dpdk-retire/1531-docs`
PR URL: https://github.com/psaab/xpf/pull/1534

## Round 2 — SHA `41bbf1d830f0873b78117ca43180ee67ad4c83b2`

Addressing Copilot round-1 nits (4 items) on prior SHA `aff968b6`:

1. Harmonize "is being retired" → "is retired" banners in
   `docs/dataplane-decision-dpdk-vs-vpp.md` + `docs/dpdk-dataplane.md`.
2. Convert bare code span to markdown link for
   `vpp-dataplane-assessment.md` in the Related (Active) Documents section.
3. Tighten "underlay-NIC XSK" wording to talk about userspace-dp's
   AF_XDP socket on the physical NIC instead of conflating NIC XDP and
   AF_XDP socket.
4. Drop the "The previous header read:" preamble and fold the prior
   #1475 policy text into a narrative paragraph in the [Retired] section.

Smoke skipped (pure-docs PR).

### Dispatched reviewers

- **Copilot**: triggered via `@copilot review` PR comment
  `https://github.com/psaab/xpf/pull/1534#issuecomment-4531821079`
  (round-1 verdict on aff968b6 was "No blocking issues" with 4 nits;
  this round revalidates the nit fixes).
- **Codex companion**: `task-mpkrvxss-6wwlip` (background hostile
  code review).
- **Antigravity (AGY)**: `adversarial-review-mpkrwdls-x93rlu`
  (background adversarial review, base `origin/master`).

### Verdict tracker

| Reviewer  | Verdict        | Notes                                  |
|-----------|----------------|----------------------------------------|
| Copilot   | pending        | re-triggered on 41bbf1d8               |
| Codex     | pending        | task-mpkrvxss-6wwlip                   |
| AGY       | pending        | adversarial-review-mpkrwdls-x93rlu     |
