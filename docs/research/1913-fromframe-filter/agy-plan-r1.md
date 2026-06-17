# AGY adversarial plan review — #1913 r1
Job: adversarial-review-mqho660c-2s2cwj  VERDICT: PLAN-NEEDS-REVISION

Findings (all folded into r2):
1. §2.2 PolicyDenied->kernel-FIB trace CORRECT (no earlier drop point). Evidence: mod.rs:1693-1694 (disposition set), :1794-1798 (misses forward branch), :2799 (counter only), :2814 (unconditional reinject), slow_path.rs:129 (no filter).
2. §2.6 partly incorrect: dispatch/mod.rs:225 Owned->_from_frame (unfiltered) but :238 desc->filtered wrapper which REJECTS FabricRedirect => desc-frame FabricRedirect silently DROPPED. Asymmetry / pre-existing bug, not clean intentional bypass.
3. Path C correctly rejected: wrapper re-slices area.slice(desc.addr,desc.len) at slow_path.rs:100 => re-introduces #1885.
4. §2.1 table mis-tabulations: ForwardCandidate/FabricRedirect consumed at :1794-1798 (never reach :2814); MissingNeighbor SNAT-failure continues at :2533/:2564 omitted.
Required: fix §2.1 table; address/document the FabricRedirect :238 asymmetry (out of scope but must not be mischaracterized).
