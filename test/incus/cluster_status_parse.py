"""Parser for `cli -c "show chassis cluster status"` output.

Extracts the list of (rg_id, node_id, state) triples per sample,
keyed deterministically by (rg_id, node_id) for cross-sample
comparison.

Output format (one block per RG, see pkg/cluster/cluster.go:1767):

    Redundancy group: 1 , Failover count: 0
    Node    Priority  Status         ...
    node0   200       primary        ...
    node1   100       secondary      ...

The local node always reports itself + the peer (when alive).
"""

import re
from typing import List, Tuple

# Public type alias for clarity.
StateTriple = Tuple[int, int, str]  # (rg_id, node_id, state)

_RG_HEADER_RE = re.compile(r"^Redundancy group:\s*(\d+)\s*,")
# State strings emitted by `pkg/cluster/cluster.go:NodeState.String()`:
# "primary", "secondary", "secondary-hold", "lost", "disabled". The regex
# anchors with `\b` and captures hyphenated suffixes (R3 HIGH:
# `secondary-hold` was previously truncated to `secondary`, masking the
# state transition).
_NODE_ROW_RE = re.compile(
    r"^node(\d+)\s+\d+\s+(primary|secondary-hold|secondary|hold|disabled|lost)\b",
    re.IGNORECASE,
)


def parse_cluster_status(text: str) -> List[StateTriple]:
    """Parse the multi-line output, return sorted (rg_id, node_id, state)."""
    if not text:
        return []
    triples: List[StateTriple] = []
    current_rg: int | None = None
    for line in text.splitlines():
        m = _RG_HEADER_RE.match(line)
        if m:
            current_rg = int(m.group(1))
            continue
        if current_rg is None:
            continue
        m = _NODE_ROW_RE.match(line)
        if m:
            node_id = int(m.group(1))
            state = m.group(2).lower()
            triples.append((current_rg, node_id, state))
    triples.sort(key=lambda t: (t[0], t[1]))
    return triples
