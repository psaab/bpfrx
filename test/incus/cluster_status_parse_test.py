import unittest

from cluster_status_parse import parse_cluster_status


SINGLE_RG = """\
Monitor Failure codes:
    CS  Cold Sync monitoring        FL  Fabric Connection monitoring
    IF  Interface monitoring        IP  IP monitoring
    CF  Config Sync monitoring

Cluster ID: 1
Node name: node0

Software version: 0.1.0
HA protocol version: 4
Peer software version: 0.1.0
Peer HA protocol version: 4

Node    Priority  Status         Preempt  Manual   Monitor-failures

Redundancy group: 1 , Failover count: 0
node0   200       primary        no       no       None
node1   100       secondary      no       no       None
"""

MULTI_RG = """\
Redundancy group: 0 , Failover count: 1
node0   200       secondary      no       no       None
node1   100       primary        no       no       None

Redundancy group: 1 , Failover count: 2
node0   200       primary        no       no       None
node1   100       secondary      no       no       None
"""

PEER_DOWN = """\
Redundancy group: 1 , Failover count: 0
node0   200       primary        no       no       None
"""

HOLD_AND_LOST = """\
Redundancy group: 1 , Failover count: 4
node0   200       hold           no       no       FL
node1   100       lost           no       no       None
"""

SECONDARY_HOLD = """\
Redundancy group: 1 , Failover count: 0
node0   200       primary        no       no       None
node1   100       secondary-hold no       no       None
"""


class ParseClusterStatusTests(unittest.TestCase):
    def test_single_rg_canonical(self):
        triples = parse_cluster_status(SINGLE_RG)
        self.assertEqual(
            triples,
            [(1, 0, "primary"), (1, 1, "secondary")],
        )

    def test_multi_rg_input_order(self):
        triples = parse_cluster_status(MULTI_RG)
        # Sorted by (rg_id, node_id):
        self.assertEqual(
            triples,
            [
                (0, 0, "secondary"),
                (0, 1, "primary"),
                (1, 0, "primary"),
                (1, 1, "secondary"),
            ],
        )

    def test_peer_down(self):
        # When peer is absent, only the local node row appears.
        triples = parse_cluster_status(PEER_DOWN)
        self.assertEqual(triples, [(1, 0, "primary")])

    def test_hold_and_lost(self):
        triples = parse_cluster_status(HOLD_AND_LOST)
        self.assertEqual(
            triples,
            [(1, 0, "hold"), (1, 1, "lost")],
        )

    def test_secondary_hold_is_distinct(self):
        # R3 HIGH: `secondary-hold` was truncated to `secondary`,
        # making secondary→secondary-hold transitions invisible.
        triples = parse_cluster_status(SECONDARY_HOLD)
        self.assertEqual(
            triples,
            [(1, 0, "primary"), (1, 1, "secondary-hold")],
        )

    def test_empty(self):
        self.assertEqual(parse_cluster_status(""), [])

    def test_malformed_no_rg_header(self):
        # Node rows without an RG header are ignored.
        text = "node0   200       primary        no       no       None\n"
        self.assertEqual(parse_cluster_status(text), [])

    def test_malformed_no_node_rows(self):
        text = "Redundancy group: 1 , Failover count: 0\nNode    Priority\n"
        self.assertEqual(parse_cluster_status(text), [])

    def test_state_case_normalized(self):
        # Defensive: even if formatter changes case in the future.
        text = "Redundancy group: 1 , Failover count: 0\nnode0   200       PRIMARY        no       no       None\n"
        self.assertEqual(parse_cluster_status(text), [(1, 0, "primary")])


if __name__ == "__main__":
    unittest.main()
