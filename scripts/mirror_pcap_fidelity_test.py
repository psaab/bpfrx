#!/usr/bin/env python3
"""Unit tests for scripts/mirror-pcap-fidelity.py.

Generates tiny in-memory pcap files (classic libpcap format) so the
fidelity logic is exercised without depending on tcpdump or any
network state. Run with:

    python3 scripts/mirror_pcap_fidelity_test.py

Each test prints `OK <name>` on pass; any failure raises and the runner
exits non-zero.
"""

from __future__ import annotations

import importlib.util
import json
import os
import struct
import sys
import tempfile
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
SCRIPT_PATH = HERE / "mirror-pcap-fidelity.py"

_spec = importlib.util.spec_from_file_location("mirror_pcap_fidelity", SCRIPT_PATH)
_mod = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
# Register before exec so @dataclass on 3.13+ can resolve cls.__module__.
sys.modules["mirror_pcap_fidelity"] = _mod
_spec.loader.exec_module(_mod)


def _write_pcap(path: Path, frames: list[bytes]) -> None:
    """Write a classic libpcap (little-endian, linktype=1 Ethernet)."""
    with path.open("wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i, frame in enumerate(frames):
            fh.write(struct.pack("<IIII", i, 0, len(frame), len(frame)))
            fh.write(frame)


def _eth_frame(payload_byte: int, payload_len: int = 60) -> bytes:
    """Minimal L2 frame: dst MAC + src MAC + ethertype + filled payload."""
    eth = bytes.fromhex("0203040506070A0B0C0D0E0F0800")
    return eth + bytes([payload_byte] * payload_len)


class MirrorFidelityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

    def test_exact_match_passes(self) -> None:
        ingress = self.dir / "ingress.pcap"
        mirror = self.dir / "mirror.pcap"
        frames = [_eth_frame(i) for i in range(10)]
        _write_pcap(ingress, frames)
        _write_pcap(mirror, frames)
        v = _mod.compare(ingress, mirror, rate=1, tolerance=None)
        self.assertTrue(v.pass_, msg=v.failure_reasons)
        self.assertEqual(v.matched_count, 10)
        self.assertEqual(v.unmatched_mirror_frames, 0)
        self.assertEqual(v.ingress_count, 10)
        self.assertEqual(v.mirror_count, 10)

    def test_byte_mismatch_fails(self) -> None:
        ingress = self.dir / "ingress.pcap"
        mirror = self.dir / "mirror.pcap"
        ingress_frames = [_eth_frame(i) for i in range(10)]
        # Mutate one mirror frame: same length, different bytes ⇒
        # different SHA-256 ⇒ unmatched.
        mirror_frames = list(ingress_frames)
        mirror_frames[3] = _eth_frame(99)
        _write_pcap(ingress, ingress_frames)
        _write_pcap(mirror, mirror_frames)
        v = _mod.compare(ingress, mirror, rate=1, tolerance=None)
        self.assertFalse(v.pass_)
        self.assertEqual(v.unmatched_mirror_frames, 1)
        self.assertTrue(
            any("did not byte-match" in r for r in v.failure_reasons),
            msg=v.failure_reasons,
        )

    def test_vlan_bytes_must_match_exact(self) -> None:
        """Mirror that strips the VLAN tag fails fidelity."""
        ingress = self.dir / "ingress.pcap"
        mirror = self.dir / "mirror.pcap"
        # Ingress: 802.1Q tagged (ethertype 0x8100 + tag + inner 0x0800)
        ingress_frame = bytes.fromhex(
            "0203040506070A0B0C0D0E0F81000064080045000028"
        ) + bytes(20)
        # Mirror: same payload but VLAN stripped (no 0x8100/tag bytes).
        stripped_frame = bytes.fromhex(
            "0203040506070A0B0C0D0E0F0800"
        ) + bytes.fromhex("45000028") + bytes(20)
        _write_pcap(ingress, [ingress_frame])
        _write_pcap(mirror, [stripped_frame])
        v = _mod.compare(ingress, mirror, rate=1, tolerance=None)
        self.assertFalse(v.pass_)
        self.assertEqual(v.unmatched_mirror_frames, 1)

    def test_count_out_of_tolerance_fails(self) -> None:
        ingress = self.dir / "ingress.pcap"
        mirror = self.dir / "mirror.pcap"
        # 100 ingress frames, rate=1 ⇒ expect ~100 mirror frames. If
        # only 50 mirror frames arrive, that's a 50-frame deficit far
        # outside default tolerance (max(2, ceil(0.05*100)) = 5).
        ingress_frames = [_eth_frame(i & 0xFF) for i in range(100)]
        mirror_frames = ingress_frames[:50]
        _write_pcap(ingress, ingress_frames)
        _write_pcap(mirror, mirror_frames)
        v = _mod.compare(ingress, mirror, rate=1, tolerance=None)
        self.assertFalse(v.pass_)
        self.assertTrue(
            any("outside" in r for r in v.failure_reasons),
            msg=v.failure_reasons,
        )

    def test_rate_4_count_within_tolerance(self) -> None:
        ingress = self.dir / "ingress.pcap"
        mirror = self.dir / "mirror.pcap"
        # Per-binding sampling at rate=4: every 4th frame, +/- jitter.
        ingress_frames = [_eth_frame(i & 0xFF) for i in range(80)]
        # 20 mirror frames, all valid copies of distinct ingress frames.
        mirror_frames = [ingress_frames[i] for i in range(0, 80, 4)]
        _write_pcap(ingress, ingress_frames)
        _write_pcap(mirror, mirror_frames)
        v = _mod.compare(ingress, mirror, rate=4, tolerance=None)
        self.assertTrue(v.pass_, msg=v.failure_reasons)
        self.assertEqual(v.matched_count, 20)
        self.assertEqual(v.unmatched_mirror_frames, 0)

    def test_multiplicity_respected(self) -> None:
        """Mirror that emits 3 copies of one ingress frame must show 2
        unmatched (only 1 ingress copy exists)."""
        ingress = self.dir / "ingress.pcap"
        mirror = self.dir / "mirror.pcap"
        ingress_frames = [_eth_frame(7)]
        mirror_frames = [_eth_frame(7)] * 3
        _write_pcap(ingress, ingress_frames)
        _write_pcap(mirror, mirror_frames)
        v = _mod.compare(ingress, mirror, rate=1, tolerance=None)
        self.assertFalse(v.pass_)
        self.assertEqual(v.matched_count, 1)
        self.assertEqual(v.unmatched_mirror_frames, 2)

    def test_empty_pcap_fails(self) -> None:
        ingress = self.dir / "ingress.pcap"
        mirror = self.dir / "mirror.pcap"
        _write_pcap(ingress, [])
        _write_pcap(mirror, [_eth_frame(1)])
        v = _mod.compare(ingress, mirror, rate=1, tolerance=None)
        self.assertFalse(v.pass_)
        self.assertTrue(
            any("ingress pcap contained zero frames" in r for r in v.failure_reasons),
            msg=v.failure_reasons,
        )

    def test_pcapng_magic_rejected(self) -> None:
        ingress = self.dir / "ingress.pcapng"
        mirror = self.dir / "mirror.pcap"
        # pcapng SHB magic = 0x0A0D0D0A (Section Header Block).
        ingress.write_bytes(b"\x0A\x0D\x0D\x0A" + bytes(20))
        _write_pcap(mirror, [_eth_frame(0)])
        with self.assertRaises(SystemExit) as ctx:
            _mod.compare(ingress, mirror, rate=1, tolerance=None)
        self.assertIn("classic pcap", str(ctx.exception))

    def test_big_endian_magic_supported(self) -> None:
        ingress = self.dir / "ingress.pcap"
        mirror = self.dir / "mirror.pcap"
        frames = [_eth_frame(1), _eth_frame(2)]
        # Write big-endian variant: same data, swapped magic + ">" fmt.
        with ingress.open("wb") as fh:
            fh.write(struct.pack(">IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
            for i, frame in enumerate(frames):
                fh.write(struct.pack(">IIII", i, 0, len(frame), len(frame)))
                fh.write(frame)
        _write_pcap(mirror, frames)
        v = _mod.compare(ingress, mirror, rate=1, tolerance=None)
        self.assertTrue(v.pass_, msg=v.failure_reasons)
        self.assertEqual(v.ingress_count, 2)
        self.assertEqual(v.mirror_count, 2)

    def test_verdict_json_shape(self) -> None:
        ingress = self.dir / "ingress.pcap"
        mirror = self.dir / "mirror.pcap"
        frames = [_eth_frame(i) for i in range(5)]
        _write_pcap(ingress, frames)
        _write_pcap(mirror, frames)
        v = _mod.compare(ingress, mirror, rate=1, tolerance=None)
        d = v.to_dict()
        # The runbook's Gate 7 summary.md cross-references these keys;
        # changing them silently is a contract break.
        for key in (
            "pass",
            "ingress_path",
            "mirror_path",
            "ingress_count",
            "mirror_count",
            "matched_count",
            "unmatched_mirror_frames",
            "expected_mirror_min",
            "expected_mirror_max",
            "rate",
            "tolerance",
            "failure_reasons",
            "sample_unmatched_digests",
        ):
            self.assertIn(key, d)
        # JSON round-trips clean.
        json.loads(json.dumps(d))


if __name__ == "__main__":
    unittest.main(verbosity=2)
