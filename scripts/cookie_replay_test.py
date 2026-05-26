#!/usr/bin/env python3
"""Unit tests for scripts/cookie-replay.py.

Exercises the pure packet-builder functions (no raw sockets). The
live raw-socket modes are only reachable inside the loss cluster
fixtures and are validated by the runbook's Gate 3.

Run with:
    python3 scripts/cookie_replay_test.py
"""

from __future__ import annotations

import importlib.util
import io
import json
import socket
import struct
import sys
import tempfile
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
SCRIPT_PATH = HERE / "cookie-replay.py"

_spec = importlib.util.spec_from_file_location("cookie_replay", SCRIPT_PATH)
_mod = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
sys.modules["cookie_replay"] = _mod
_spec.loader.exec_module(_mod)


# ---------------------------------------------------------------------------
# Reference checksum (RFC 1071) — independent of the implementation under
# test so we catch off-by-one or byte-order bugs in _checksum.
# ---------------------------------------------------------------------------


def _ref_checksum(data: bytes) -> int:
    if len(data) % 2:
        data = data + b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += int.from_bytes(data[i : i + 2], "big")
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


class ChecksumTests(unittest.TestCase):
    def test_zero(self) -> None:
        self.assertEqual(_mod._checksum(b""), 0xFFFF)

    def test_matches_reference(self) -> None:
        for payload in (b"\x00", b"abc", b"\x45\x00\x00\x28", b"x" * 31):
            self.assertEqual(_mod._checksum(payload), _ref_checksum(payload), payload)


class Ipv4HeaderTests(unittest.TestCase):
    def test_ipv4_header_checksum_valid(self) -> None:
        hdr = _mod._build_ipv4("10.0.0.1", "10.0.0.2", payload_len=20, ident=0x1234)
        self.assertEqual(len(hdr), 20)
        # An IPv4 header with its own checksum field included must
        # checksum to zero when re-summed.
        self.assertEqual(_ref_checksum(hdr), 0)

    def test_ipv4_total_length_includes_payload(self) -> None:
        hdr = _mod._build_ipv4("1.2.3.4", "5.6.7.8", payload_len=20, ident=1)
        total_len = struct.unpack("!H", hdr[2:4])[0]
        self.assertEqual(total_len, 40)
        # Protocol field is TCP.
        self.assertEqual(hdr[9], socket.IPPROTO_TCP)
        # Src/Dst addrs in the right slots.
        self.assertEqual(socket.inet_ntoa(hdr[12:16]), "1.2.3.4")
        self.assertEqual(socket.inet_ntoa(hdr[16:20]), "5.6.7.8")


class TcpHeaderTests(unittest.TestCase):
    def _verify_tcp_checksum(self, src: str, dst: str, tcp: bytes) -> None:
        pseudo = (
            socket.inet_aton(src)
            + socket.inet_aton(dst)
            + struct.pack("!BBH", 0, socket.IPPROTO_TCP, len(tcp))
        )
        self.assertEqual(_ref_checksum(pseudo + tcp), 0)

    def test_syn_packet_checksum_valid(self) -> None:
        tcp = _mod._build_tcp(
            "10.0.0.1",
            "10.0.0.2",
            sport=44444,
            dport=5201,
            seq=0xDEADBEEF,
            ack=0,
            flags=_mod.TCP_SYN,
        )
        self.assertEqual(len(tcp), 20)
        # data offset = 5 (no opts), reserved = 0
        self.assertEqual(tcp[12] >> 4, 5)
        # Flags byte.
        self.assertEqual(tcp[13], _mod.TCP_SYN)
        self._verify_tcp_checksum("10.0.0.1", "10.0.0.2", tcp)

    def test_ack_packet_carries_ack_number(self) -> None:
        tcp = _mod._build_tcp(
            "10.0.0.1",
            "10.0.0.2",
            sport=44444,
            dport=5201,
            seq=0x11111111,
            ack=0x22222222,
            flags=_mod.TCP_ACK,
        )
        sport, dport, seq, ack, _off_res, flags, _win, _csum, _urg = struct.unpack(
            "!HHLLBBHHH", tcp
        )
        self.assertEqual(sport, 44444)
        self.assertEqual(dport, 5201)
        self.assertEqual(seq, 0x11111111)
        self.assertEqual(ack, 0x22222222)
        self.assertEqual(flags, _mod.TCP_ACK)


class BuildPacketTests(unittest.TestCase):
    def test_packet_length_and_checksum_chain(self) -> None:
        pkt = _mod._build_packet(
            src="10.0.0.1",
            dst="10.0.0.2",
            sport=44444,
            dport=5201,
            seq=0xDEADBEEF,
            ack=0,
            flags=_mod.TCP_SYN,
            ident=0x1234,
        )
        self.assertEqual(len(pkt), 40)
        # IPv4 header re-checksums to zero.
        self.assertEqual(_ref_checksum(pkt[:20]), 0)
        # TCP checksum verified against pseudo-header.
        pseudo = (
            socket.inet_aton("10.0.0.1")
            + socket.inet_aton("10.0.0.2")
            + struct.pack("!BBH", 0, socket.IPPROTO_TCP, 20)
        )
        self.assertEqual(_ref_checksum(pseudo + pkt[20:]), 0)


class TokenSerializationTests(unittest.TestCase):
    def test_token_roundtrip(self) -> None:
        tok = _mod.CookieToken(
            src_ip="10.0.0.1",
            dst_ip="172.16.80.200",
            src_port=44444,
            dst_port=5201,
            cookie_isn=0xABCDEF12,
            client_isn=0x11223344,
            captured_at=1716700000.5,
        )
        body = tok.to_json()
        parsed = _mod.CookieToken.from_json(body)
        self.assertEqual(parsed.src_ip, "10.0.0.1")
        self.assertEqual(parsed.cookie_isn, 0xABCDEF12)
        self.assertEqual(parsed.client_isn, 0x11223344)
        # Stable shape — JSON keys are public contract for failover
        # sub-gate cross-process replay.
        d = json.loads(body)
        for key in (
            "src_ip",
            "dst_ip",
            "src_port",
            "dst_port",
            "cookie_isn",
            "client_isn",
            "captured_at",
        ):
            self.assertIn(key, d)


class ParserTests(unittest.TestCase):
    def test_parse_tcp_round_trip(self) -> None:
        pkt = _mod._build_packet(
            src="10.0.0.1",
            dst="10.0.0.2",
            sport=44444,
            dport=5201,
            seq=0x12345678,
            ack=0x9ABCDEF0,
            flags=_mod.TCP_SYN | _mod.TCP_ACK,
            ident=1,
        )
        parsed = _mod._parse_tcp(pkt)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["src_ip"], "10.0.0.1")
        self.assertEqual(parsed["dst_ip"], "10.0.0.2")
        self.assertEqual(parsed["src_port"], 44444)
        self.assertEqual(parsed["dst_port"], 5201)
        self.assertEqual(parsed["seq"], 0x12345678)
        self.assertEqual(parsed["ack"], 0x9ABCDEF0)
        self.assertEqual(parsed["flags"], _mod.TCP_SYN | _mod.TCP_ACK)

    def test_parse_tcp_rejects_short_buffer(self) -> None:
        self.assertIsNone(_mod._parse_tcp(b"\x45\x00"))

    def test_parse_tcp_rejects_non_tcp(self) -> None:
        # IPv4 header with protocol=17 (UDP).
        hdr = bytearray(_mod._build_ipv4("1.2.3.4", "5.6.7.8", 20, 1))
        hdr[9] = 17
        # Recompute IPv4 header checksum.
        hdr[10:12] = b"\x00\x00"
        csum = _ref_checksum(bytes(hdr))
        hdr[10:12] = struct.pack("!H", csum)
        self.assertIsNone(_mod._parse_tcp(bytes(hdr) + bytes(20)))


class CliTests(unittest.TestCase):
    def test_help_lists_all_modes(self) -> None:
        parser = _mod.build_parser()
        # argparse encodes choices on the --mode action.
        modes = next(
            a.choices for a in parser._actions if a.dest == "mode"
        )
        for required in (
            "challenge",
            "capture-cookie",
            "valid",
            "valid-ack",
            "retransmit-syn",
            "random-ack",
            "budget-exhaust",
            "replay",
        ):
            self.assertIn(required, modes)

    def test_load_token_requires_file(self) -> None:
        parser = _mod.build_parser()
        args = parser.parse_args(["--mode", "valid-ack"])
        with self.assertRaises(SystemExit) as ctx:
            _mod._load_token(args)
        self.assertIn("--token-file", str(ctx.exception))


if __name__ == "__main__":
    unittest.main(verbosity=2)
