#!/usr/bin/env python3
"""
cookie-replay.py — #1477 SYN-cookie validation helper

Drives the six Gate-3 sub-gates of the #1477 final-validation runbook
(docs/pr/1477-final-validation/runbook.md):

  challenge          Send a SYN flood and capture one SYN-ACK reply with
                     the encoded ISN (the "cookie"). The captured cookie
                     is written to --token-file so later modes can replay
                     it without re-deriving the secret.

  valid-ack          Replay the captured cookie as a valid ACK (ISN+1).
                     Expectation: dataplane emits a RST and does NOT
                     install a session.

  retransmit-syn     After a successful valid-ack, send the original SYN
                     again from the same tuple. Expectation: dataplane
                     consumes the single-use SynCookieBypass and admits
                     the SYN into the normal policy/NAT/session path.

  random-ack         Send N ACKs with random ISNs from random source
                     ports against the same target. Expectation:
                     dataplane drops them and increments
                     syn_cookie_ack_invalid; no session installed.

  budget-exhaust     Send a fast SYN burst above the per-binding reply
                     budget. Expectation: syn_cookie_reply_budget_drops
                     advances and forwarding TX is unaffected.

  capture-cookie     Same as challenge but emits only the token line
                     (no flood); used by failover sub-gate so we hold a
                     cookie minted on fw0 then replay it on fw1.

  replay             Replay a previously captured token (from
                     --token-file) as a valid ACK against the current
                     primary. Used by failover sub-gate after force-fail
                     to fw1.

This script is hot-path-free — it runs inside a test container
(loss:cluster-userspace-host). It does NOT depend on scapy; it uses
raw sockets + struct.pack so it works on the minimal Debian image
used by the loss cluster fixtures.

The cookie ISN layout (from docs/pr/1373-retire-ebpf-dataplane/
plan-1374-syn-cookies.md):

    [5 bits epoch] [3 bits MSS index] [24 bits MAC]

This helper does NOT mint cookies — it captures the SYN-ACK ISN as an
opaque token and replays the matching ACK (ISN+1). All cookie
derivation, validation, and counter accounting happens in the dataplane.

Counter names (per pkg/dataplane/userspace/protocol.go):
  syn_cookie_challenges          challenge selected for this SYN
  syn_cookie_syn_ack_sent        SYN-ACK reply sent
  syn_cookie_ack_rst_sent        RST sent for validated cookie ACK
  syn_cookie_ack_valid           validated cookie ACK observed
  syn_cookie_ack_invalid         invalid cookie ACK dropped
  syn_cookie_bypass              single-use bypass consumed
  syn_cookie_reply_budget_drops  flood SYN dropped (no reply frame)
  syn_cookie_secret_unavailable  fail-closed (no published secret)

Required privileges: CAP_NET_RAW (raw sockets). The cluster-userspace-host
container runs as root inside an incus VM so this is fine; on a bare
shell run as root.

Refs: #1477, #1374
"""

from __future__ import annotations

import argparse
import errno
import json
import os
import random
import select
import socket
import struct
import sys
import time
from dataclasses import asdict, dataclass
from typing import Optional


# ---------------------------------------------------------------------------
# Packet builders — IPv4 + TCP. Hand-rolled struct.pack so the script does
# not depend on scapy or any non-stdlib package.
# ---------------------------------------------------------------------------

IP_HEADER_LEN = 20
TCP_HEADER_LEN = 20
PROTO_TCP = socket.IPPROTO_TCP

TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10
TCP_URG = 0x20


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data = data + b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return (~total) & 0xFFFF


def _build_ipv4(src: str, dst: str, payload_len: int, ident: int) -> bytes:
    total_len = IP_HEADER_LEN + payload_len
    ver_ihl = (4 << 4) | (IP_HEADER_LEN // 4)
    src_b = socket.inet_aton(src)
    dst_b = socket.inet_aton(dst)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        ver_ihl,
        0,                # DSCP/ECN
        total_len,
        ident & 0xFFFF,
        0,                # flags/frag
        64,               # TTL
        PROTO_TCP,
        0,                # checksum placeholder
        src_b,
        dst_b,
    )
    csum = _checksum(header)
    return header[:10] + struct.pack("!H", csum) + header[12:]


def _build_tcp(
    src: str,
    dst: str,
    sport: int,
    dport: int,
    seq: int,
    ack: int,
    flags: int,
    window: int = 64240,
) -> bytes:
    # Data offset = 5 (no options).
    off_reserved = (5 << 4) | 0
    tcp = struct.pack(
        "!HHLLBBHHH",
        sport,
        dport,
        seq & 0xFFFFFFFF,
        ack & 0xFFFFFFFF,
        off_reserved,
        flags,
        window,
        0,                # checksum placeholder
        0,                # urgent ptr
    )
    pseudo = (
        socket.inet_aton(src)
        + socket.inet_aton(dst)
        + struct.pack("!BBH", 0, PROTO_TCP, len(tcp))
    )
    csum = _checksum(pseudo + tcp)
    return tcp[:16] + struct.pack("!H", csum) + tcp[18:]


def _build_packet(
    src: str,
    dst: str,
    sport: int,
    dport: int,
    seq: int,
    ack: int,
    flags: int,
    ident: int,
) -> bytes:
    tcp = _build_tcp(src, dst, sport, dport, seq, ack, flags)
    ip = _build_ipv4(src, dst, len(tcp), ident)
    return ip + tcp


# ---------------------------------------------------------------------------
# Token (captured cookie) representation. Persists across processes via JSON
# so the failover sub-gate can capture on fw0 and replay on fw1.
# ---------------------------------------------------------------------------


@dataclass
class CookieToken:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    cookie_isn: int      # SYN-ACK ISN as observed off the wire
    client_isn: int      # the SYN ISN we sent (so retransmit-syn reuses it)
    captured_at: float   # wall-clock seconds

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2, sort_keys=True)

    @classmethod
    def from_json(cls, text: str) -> "CookieToken":
        return cls(**json.loads(text))


# ---------------------------------------------------------------------------
# Raw-socket helpers
# ---------------------------------------------------------------------------


def _open_send_socket() -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    return sock


def _open_recv_socket() -> socket.socket:
    # Receive all TCP frames; we filter in software because we control
    # source ports and target.
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    sock.setblocking(False)
    return sock


def _parse_tcp(buf: bytes) -> Optional[dict]:
    """Parse an IPv4+TCP frame off a raw IPPROTO_TCP socket.

    Returns a dict with src/dst IP, ports, seq, ack, flags — or None
    if the frame isn't parseable as IPv4+TCP.
    """
    if len(buf) < IP_HEADER_LEN + TCP_HEADER_LEN:
        return None
    ver_ihl = buf[0]
    if (ver_ihl >> 4) != 4:
        return None
    ihl = (ver_ihl & 0x0F) * 4
    if len(buf) < ihl + TCP_HEADER_LEN:
        return None
    if buf[9] != PROTO_TCP:
        return None
    src = socket.inet_ntoa(buf[12:16])
    dst = socket.inet_ntoa(buf[16:20])
    tcp = buf[ihl : ihl + TCP_HEADER_LEN]
    sport, dport, seq, ack, off_res, flags, _win, _csum, _urg = struct.unpack(
        "!HHLLBBHHH", tcp
    )
    return {
        "src_ip": src,
        "dst_ip": dst,
        "src_port": sport,
        "dst_port": dport,
        "seq": seq,
        "ack": ack,
        "flags": flags,
        "data_off_words": off_res >> 4,
    }


def _await_synack(
    rsock: socket.socket,
    expect_src_ip: str,
    expect_dst_ip: str,
    expect_dst_port: int,
    timeout_s: float,
) -> Optional[dict]:
    """Wait for a SYN-ACK whose tuple matches the SYN we just sent.

    The dataplane's cookie reply has src/dst swapped relative to our SYN:
    the firewall stamps the captured ISN onto its SYN-ACK that goes
    BACK to us (the client). So a matching SYN-ACK has:
        pkt.src_ip == expect_dst_ip   (the server)
        pkt.dst_ip == expect_src_ip   (us)
        pkt.src_port == <target port> (we sent dport=expect_dst_port)
        flags == SYN|ACK
    """
    end = time.monotonic() + timeout_s
    while time.monotonic() < end:
        remaining = end - time.monotonic()
        if remaining <= 0:
            return None
        try:
            r, _, _ = select.select([rsock], [], [], min(remaining, 0.25))
        except InterruptedError:
            continue
        if not r:
            continue
        try:
            buf, _ = rsock.recvfrom(65535)
        except OSError as ex:
            if ex.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                continue
            raise
        pkt = _parse_tcp(buf)
        if pkt is None:
            continue
        if (
            pkt["src_ip"] != expect_dst_ip
            or pkt["dst_ip"] != expect_src_ip
            or pkt["src_port"] != expect_dst_port
        ):
            continue
        if (pkt["flags"] & (TCP_SYN | TCP_ACK)) != (TCP_SYN | TCP_ACK):
            continue
        return pkt
    return None


# ---------------------------------------------------------------------------
# Mode implementations
# ---------------------------------------------------------------------------


def _pick_source_ip(default: Optional[str]) -> str:
    if default:
        return default
    env = os.environ.get("COOKIE_REPLAY_SRC_IP")
    if env:
        return env
    # Fall back to the cluster-userspace-host's LAN IP (per CLAUDE.md
    # topology, 172.16.50.x is the WAN side; the host is 10.0.x or
    # configured upstream). The operator can override via --src.
    return "172.16.50.100"


def _flood_until_synack(
    args: argparse.Namespace,
    rsock: socket.socket,
    ssock: socket.socket,
    src_ip: str,
    src_port: int,
    client_isn: int,
) -> dict:
    """Send up to args.flood SYNs (1 by default) and capture one SYN-ACK."""
    pkt = _build_packet(
        src=src_ip,
        dst=args.target,
        sport=src_port,
        dport=args.port,
        seq=client_isn,
        ack=0,
        flags=TCP_SYN,
        ident=random.randint(0, 0xFFFF),
    )
    sent = 0
    deadline = time.monotonic() + args.timeout
    while time.monotonic() < deadline:
        ssock.sendto(pkt, (args.target, 0))
        sent += 1
        if sent >= args.flood:
            break
        # Tiny pacing to give the dataplane a chance to issue the
        # SYN-ACK before we burst more.
        time.sleep(0.005)
    captured = _await_synack(
        rsock,
        expect_src_ip=src_ip,
        expect_dst_ip=args.target,
        expect_dst_port=args.port,
        timeout_s=max(0.0, deadline - time.monotonic()),
    )
    if captured is None:
        raise SystemExit(
            f"FAIL no SYN-ACK observed within {args.timeout:.1f}s "
            f"after {sent} SYN(s) to {args.target}:{args.port}"
        )
    captured["sent_syns"] = sent
    return captured


def cmd_capture(args: argparse.Namespace) -> int:
    """challenge / capture-cookie — provoke and capture ONE cookie."""
    src_ip = _pick_source_ip(args.src)
    src_port = args.src_port or random.randint(20000, 60000)
    client_isn = random.randint(1, 0x7FFFFFFF)

    ssock = _open_send_socket()
    rsock = _open_recv_socket()
    try:
        synack = _flood_until_synack(args, rsock, ssock, src_ip, src_port, client_isn)
    finally:
        ssock.close()
        rsock.close()

    token = CookieToken(
        src_ip=src_ip,
        dst_ip=args.target,
        src_port=src_port,
        dst_port=args.port,
        cookie_isn=synack["seq"],
        client_isn=client_isn,
        captured_at=time.time(),
    )
    if args.token_file:
        with open(args.token_file, "w", encoding="utf-8") as fh:
            fh.write(token.to_json())
    print(token.to_json())
    return 0


def cmd_valid_ack(args: argparse.Namespace) -> int:
    """valid-ack — replay the captured SYN-ACK as an ACK (ISN+1).

    Dataplane expectation: emit RST, do not install session.
    """
    token = _load_token(args)
    ssock = _open_send_socket()
    try:
        ack_pkt = _build_packet(
            src=token.src_ip,
            dst=token.dst_ip,
            sport=token.src_port,
            dport=token.dst_port,
            seq=token.client_isn + 1,
            ack=token.cookie_isn + 1,
            flags=TCP_ACK,
            ident=random.randint(0, 0xFFFF),
        )
        for _ in range(args.count):
            ssock.sendto(ack_pkt, (token.dst_ip, 0))
    finally:
        ssock.close()
    print(
        f"OK valid-ack: replayed cookie ISN=0x{token.cookie_isn:08x} "
        f"x{args.count} from {token.src_ip}:{token.src_port} -> "
        f"{token.dst_ip}:{token.dst_port}"
    )
    return 0


def cmd_retransmit_syn(args: argparse.Namespace) -> int:
    """retransmit-syn — replay the original SYN from the validated tuple.

    Dataplane expectation: consume the single-use SynCookieBypass and
    admit into normal policy/NAT/session path; subsequent SYNs from the
    same tuple do NOT bypass.
    """
    token = _load_token(args)
    ssock = _open_send_socket()
    try:
        syn_pkt = _build_packet(
            src=token.src_ip,
            dst=token.dst_ip,
            sport=token.src_port,
            dport=token.dst_port,
            seq=token.client_isn,
            ack=0,
            flags=TCP_SYN,
            ident=random.randint(0, 0xFFFF),
        )
        ssock.sendto(syn_pkt, (token.dst_ip, 0))
    finally:
        ssock.close()
    print(
        f"OK retransmit-syn: replayed SYN seq=0x{token.client_isn:08x} "
        f"from {token.src_ip}:{token.src_port} -> "
        f"{token.dst_ip}:{token.dst_port}"
    )
    return 0


def cmd_random_ack(args: argparse.Namespace) -> int:
    """random-ack — flood random-ISN ACKs from random source ports.

    Dataplane expectation: drop, advance syn_cookie_ack_invalid,
    install nothing.
    """
    src_ip = _pick_source_ip(args.src)
    ssock = _open_send_socket()
    sent = 0
    try:
        for _ in range(args.count):
            sport = random.randint(20000, 60000)
            seq = random.randint(1, 0xFFFFFFFF)
            ack = random.randint(1, 0xFFFFFFFF)
            pkt = _build_packet(
                src=src_ip,
                dst=args.target,
                sport=sport,
                dport=args.port,
                seq=seq,
                ack=ack,
                flags=TCP_ACK,
                ident=random.randint(0, 0xFFFF),
            )
            ssock.sendto(pkt, (args.target, 0))
            sent += 1
    finally:
        ssock.close()
    print(f"OK random-ack: sent {sent} random ACKs to {args.target}:{args.port}")
    return 0


def cmd_budget_exhaust(args: argparse.Namespace) -> int:
    """budget-exhaust — high-rate SYN flood from random source ports.

    Dataplane expectation: per-binding reply budget exhausts and
    syn_cookie_reply_budget_drops advances; primary forwarding TX
    survives (separately validated by re-running Gate 1).
    """
    src_ip = _pick_source_ip(args.src)
    ssock = _open_send_socket()
    sent = 0
    deadline = time.monotonic() + args.duration
    try:
        while time.monotonic() < deadline:
            sport = random.randint(20000, 60000)
            seq = random.randint(1, 0x7FFFFFFF)
            pkt = _build_packet(
                src=src_ip,
                dst=args.target,
                sport=sport,
                dport=args.port,
                seq=seq,
                ack=0,
                flags=TCP_SYN,
                ident=random.randint(0, 0xFFFF),
            )
            ssock.sendto(pkt, (args.target, 0))
            sent += 1
    finally:
        ssock.close()
    print(
        f"OK budget-exhaust: sent {sent} SYNs in {args.duration:.1f}s "
        f"to {args.target}:{args.port}"
    )
    return 0


def cmd_replay(args: argparse.Namespace) -> int:
    """replay — replay a previously captured token as a valid ACK.

    Used by the failover sub-gate after primary moves from fw0 to fw1.
    """
    return cmd_valid_ack(args)


def _load_token(args: argparse.Namespace) -> CookieToken:
    if not args.token_file or not os.path.exists(args.token_file):
        raise SystemExit(
            "FAIL --token-file required for valid-ack / retransmit-syn / replay; "
            "run `cookie-replay.py --mode capture-cookie --token-file ...` first"
        )
    with open(args.token_file, "r", encoding="utf-8") as fh:
        return CookieToken.from_json(fh.read())


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cookie-replay.py",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--mode",
        required=True,
        choices=[
            "challenge",
            "capture-cookie",
            "valid",
            "valid-ack",
            "retransmit-syn",
            "random-ack",
            "budget-exhaust",
            "replay",
        ],
        help="sub-gate to exercise",
    )
    parser.add_argument(
        "--target",
        default=os.environ.get("COOKIE_REPLAY_TARGET", "172.16.80.200"),
        help="destination IPv4 (default: %(default)s; runbook target)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("COOKIE_REPLAY_PORT", "5201")),
        help="destination TCP port (default: %(default)s)",
    )
    parser.add_argument(
        "--src",
        default=None,
        help="source IPv4 (default: $COOKIE_REPLAY_SRC_IP or 172.16.50.100)",
    )
    parser.add_argument(
        "--src-port",
        type=int,
        default=None,
        help="source TCP port (default: random 20000-60000)",
    )
    parser.add_argument(
        "--flood",
        type=int,
        default=1,
        help="number of SYNs to send while waiting for SYN-ACK (default: 1; "
        "increase if the daemon's SYN-flood attack-threshold is high)",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=1,
        help="number of frames to send for valid-ack/random-ack modes "
        "(default: 1)",
    )
    parser.add_argument(
        "--duration",
        type=float,
        default=2.0,
        help="seconds to flood for budget-exhaust mode (default: %(default)s)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=2.0,
        help="seconds to wait for a SYN-ACK in capture modes "
        "(default: %(default)s)",
    )
    parser.add_argument(
        "--token-file",
        default=None,
        help="path to persist (capture) or load (replay) the captured "
        "cookie token JSON",
    )
    return parser


def main(argv: list[str]) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    random.seed()

    mode = args.mode
    if mode in ("challenge", "capture-cookie"):
        return cmd_capture(args)
    if mode in ("valid", "valid-ack"):
        return cmd_valid_ack(args)
    if mode == "retransmit-syn":
        return cmd_retransmit_syn(args)
    if mode == "random-ack":
        return cmd_random_ack(args)
    if mode == "budget-exhaust":
        return cmd_budget_exhaust(args)
    if mode == "replay":
        return cmd_replay(args)
    parser.error(f"unknown mode {mode}")
    return 2  # pragma: no cover — argparse exits before this


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
