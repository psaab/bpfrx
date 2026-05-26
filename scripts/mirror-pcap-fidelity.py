#!/usr/bin/env python3
"""
mirror-pcap-fidelity.py — #1477 port-mirror fidelity checker

Verifies that the userspace dataplane's `forwarding-options port-mirroring`
output preserves the original Ethernet frame byte-for-byte (full L2,
including VLAN tags and IPv4/IPv6 payload). This is the structured
fidelity gate referenced as a follow-up in
docs/pr/1477-final-validation/runbook.md Gate 7 (#1376 port-mirror).

Inputs:

  --ingress  Path to a pcap captured on the ingress interface of the
             firewall (or the host side of that interface). This is the
             "ground truth" frame stream the mirror was supposed to copy.

  --mirror   Path to a pcap captured on the mirror OUTPUT interface
             (Gate 7 captures this as `mirror-output-tcpdump.pcap`).

  --rate     The configured mirror rate (`forwarding-options port-mirroring
             ... input rate N`). Used only to interpret expected counts;
             defaults to 1 (mirror every frame).

  --tolerance  Allowed absolute deviation in matched-frame count between
               ingress/rate and mirror. Defaults to 5% of expected count
               (rounded up), with a floor of 2 frames. Per-binding
               sampling is bursty so an exact match is not required.

  --output   Path to write a machine-readable verdict JSON (matches the
             schema expected by docs/pr/1477-final-validation/runbook.md
             Gate 7 summary.md).

Pass criteria:

  - Every frame in --mirror has an EXACT byte-equal counterpart in
    --ingress (matching by hash over the full L2 frame). Any unmatched
    mirror frame is a fidelity failure (mirror output rewrote bytes,
    stripped VLAN, or invented data).
  - Mirror count is within --tolerance of ingress_count / rate.
  - Both pcaps parsed at least one frame each.

Output:

  - PASS / FAIL on stderr.
  - JSON verdict on stdout (or --output).
  - Exit 0 on PASS, 1 on FAIL.

This script uses only Python stdlib so it runs in the loss cluster
fixtures without extra deps. It supports the classic libpcap file format
(magic 0xa1b2c3d4 + byte-swapped variant); it does NOT parse pcapng
(operator captures with `tcpdump -w` produce classic pcap by default).

Refs: #1477, #1376
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, Optional


# ---------------------------------------------------------------------------
# Classic libpcap reader (RFC pcap, magic 0xa1b2c3d4 or swapped).
# ---------------------------------------------------------------------------

PCAP_MAGIC_LE = 0xA1B2C3D4
PCAP_MAGIC_BE = 0xD4C3B2A1


@dataclass
class PcapHeader:
    byte_order: str           # "<" or ">"
    snaplen: int
    linktype: int


@dataclass
class FrameRecord:
    ts_sec: int
    ts_usec: int
    cap_len: int
    orig_len: int
    payload: bytes            # exactly cap_len bytes

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.payload).hexdigest()


def _read_global_header(fh) -> PcapHeader:
    raw = fh.read(24)
    if len(raw) != 24:
        raise SystemExit(f"FAIL truncated pcap global header at {fh.name}")
    (magic,) = struct.unpack("<I", raw[:4])
    if magic == PCAP_MAGIC_LE:
        byte_order = "<"
    elif magic == PCAP_MAGIC_BE:
        byte_order = ">"
    else:
        raise SystemExit(
            f"FAIL {fh.name}: not a classic pcap (magic=0x{magic:08x}); "
            "this checker does not support pcapng. Use `tcpdump -w` "
            "(default produces classic pcap)."
        )
    _major, _minor, _zone, _ts_accuracy, snaplen, linktype = struct.unpack(
        byte_order + "HHiIII", raw[4:24]
    )
    return PcapHeader(byte_order=byte_order, snaplen=snaplen, linktype=linktype)


def iter_frames(path: Path) -> Iterator[FrameRecord]:
    with path.open("rb") as fh:
        header = _read_global_header(fh)
        record_fmt = header.byte_order + "IIII"
        record_size = struct.calcsize(record_fmt)
        while True:
            raw = fh.read(record_size)
            if not raw:
                return
            if len(raw) != record_size:
                raise SystemExit(
                    f"FAIL {path}: truncated record header "
                    f"(got {len(raw)} bytes, want {record_size})"
                )
            ts_sec, ts_usec, cap_len, orig_len = struct.unpack(record_fmt, raw)
            payload = fh.read(cap_len)
            if len(payload) != cap_len:
                raise SystemExit(
                    f"FAIL {path}: truncated frame payload "
                    f"(got {len(payload)} of {cap_len})"
                )
            yield FrameRecord(
                ts_sec=ts_sec,
                ts_usec=ts_usec,
                cap_len=cap_len,
                orig_len=orig_len,
                payload=payload,
            )


# ---------------------------------------------------------------------------
# Fidelity comparison
# ---------------------------------------------------------------------------


@dataclass
class FidelityVerdict:
    pass_: bool = False
    ingress_path: str = ""
    mirror_path: str = ""
    ingress_count: int = 0
    mirror_count: int = 0
    matched_count: int = 0
    unmatched_mirror_frames: int = 0
    expected_mirror_min: int = 0
    expected_mirror_max: int = 0
    rate: int = 1
    tolerance: int = 0
    failure_reasons: list = field(default_factory=list)
    sample_unmatched_digests: list = field(default_factory=list)

    def to_dict(self) -> dict:
        out = {
            "pass": self.pass_,
            "ingress_path": self.ingress_path,
            "mirror_path": self.mirror_path,
            "ingress_count": self.ingress_count,
            "mirror_count": self.mirror_count,
            "matched_count": self.matched_count,
            "unmatched_mirror_frames": self.unmatched_mirror_frames,
            "expected_mirror_min": self.expected_mirror_min,
            "expected_mirror_max": self.expected_mirror_max,
            "rate": self.rate,
            "tolerance": self.tolerance,
            "failure_reasons": self.failure_reasons,
            "sample_unmatched_digests": self.sample_unmatched_digests,
        }
        return out


def _strip_vlan_for_match(payload: bytes) -> bytes:
    """No-op: byte-equality MUST be exact, including VLAN bytes.

    Kept as a hook in case a future variant of the checker wants to
    allow VLAN-strip on the mirror output. Today, the #1376 plan
    explicitly requires VLAN preservation, so we hash the raw bytes.
    """
    return payload


def compare(
    ingress: Path,
    mirror: Path,
    rate: int,
    tolerance: Optional[int],
) -> FidelityVerdict:
    verdict = FidelityVerdict(
        ingress_path=str(ingress),
        mirror_path=str(mirror),
        rate=rate,
    )

    # Build a multiset of ingress frame digests; mirror frames must each
    # find a match (with multiplicity respected).
    ingress_digests: dict[str, int] = {}
    for frame in iter_frames(ingress):
        digest = hashlib.sha256(_strip_vlan_for_match(frame.payload)).hexdigest()
        ingress_digests[digest] = ingress_digests.get(digest, 0) + 1
        verdict.ingress_count += 1

    unmatched_samples: list[str] = []
    for frame in iter_frames(mirror):
        verdict.mirror_count += 1
        digest = hashlib.sha256(_strip_vlan_for_match(frame.payload)).hexdigest()
        remaining = ingress_digests.get(digest, 0)
        if remaining > 0:
            verdict.matched_count += 1
            if remaining == 1:
                del ingress_digests[digest]
            else:
                ingress_digests[digest] = remaining - 1
        else:
            verdict.unmatched_mirror_frames += 1
            if len(unmatched_samples) < 8:
                unmatched_samples.append(digest)

    verdict.sample_unmatched_digests = unmatched_samples

    if rate <= 0:
        verdict.failure_reasons.append(f"invalid rate {rate}; must be >= 1")
        return verdict

    expected = verdict.ingress_count / rate
    if tolerance is None:
        tolerance = max(2, math.ceil(0.05 * expected))
    verdict.tolerance = tolerance
    verdict.expected_mirror_min = max(0, math.floor(expected - tolerance))
    verdict.expected_mirror_max = math.ceil(expected + tolerance)

    if verdict.ingress_count == 0:
        verdict.failure_reasons.append("ingress pcap contained zero frames")
    if verdict.mirror_count == 0:
        verdict.failure_reasons.append("mirror pcap contained zero frames")
    if verdict.unmatched_mirror_frames > 0:
        verdict.failure_reasons.append(
            f"{verdict.unmatched_mirror_frames} mirror frame(s) did not "
            "byte-match any ingress frame (mirror output rewrote bytes "
            "or invented data)"
        )
    if (
        verdict.mirror_count < verdict.expected_mirror_min
        or verdict.mirror_count > verdict.expected_mirror_max
    ):
        verdict.failure_reasons.append(
            f"mirror_count={verdict.mirror_count} outside "
            f"[{verdict.expected_mirror_min}, {verdict.expected_mirror_max}] "
            f"(ingress={verdict.ingress_count} / rate={rate} +/- "
            f"{tolerance})"
        )

    verdict.pass_ = not verdict.failure_reasons
    return verdict


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="mirror-pcap-fidelity.py",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--ingress", required=True, type=Path)
    p.add_argument("--mirror", required=True, type=Path)
    p.add_argument(
        "--rate",
        type=int,
        default=1,
        help="configured port-mirror rate (default: 1, mirror every frame)",
    )
    p.add_argument(
        "--tolerance",
        type=int,
        default=None,
        help="allowed absolute deviation in mirror count "
        "(default: max(2, ceil(5%% of expected)))",
    )
    p.add_argument(
        "--output",
        type=Path,
        default=None,
        help="write the verdict JSON to this path (default: stdout)",
    )
    return p


def main(argv: list[str]) -> int:
    args = build_parser().parse_args(argv)
    verdict = compare(args.ingress, args.mirror, args.rate, args.tolerance)
    body = json.dumps(verdict.to_dict(), indent=2, sort_keys=True)
    if args.output:
        args.output.write_text(body + "\n", encoding="utf-8")
    else:
        print(body)
    if verdict.pass_:
        print(
            f"PASS mirror fidelity: matched={verdict.matched_count} "
            f"of mirror_count={verdict.mirror_count}; "
            f"ingress_count={verdict.ingress_count} rate={verdict.rate}",
            file=sys.stderr,
        )
        return 0
    for reason in verdict.failure_reasons:
        print(f"FAIL {reason}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
