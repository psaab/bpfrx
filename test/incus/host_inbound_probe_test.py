"""Hermetic self-test for host_inbound_probe.py (#6936 follow-up).

No cluster, no incus, no off-box network. Runs in `make test-host-inbound-lib`,
which previously only ran `py_compile` on the prober — a SYNTAX check. An
unresolvable import, a renamed exception class, or a changed output format all
pass py_compile and fail later on the cluster, where the shell side scores the
missing line as BLIND rather than as a broken prober.

Two properties are worth more than the rest:

1. **The OPEN / REFUSED / TIMEOUT / ERROR mapping.** It is the discriminator the
   whole smoke rests on: xpfd binds its listeners on 127.0.0.1 only, so an
   ADMITTED probe of a non-listening firewall address returns an RST while a
   host-inbound DROP returns nothing. Collapsing REFUSED into TIMEOUT would make
   every negative cell in the smoke unfalsifiable, and the shell lib cannot see
   that happen — it only ever sees the word the prober printed.

2. **The output FORMAT.** host-inbound-lib.sh parses positionally
   (`$1 == "PROBE" && $2 == target && $3 == port` -> `$4`). The two sides must
   AGREE, and neither can see the other: reordering a field or dropping the
   PROBE prefix makes every cell classify as BLIND, and BLIND on an ADMIT cell
   is a loud failure but BLIND is also what an unreachable prober looks like.
   The format assertions below are pinned against the awk field numbers the
   shell actually uses, not against a prose description of them.
"""

import errno
import socket
import subprocess
import sys
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import host_inbound_probe as probe_mod  # noqa: E402


class FakeSocket:
    """Stands in for socket.socket so the mapping can be driven without a network."""

    def __init__(self, raise_exc=None):
        self._raise = raise_exc
        self.closed = False
        self.timeout = None

    def settimeout(self, t):
        self.timeout = t

    def connect(self, _addr):
        if self._raise is not None:
            raise self._raise

    def close(self):
        self.closed = True


class ResultMappingTests(unittest.TestCase):
    """Each exception class must map to its OWN word."""

    def _probe_with(self, raise_exc):
        made = []

        def fake_socket(*_a, **_kw):
            s = FakeSocket(raise_exc)
            made.append(s)
            return s

        orig = socket.socket
        socket.socket = fake_socket
        try:
            result = probe_mod.probe("192.0.2.1", 22)
        finally:
            socket.socket = orig
        self.assertTrue(made, "probe() never created a socket")
        self.assertTrue(made[0].closed, "probe() leaked a socket (no close in finally)")
        return result

    def test_success_is_open(self):
        self.assertEqual(self._probe_with(None), "OPEN")

    def test_refused_is_refused(self):
        # The load-bearing one: an RST means host-inbound ADMITTED the packet and
        # the stack answered. Folding it into TIMEOUT makes every negative cell
        # in the smoke unfalsifiable.
        self.assertEqual(self._probe_with(ConnectionRefusedError()), "REFUSED")

    def test_timeout_is_timeout(self):
        self.assertEqual(self._probe_with(socket.timeout()), "TIMEOUT")

    def test_host_unreachable_is_error_not_timeout(self):
        # An ICMP unreachable means the packet never reached a host-inbound
        # decision. Scoring it as TIMEOUT would let the shell promote it to a
        # DENY, certifying a deny on a packet that never got a verdict.
        exc = OSError(errno.EHOSTUNREACH, "No route to host")
        self.assertEqual(self._probe_with(exc), "ERROR")

    def test_network_unreachable_is_error(self):
        exc = OSError(errno.ENETUNREACH, "Network is unreachable")
        self.assertEqual(self._probe_with(exc), "ERROR")

    def test_refused_is_not_swallowed_by_the_oserror_arm(self):
        # ConnectionRefusedError IS an OSError subclass, so an arm ordering that
        # catches OSError first silently turns every REFUSED into ERROR — and
        # ERROR reads as UNREACHED on the shell side, which fails an ADMIT cell.
        # This is a real ordering hazard, not a hypothetical one.
        self.assertNotEqual(self._probe_with(ConnectionRefusedError()), "ERROR")


class RealLoopbackTests(unittest.TestCase):
    """End-to-end against 127.0.0.1 — hermetic and fast, no off-box traffic."""

    def test_closed_local_port_is_refused(self):
        # Bind to get a free port, then close it: connecting now gets an RST.
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        self.assertEqual(probe_mod.probe("127.0.0.1", port), "REFUSED")

    def test_listening_local_port_is_open(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        conns = []

        def _accept():
            try:
                c, _ = srv.accept()
                conns.append(c)
            except OSError:
                pass

        accepted = threading.Thread(target=_accept, daemon=True)
        accepted.start()
        try:
            self.assertEqual(probe_mod.probe("127.0.0.1", port), "OPEN")
        finally:
            accepted.join(timeout=5)
            for c in conns:
                c.close()
            srv.close()

    def test_unresolvable_name_is_error(self):
        # getaddrinfo failure must be ERROR, never TIMEOUT: the shell must not be
        # able to read a broken target as a firewall drop.
        self.assertEqual(
            probe_mod.probe("host.invalid.7157.example.", 22), "ERROR"
        )


class OutputFormatContractTests(unittest.TestCase):
    """The cross-language contract with host-inbound-lib.sh.

    hi_classify_probe does:
        awk '$1 == "PROBE" && $2 == t && $3 == p { print $4; exit }'
    so the field POSITIONS are the interface. Asserting the agreement rather
    than pinning one side to a literal is the point: if these ever diverge, the
    shell classifies every cell as BLIND and the smoke fails in a way that looks
    like an unreachable prober.
    """

    def _run(self, *args):
        out = subprocess.run(
            [sys.executable, str(Path(__file__).resolve().parent / "host_inbound_probe.py"), *args],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        self.assertEqual(out.returncode, 0, f"prober exited {out.returncode}: {out.stderr}")
        return [ln for ln in out.stdout.splitlines() if ln.strip()]

    def test_line_shape_matches_the_awk_field_positions(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        lines = self._run(f"127.0.0.1|{port}")
        self.assertEqual(len(lines), 1)
        f = lines[0].split()
        self.assertEqual(f[0], "PROBE", "field 1 must be the literal PROBE ($1 in the awk)")
        self.assertEqual(f[1], "127.0.0.1", "field 2 must be the target ($2 in the awk)")
        self.assertEqual(f[2], str(port), "field 3 must be the port ($3 in the awk)")
        self.assertEqual(f[3], "REFUSED", "field 4 must be the result word ($4 in the awk)")
        self.assertGreaterEqual(len(f), 5, "field 5 (elapsed) is part of the documented shape")

    def test_ipv6_target_keeps_the_field_positions(self):
        # An IPv6 literal is full of colons, which is why the argument separator
        # is a pipe. If the host ever got split across fields, $3 would stop
        # being the port and every v6 cell would classify BLIND.
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.bind(("::1", 0))
        port = s.getsockname()[1]
        s.close()
        lines = self._run(f"::1|{port}")
        f = lines[0].split()
        self.assertEqual(f[0], "PROBE")
        self.assertEqual(f[1], "::1")
        self.assertEqual(f[2], str(port))
        self.assertEqual(f[3], "REFUSED")

    def test_one_line_per_cell_even_for_a_malformed_spec(self):
        # A cell must never VANISH: a missing line is what the shell scores as
        # BLIND, and BLIND on a DENY cell is (correctly) a failure — but a
        # prober that silently drops cells turns a real reading into that same
        # failure and sends the reader after the wrong defect.
        lines = self._run("not-a-spec", "127.0.0.1|1", "also|bad|spec")
        self.assertEqual(len(lines), 3, f"expected one line per cell, got: {lines}")
        for ln in lines:
            self.assertEqual(ln.split()[0], "PROBE")

    def test_no_cells_produces_no_output_and_exits_clean(self):
        self.assertEqual(self._run(), [])


if __name__ == "__main__":
    unittest.main()
