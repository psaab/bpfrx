#!/usr/bin/env python3
"""TCP host-inbound prober for test/incus/test-host-inbound.sh (#6936).

Runs ON the LAN prober container, not on the dev box. Each argument is one
cell, spelled ``host|port`` (a pipe, because an IPv6 literal is full of
colons). For every cell it prints exactly one line:

    PROBE <host> <port> <OPEN|REFUSED|TIMEOUT|ERROR> <elapsed-seconds>

The four result words are the RAW observation, not a verdict. Deciding what
they mean is host-inbound-lib.sh's job (``hi_classify_probe``), and it is kept
there because that is the half a hermetic selftest can drive.

The distinction that matters is REFUSED vs TIMEOUT. xpfd binds its own
listeners on 127.0.0.1 only, so a probe of a non-listening port on a
firewall-local address comes back as an RST *if host-inbound admitted it* and
as nothing at all if host-inbound dropped it. Collapsing those two -- which is
what a bare ``nc -z`` exit status does -- would make every negative cell in the
smoke unfalsifiable.

One line is printed per cell even on an unexpected exception, so a cell can
never silently vanish from the matrix: a missing line is what the shell side
scores as BLIND.
"""

import socket
import sys
import time

TIMEOUT = float(__import__("os").environ.get("HI_PROBE_TIMEOUT", "3"))


def probe(host: str, port: int) -> str:
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except OSError:
        return "ERROR"
    family, socktype, proto, _, sockaddr = infos[0]
    s = socket.socket(family, socktype, proto)
    s.settimeout(TIMEOUT)
    try:
        s.connect(sockaddr)
        return "OPEN"
    except ConnectionRefusedError:
        return "REFUSED"
    except socket.timeout:
        return "TIMEOUT"
    except OSError:
        # EHOSTUNREACH / ENETUNREACH / EACCES (an ICMP admin-prohibited
        # translated by the stack). The packet never reached a host-inbound
        # decision, so this must NOT read as a deny.
        return "ERROR"
    finally:
        s.close()


def main(argv: list) -> int:
    for spec in argv:
        host, _, port = spec.rpartition("|")
        if not host or not port.isdigit():
            print(f"PROBE {spec} - ERROR 0.00", flush=True)
            continue
        started = time.monotonic()
        try:
            result = probe(host, int(port))
        except Exception:  # noqa: BLE001 - a cell must never vanish
            result = "ERROR"
        print(
            f"PROBE {host} {port} {result} {time.monotonic() - started:.2f}",
            flush=True,
        )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
