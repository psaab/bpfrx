#!/usr/bin/env python3
"""#8259: multi-port TCP echo for the mouse-latency probe.

One asyncio server per mouse port. The probe measures round-trip time on a
persistent connection, so the ONLY thing this must not do is add latency of its
own: no logging per message, no per-connection allocation beyond the reader.
"""
import asyncio
import sys

PORTS = [7] + list(range(6200, 6212))


async def handle(reader, writer):
    try:
        while True:
            data = await reader.read(4096)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def main():
    servers = []
    for port in PORTS:
        try:
            servers.append(await asyncio.start_server(handle, "0.0.0.0", port))
        except OSError as exc:
            print(f"port {port}: {exc}", file=sys.stderr, flush=True)
    print(f"echo listening on {len(servers)} ports", flush=True)
    await asyncio.gather(*(s.serve_forever() for s in servers))


asyncio.run(main())
