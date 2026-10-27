#!/usr/bin/env python3
"""Local SOCKS5 UDP ASSOCIATE benchmark with payload verification.

Starts a standalone Relay with a SOCKS5 Both rule, performs the TCP control
handshake and UDP ASSOCIATE, then sends verified UDP datagrams to an echo
target. It is a loopback smoke benchmark, not a WAN/client/SLA result.
"""
import argparse
import asyncio
import hashlib
import json
import platform
import signal
import socket
import statistics
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

FILLER = bytes(i % 251 for i in range(65536))


class UdpEcho(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, payload, peer):
        self.transport.sendto(payload, peer)


def packet(destination, payload):
    host, port = destination
    address = socket.inet_aton(host)
    return b"\0\0\0\1" + address + int(port).to_bytes(2, "big") + payload


def parse_bind(reply):
    if len(reply) != 10 or reply[0] != 5 or reply[1] != 0 or reply[3] != 1:
        raise RuntimeError(f"unexpected UDP ASSOCIATE reply: {reply!r}")
    return f"{reply[4]}.{reply[5]}.{reply[6]}.{reply[7]}", int.from_bytes(reply[8:10], "big")


async def run(args):
    binary = args.binary.resolve()
    if not binary.is_file():
        raise RuntimeError("build the release binary before benchmarking")
    loop = asyncio.get_running_loop()
    echo, _ = await loop.create_datagram_endpoint(UdpEcho, local_addr=("127.0.0.1", 0))
    target = echo.get_extra_info("sockname")
    with tempfile.TemporaryDirectory(prefix="relay-socks5-udp-") as scratch:
        scratch = Path(scratch)
        reserve = socket.socket()
        reserve.bind(("127.0.0.1", 0))
        port = reserve.getsockname()[1]
        reserve.close()
        config = {
            "api_version": 1,
            "node_id": "socks5-udp-benchmark",
            "revision": 1,
            "rules": [{
                "id": "socks5-udp",
                "tenant_id": "default",
                "owner_id": "admin",
                "name": "SOCKS5 UDP benchmark",
                "listen": f"127.0.0.1:{port}",
                "protocol": "both",
                "inbound_socks5": {
                    "username": None,
                    "password": None,
                    "allow_private_destinations": True,
                },
                "targets": [],
                "meter_epoch": "socks5-udp-run",
                "quota_bytes": None,
                "expires_at_ms": None,
                "rate_bytes_per_sec": None,
                "max_connections": 128,
                "udp_max_sessions": 128,
            }],
        }
        (scratch / "config.json").write_text(json.dumps(config))
        with (scratch / "engine.log").open("wb") as log:
            process = await asyncio.create_subprocess_exec(
                str(binary), "standalone", "--config", str(scratch / "config.json"),
                "--database", str(scratch / "agent.db"), stdout=log, stderr=asyncio.subprocess.STDOUT)
            try:
                until = time.monotonic() + 10
                while True:
                    if process.returncode is not None:
                        raise RuntimeError("relay exited during startup")
                    try:
                        control_reader, control_writer = await asyncio.open_connection("127.0.0.1", port)
                        break
                    except OSError:
                        if time.monotonic() > until:
                            raise RuntimeError("relay listener not ready")
                        await asyncio.sleep(.05)
                control_writer.write(b"\x05\x01\x00")
                await control_writer.drain()
                if await control_reader.readexactly(2) != b"\x05\x00":
                    raise RuntimeError("SOCKS5 greeting rejected")
                control_writer.write(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
                await control_writer.drain()
                relay = parse_bind(await control_reader.readexactly(10))
                client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                client.setblocking(False)
                payload_bytes = args.payload
                started = time.perf_counter()
                latencies = []
                received = 0
                sequence = 0
                while sequence < args.packets:
                    batch = min(args.window, args.packets - sequence)
                    batch_start = time.perf_counter()
                    for _ in range(batch):
                        payload = sequence.to_bytes(4, "big") + FILLER[: max(0, payload_bytes - 4)]
                        sequence += 1
                        await loop.sock_sendto(client, packet(target, payload), relay)
                    for _ in range(batch):
                        reply = await asyncio.wait_for(loop.sock_recv(client, payload_bytes + 32), 2)
                        if len(reply) < 10 or reply[3] != 1:
                            raise RuntimeError("invalid SOCKS5 UDP reply")
                        body = reply[10:]
                        if len(body) != payload_bytes or body[4:] != FILLER[: payload_bytes - 4]:
                            raise RuntimeError("SOCKS5 UDP payload mismatch")
                        received += 1
                    latencies.append((time.perf_counter() - batch_start) * 1000 / batch)
                elapsed = time.perf_counter() - started
                ordered = sorted(latencies)
                client.close()
                control_writer.close()
                await control_writer.wait_closed()
            finally:
                if process.returncode is None:
                    process.send_signal(signal.SIGTERM)
                    try:
                        await asyncio.wait_for(process.wait(), 10)
                    except TimeoutError:
                        process.kill()
                        await process.wait()
                echo.close()
            if process.returncode != 0:
                raise RuntimeError(f"relay failed: {(scratch / 'engine.log').read_text()}")
            return {
                "at_utc": datetime.now(timezone.utc).isoformat(),
                "platform": platform.platform(),
                "machine": platform.machine(),
                "python": platform.python_version(),
                "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                "scope": "local loopback SOCKS5 UDP ASSOCIATE; verified payloads; no WAN/TLS/real client",
                "packets": args.packets,
                "payload_bytes": payload_bytes,
                "window": args.window,
                "received": received,
                "lost": args.packets - received,
                "seconds": elapsed,
                "goodput_mbps": args.packets * payload_bytes * 8 / elapsed / 1_000_000,
                "batch_rtt_p50_ms": statistics.median(latencies),
                "batch_rtt_p95_ms": ordered[max(0, int(len(ordered) * .95) - 1)],
                "relay": f"{relay[0]}:{relay[1]}",
            }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=Path("target/release/relay"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--packets", type=int, default=1000)
    parser.add_argument("--payload", type=int, default=1200)
    parser.add_argument("--window", type=int, default=32)
    args = parser.parse_args()
    if min(args.packets, args.payload, args.window) < 1:
        parser.error("all workload sizes must be positive")
    report = asyncio.run(run(args))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
