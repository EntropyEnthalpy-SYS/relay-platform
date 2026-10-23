#!/usr/bin/env python3
"""Reproducible local smoke benchmark. Every transferred byte is verified.

This measures local loopback plus the same Python echo service. It is not a
multi-machine capacity test, a Realm comparison, or a production performance SLA.
"""
import argparse
import asyncio
import hashlib
import json
import os
import platform
import signal
import socket
import statistics
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

BLOCK = bytes(i % 251 for i in range(65536))


async def echo(reader, writer):
    try:
        while packet := await reader.read(65536):
            writer.write(packet)
            await writer.drain()
    finally:
        writer.close()
        await writer.wait_closed()


class DatagramEcho(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, payload, peer):
        self.transport.sendto(payload, peer)


class DatagramClient(asyncio.DatagramProtocol):
    def __init__(self):
        self.queue = asyncio.Queue()

    def datagram_received(self, payload, _peer):
        self.queue.put_nowait(payload)

    def error_received(self, error):
        self.queue.put_nowait(error)


async def transfer(port, amount):
    reader, writer = await asyncio.open_connection('127.0.0.1', port)

    async def send():
        left = amount
        while left:
            size = min(len(BLOCK), left)
            writer.write(BLOCK[:size])
            await writer.drain()
            left -= size
        writer.write_eof()

    async def receive():
        left = amount
        while left:
            size = min(len(BLOCK), left)
            data = await reader.readexactly(size)
            if data != BLOCK[:size]:
                raise RuntimeError('TCP payload corrupted')
            left -= size
        if await reader.read(1):
            raise RuntimeError('unexpected TCP trailing bytes')

    try:
        await asyncio.wait_for(asyncio.gather(send(), receive()), timeout=90)
    finally:
        writer.close()
        await writer.wait_closed()


async def tcp_measure(port, connections, amount):
    start = time.perf_counter()
    await asyncio.gather(*(transfer(port, amount) for _ in range(connections)))
    elapsed = time.perf_counter() - start
    return {'seconds': elapsed, 'one_way_payload_bytes': amount * connections,
            'goodput_mbps': amount * connections * 8 / elapsed / 1_000_000}


async def udp_measure(port, samples):
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        DatagramClient, remote_addr=('127.0.0.1', port))
    durations = []
    try:
        for sequence in range(samples):
            payload = sequence.to_bytes(4, 'big') + BLOCK[:1196]
            start = time.perf_counter()
            transport.sendto(payload)
            reply = await asyncio.wait_for(protocol.queue.get(), timeout=2)
            if reply != payload:
                raise RuntimeError(f'UDP payload failed at packet {sequence}')
            durations.append((time.perf_counter() - start) * 1_000_000)
    finally:
        transport.close()
    return {'samples': samples, 'payload_bytes_per_packet': 1200, 'failures': 0,
            'median_rtt_us': statistics.median(durations),
            'p95_rtt_us': sorted(durations)[max(0, int(samples * .95) - 1)]}


def private_json(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as out:
        json.dump(value, out)


async def run(args):
    binary = args.binary.resolve()
    if not binary.is_file():
        raise RuntimeError('build the release binary before benchmarking')
    server = await asyncio.start_server(echo, '127.0.0.1', 0)
    target_port = server.sockets[0].getsockname()[1]
    udp_echo, _ = await asyncio.get_running_loop().create_datagram_endpoint(
        DatagramEcho, local_addr=('127.0.0.1', target_port))
    relay_bytes = 0
    with tempfile.TemporaryDirectory(prefix='relay-bench-') as scratch:
        scratch = Path(scratch)
        reserve = socket.socket()
        reserve.bind(('127.0.0.1', 0))
        port = reserve.getsockname()[1]
        config = {'api_version': 1, 'node_id': 'benchmark', 'revision': 1, 'rules': [{
            'id': 'loopback', 'tenant_id': 'default', 'owner_id': 'admin', 'name': 'Loopback benchmark',
            'listen': f'127.0.0.1:{port}', 'protocol': 'both',
            'targets': [{'address': f'127.0.0.1:{target_port}', 'weight': 1}],
            'meter_epoch': 'run-one', 'quota_bytes': None, 'expires_at_ms': None,
            'rate_bytes_per_sec': None, 'max_connections': 4096}]}
        private_json(scratch / 'config.json', config)
        reserve.close()
        with (scratch / 'engine.log').open('wb') as log:
            process = await asyncio.create_subprocess_exec(
                str(binary), 'standalone', '--config', str(scratch / 'config.json'),
                '--database', str(scratch / 'agent.db'), stdout=log, stderr=asyncio.subprocess.STDOUT)
            try:
                until = time.monotonic() + 10
                while True:
                    if process.returncode is not None:
                        raise RuntimeError('relay exited during startup')
                    try:
                        reader, writer = await asyncio.open_connection('127.0.0.1', port)
                        writer.close()
                        await writer.wait_closed()
                        break
                    except OSError:
                        if time.monotonic() > until:
                            raise RuntimeError('relay listener not ready')
                        await asyncio.sleep(.05)
                await transfer(port, 1024 * 1024)
                relay_bytes += 2 * 1024 * 1024
                results = []
                for connections in args.connections:
                    direct, forwarded = [], []
                    for iteration in range(args.rounds):
                        for name, endpoint in ([('direct', target_port), ('relay', port)] if iteration % 2 == 0 else [('relay', port), ('direct', target_port)]):
                            sample = await tcp_measure(endpoint, connections, args.mib * 1024 * 1024)
                            (direct if name == 'direct' else forwarded).append(sample)
                            if name == 'relay':
                                relay_bytes += 2 * args.mib * 1024 * 1024 * connections
                    dm = statistics.median(x['goodput_mbps'] for x in direct)
                    rm = statistics.median(x['goodput_mbps'] for x in forwarded)
                    results.append({'connections': connections, 'direct': direct, 'relay': forwarded,
                                    'direct_median_mbps': dm, 'relay_median_mbps': rm, 'relay_to_direct_ratio': rm / dm})
                udp_direct = await udp_measure(target_port, args.udp_samples)
                udp_relay = await udp_measure(port, args.udp_samples)
                relay_bytes += 2 * 1200 * args.udp_samples
            finally:
                if process.returncode is None:
                    process.send_signal(signal.SIGTERM)
                    try:
                        await asyncio.wait_for(process.wait(), 10)
                    except TimeoutError:
                        process.kill()
                        await process.wait()
                udp_echo.close()
                server.close()
                await server.wait_closed()
            if process.returncode != 0:
                raise RuntimeError(f'relay failed: {(scratch / "engine.log").read_text()}')
        inspection = await asyncio.create_subprocess_exec(str(binary), 'usage', '--database', str(scratch / 'agent.db'), stdout=asyncio.subprocess.PIPE)
        stdout, _ = await inspection.communicate()
        if inspection.returncode != 0:
            raise RuntimeError('cannot verify benchmark ledger')
        usage = json.loads(stdout)
        recorded = sum(row['upload_bytes'] + row['download_bytes'] for row in usage)
        if recorded != relay_bytes:
            raise RuntimeError(f'ledger mismatch: expected {relay_bytes}, recorded {recorded}')
        return {'at_utc': datetime.now(timezone.utc).isoformat(), 'platform': platform.platform(),
                'machine': platform.machine(), 'python': platform.python_version(),
                'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
                'scope': 'local loopback smoke benchmark; durable admission metering; no TLS; Python echo target',
                'rounds': args.rounds, 'mib_per_connection': args.mib, 'tcp': results,
                'udp': {'direct': udp_direct, 'relay': udp_relay},
                'ledger': {'expected_admitted_bytes': relay_bytes, 'recorded_bytes': recorded, 'exact_match': True}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=Path('target/release/relay'))
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--mib', type=int, default=8)
    parser.add_argument('--connections', type=int, nargs='+', default=[1, 4])
    parser.add_argument('--rounds', type=int, default=3)
    parser.add_argument('--udp-samples', type=int, default=100)
    args = parser.parse_args()
    if min(args.mib, args.rounds, args.udp_samples, *args.connections) < 1:
        parser.error('all workload sizes must be positive')
    report = asyncio.run(run(args))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'tcp': [{k: row[k] for k in ['connections', 'direct_median_mbps', 'relay_median_mbps', 'relay_to_direct_ratio']} for row in report['tcp']], 'udp': report['udp'], 'ledger': report['ledger']}, indent=2))


if __name__ == '__main__':
    main()
