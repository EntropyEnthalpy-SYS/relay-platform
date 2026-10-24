#!/usr/bin/env python3
"""Independent Python/OpenSSL client for the documented relay-multipath-v1 wire format.

Checks native inbound interoperability, reordered and duplicate frames, FIN/ACK,
replicated replies and strict malformed-input rejection. This fixture is not a
production multipath implementation or a third-party proprietary protocol test.
"""
import argparse
import asyncio
import hashlib
import json
import os
import platform
import ssl
import struct
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from bench_budget import free_port, ready, stop
from bench_loopback import echo
from check_websocket_interop import certificates, command

HELLO = struct.Struct('>8sBBBBHHH2x32s32s')
HEADER = struct.Struct('>B3xQI')


async def frame(reader):
    raw = await reader.readexactly(16)
    kind, seq, size = HEADER.unpack(raw)
    if raw[1:4] != b'\0\0\0' or kind not in (1, 2, 3):
        raise AssertionError('invalid response frame')
    if (kind == 1 and not 1 <= size <= 16384) or (kind == 2 and size != 0) or (kind == 3 and size not in (0, 32)):
        raise AssertionError('invalid response frame length')
    return kind, seq, await reader.readexactly(size)


async def close(paths):
    for _, writer in paths:
        writer.close()
    for _, writer in paths:
        try:
            await asyncio.wait_for(writer.wait_closed(), 2)
        except (OSError, asyncio.TimeoutError):
            pass


async def connect(port, context, mode):
    paths = []
    session = os.urandom(32)
    token = bytes(32)
    try:
        for slot in range(2):
            reader, writer = await asyncio.open_connection('127.0.0.1', port, ssl=context, server_hostname='localhost')
            paths.append((reader, writer))
            writer.write(HELLO.pack(b'RLYMP001', 1 if slot == 0 else 2, slot, mode, 0, 8, 1, 1, session, token))
            await writer.drain()
            magic, window, received = struct.unpack('>8sH32s', await reader.readexactly(42))
            if magic != b'RLYMPA01' or window != 8 or received == bytes(32) or (slot == 1 and received != token):
                raise AssertionError('native handshake response differs from public format')
            token = received
        paths[0][1].write(b'RLYMPS01\x03')
        await paths[0][1].drain()
        if await paths[0][0].readexactly(8) != b'RLYMPOK1':
            raise AssertionError('missing start barrier')
        return paths
    except BaseException:
        await close(paths)
        raise


async def positive(port, context, mode):
    paths = await connect(port, context, mode)
    data = [bytes((i + shift) % 251 for i in range(length)) for shift, length in enumerate([16000, 19, 16384, 8187, 9001])]
    expected = b''.join(data)
    inbox = asyncio.Queue()
    async def reader(slot):
        try:
            while True:
                await inbox.put((slot, await frame(paths[slot][0])))
        except (OSError, asyncio.IncompleteReadError) as error:
            await inbox.put((slot, error))
    readers = [asyncio.create_task(reader(slot)) for slot in range(2)]
    try:
        # seq 1 arrives before 0, and seq 1 is sent twice on different subflows.
        for position, seq in enumerate([1, 0, 2, 1, 3, 4]):
            writer = paths[position % 2][1]
            writer.write(HEADER.pack(1, seq, len(data[seq])) + data[seq])
            await writer.drain()
        paths[0][1].write(HEADER.pack(2, len(data), 0))
        await paths[0][1].drain()
        pending, output, next_sequence, ack, finished = {}, bytearray(), 0, 0, False
        duplicates = 0
        while not (finished and ack == len(data) + 1):
            _, item = await inbox.get()
            if isinstance(item, BaseException):
                raise AssertionError('native transport ended before FIN/ACK') from item
            kind, seq, payload = item
            if kind == 3:
                if seq > len(data) + 1:
                    raise AssertionError('native acknowledged nonexistent input')
                ack = max(ack, seq)
                continue
            if seq < next_sequence or seq in pending:
                duplicates += len(payload)
            else:
                if seq - next_sequence >= 8:
                    raise AssertionError('native exceeded the negotiated receive window')
                pending[seq] = (kind, payload)
            while next_sequence in pending:
                record, payload = pending.pop(next_sequence)
                if finished:
                    raise AssertionError('native data follows FIN')
                if record == 2:
                    finished = True
                else:
                    output.extend(payload)
                next_sequence += 1
            for _, writer in paths:
                writer.write(HEADER.pack(3, next_sequence, 0))
                await writer.drain()
        if bytes(output) != expected:
            raise AssertionError('reassembled application payload differs')
        return {'mode': 'stripe' if mode == 0 else 'replicate', 'payload_bytes_each_direction': len(expected),
                'sent_duplicate_bytes': len(data[1]), 'received_duplicate_bytes': duplicates,
                'out_of_order_and_half_close': 'verified', 'sha256': hashlib.sha256(expected).hexdigest()}
    finally:
        for task in readers:
            task.cancel()
        await asyncio.gather(*readers, return_exceptions=True)
        await close(paths)


async def negative(port, context, case):
    paths = []
    try:
        if case in ['bad-magic', 'reserved-handshake']:
            reader, writer = await asyncio.open_connection('127.0.0.1', port, ssl=context, server_hostname='localhost')
            paths = [(reader, writer)]
            message = bytearray(HELLO.pack(b'RLYMP001', 1, 0, 0, 0, 8, 1, 1, os.urandom(32), bytes(32)))
            if case == 'bad-magic':
                message[0] ^= 1
            else:
                message[18] = 1
            writer.write(message)
            await writer.drain()
            try:
                response = await reader.read(1)
            except OSError:
                response = b''
            if response:
                raise AssertionError('malformed handshake was accepted')
        else:
            paths = await connect(port, context, 0)
            if case == 'oversize-frame':
                message = HEADER.pack(1, 0, 16385)
            elif case == 'out-of-window':
                message = HEADER.pack(1, 8, 1) + b'x'
            else:
                message = HEADER.pack(3, 9, 0)
            paths[0][1].write(message)
            await paths[0][1].drain()
            for reader, _ in paths:
                try:
                    while True:
                        kind, _, _ = await frame(reader)
                        if kind in (1, 2):
                            raise AssertionError('invalid input produced application data or clean EOF')
                except (OSError, asyncio.IncompleteReadError):
                    pass
        return {'case': case, 'result': 'rejected without application payload'}
    finally:
        await close(paths)


async def run(args):
    binary = args.binary.resolve()
    service = await asyncio.start_server(echo, '127.0.0.1', 0)
    target = service.sockets[0].getsockname()[1]
    process = log = None
    with tempfile.TemporaryDirectory(prefix='relay-mp-interop-') as directory:
        root = Path(directory)
        try:
            await certificates(root / 'tls')
            context = ssl.create_default_context(cafile=str(root / 'tls/root/ca.pem'))
            context.load_cert_chain(root / 'tls/client/cert.pem', root / 'tls/client/key.pem')
            port = free_port()
            spec = {'api_version': 1, 'node_id': 'interop', 'revision': 1, 'rules': [{
                'id': 'interop', 'name': 'interop', 'tenant_id': 'default', 'owner_id': 'admin',
                'listen': '127.0.0.1:' + str(port), 'protocol': 'tcp', 'meter_epoch': 'interop',
                'inbound_tls': {'identity': 'server', 'client_ca': 'root'},
                'inbound_multipath': {'max_paths': 2, 'allow_replication': True,
                    'limits': {'window_frames': 8, 'max_sessions': 4, 'retransmit_ms': 200, 'stall_timeout_ms': 3000}},
                'targets': [{'address': '127.0.0.1:' + str(target), 'weight': 1}]}]}
            config = root / 'config.json'; config.write_text(json.dumps(spec))
            database = root / 'agent.sqlite'
            log = (root / 'agent.log').open('wb')
            process = await asyncio.create_subprocess_exec(str(binary), 'standalone', '--config', str(config),
                '--database', str(database), '--tls-directory', str(root / 'tls'), stdout=log, stderr=log)
            await ready(port, process)
            success = [await asyncio.wait_for(positive(port, context, mode), 10) for mode in (0, 1)]
            failures = [await asyncio.wait_for(negative(port, context, case), 5) for case in
                        ['bad-magic', 'reserved-handshake', 'oversize-frame', 'out-of-window', 'ack-unsent-data']]
            await stop(process)
            rows = json.loads(await command(binary, 'usage', '--database', database))
            expected = sum(row['payload_bytes_each_direction'] for row in success)
            if len(rows) != 1 or rows[0]['upload_bytes'] != expected or rows[0]['download_bytes'] != expected:
                raise AssertionError('duplicate or invalid frames changed the logical ledger')
            report = {'at_utc': datetime.now(timezone.utc).isoformat(), 'version': (await command(binary, '--version')).strip(),
                'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(), 'platform': platform.platform(),
                'python': platform.python_version(), 'tls': ssl.OPENSSL_VERSION,
                'successes': success, 'rejections': failures,
                'ledger': {'upload_bytes': expected, 'download_bytes': expected, 'exact_match': True},
                'child_processes_stopped': True,
                'scope': 'independent Python/OpenSSL client -> native mTLS aggregation server -> Python TCP echo',
                'limits': ['functional local wire-format fixture', 'no independent server, WAN or proprietary protocol compatibility claim']}
        finally:
            if process:
                await stop(process)
            if log:
                log.close()
            service.close()
            await service.wait_closed()
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=Path('target/release/relay'))
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    report = asyncio.run(run(args))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
