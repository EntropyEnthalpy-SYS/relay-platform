#!/usr/bin/env python3
"""Verify TCP PROXY interoperability through HAProxy -> relay -> HAProxy.

Uses an explicitly supplied HAProxy binary, loopback listeners and temporary
state only. Each direction covers v1, v2 and v2 with CRC32C, with original IPv4
and IPv6 addresses. A separate Python decoder checks the final HAProxy header.
This is a functional check, not a UDP, TLS or performance benchmark.
"""
import argparse
import asyncio
import hashlib
import ipaddress
import json
import platform
import signal
import struct
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from bench_budget import free_port, ready


def crc32c(data):
    value = 0xffffffff
    for byte in data:
        value ^= byte
        for _ in range(8):
            value = (value >> 1) ^ (0x82f63b78 if value & 1 else 0)
    return value ^ 0xffffffff


async def read_proxy(reader):
    fixed = await reader.readexactly(16)
    if fixed[:12] != b'\r\n\r\n\0\r\nQUIT\n' or fixed[12] != 0x21:
        raise RuntimeError('HAProxy did not emit a v2 PROXY header')
    size = int.from_bytes(fixed[14:16], 'big')
    if size > 4096:
        raise RuntimeError('unexpected HAProxy header size')
    body = await reader.readexactly(size)
    if fixed[13] == 0x11:
        address_size = 4
    elif fixed[13] == 0x21:
        address_size = 16
    else:
        raise RuntimeError('unexpected HAProxy family or transport')
    offset = 2 * address_size
    source = str(ipaddress.ip_address(body[:address_size]))
    destination = str(ipaddress.ip_address(body[address_size:offset]))
    ports = struct.unpack('!HH', body[offset:offset + 4])
    offset += 4
    checksum = None
    while offset < len(body):
        if len(body) - offset < 3:
            raise RuntimeError('truncated HAProxy TLV')
        kind, length = struct.unpack('!BH', body[offset:offset + 3])
        offset += 3
        if offset + length > len(body):
            raise RuntimeError('HAProxy TLV exceeds header')
        if kind == 3:
            if length != 4 or checksum is not None:
                raise RuntimeError('invalid HAProxy CRC32C TLV')
            checksum = int.from_bytes(body[offset:offset + 4], 'big')
            check = bytearray(fixed + body)
            check[16 + offset:20 + offset] = b'\0' * 4
            if crc32c(check) != checksum:
                raise RuntimeError('independent CRC32C calculation differs')
        offset += length
    if checksum is None:
        raise RuntimeError('HAProxy did not emit the requested checksum')
    return [source, destination, *ports]


def haproxy_config(entrance, relay, departure, target, mode):
    option = {'v1': 'send-proxy', 'v2': 'send-proxy-v2',
              'v2_crc': 'send-proxy-v2 proxy-v2-options crc32c'}[mode]
    return f'''global
    nbthread 1
defaults
    mode tcp
    timeout connect 3s
    timeout client 10s
    timeout server 10s
frontend before_relay
    bind 127.0.0.1:{entrance} accept-proxy
    default_backend to_relay
backend to_relay
    server relay 127.0.0.1:{relay} {option}
frontend after_relay
    bind 127.0.0.1:{departure} accept-proxy
    default_backend to_observer
backend to_observer
    server observer 127.0.0.1:{target} send-proxy-v2 proxy-v2-options crc32c
'''


async def command(*arguments):
    process = await asyncio.create_subprocess_exec(*map(str, arguments),
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    try:
        output, error = await asyncio.wait_for(process.communicate(), 15)
    except BaseException:
        if process.returncode is None:
            process.kill()
        await process.wait()
        raise
    if process.returncode != 0:
        raise RuntimeError(f'{arguments[0]} failed: {error.decode()}')
    return output.decode()


async def stop(process, is_haproxy):
    if process.returncode is None:
        process.send_signal(signal.SIGUSR1 if is_haproxy else signal.SIGTERM)
        try:
            await asyncio.wait_for(process.wait(), 5)
        except TimeoutError:
            process.kill()
            await process.wait()
    if process.returncode != 0:
        raise RuntimeError(f'interoperability process exited with {process.returncode}')


async def run(args):
    binary, haproxy = args.binary.resolve(), args.haproxy.resolve()
    version = (await command(binary, '--version')).strip()
    haproxy_version = (await command(haproxy, '-v')).splitlines()[0]
    cases, total = [], 0
    claims = [['198.51.100.7', '203.0.113.9', 12345, 443],
              ['2001:db8:1::7', '2001:db8:2::9', 23456, 8443]]
    payload = bytes(range(256)) * 32
    for incoming in ('v1', 'v2', 'v2_crc'):
        for outgoing in ('v1', 'v2', 'v2_crc'):
            processes, logs, handlers = [], [], set()
            observations = asyncio.Queue()

            async def observer(reader, writer):
                try:
                    observed = await read_proxy(reader)
                    while chunk := await reader.read(65536):
                        writer.write(chunk)
                        await writer.drain()
                    await observations.put(observed)
                except Exception as error:
                    await observations.put(error)
                finally:
                    writer.close()
                    await writer.wait_closed()

            def connected(reader, writer):
                task = asyncio.create_task(observer(reader, writer))
                handlers.add(task)
                task.add_done_callback(handlers.discard)

            server = await asyncio.start_server(connected, '127.0.0.1', 0)
            target = server.sockets[0].getsockname()[1]
            ports = {target}
            while len(ports) < 4:
                ports.add(free_port())
            entrance, relay_port, departure = sorted(ports - {target})
            with tempfile.TemporaryDirectory(prefix='relay-proxy-interop-') as temporary:
                scratch = Path(temporary)
                config = {'api_version': 1, 'node_id': 'proxy-interop', 'revision': 1, 'rules': [{
                    'id': 'proxy-chain', 'tenant_id': 'default', 'owner_id': 'admin',
                    'name': 'HAProxy interoperability', 'listen': f'127.0.0.1:{relay_port}',
                    'protocol': 'tcp', 'meter_epoch': 'interop',
                    'inbound_proxy': {'version': incoming[:2], 'trusted_sources': ['127.0.0.0/8']},
                    'allow_sources': ['198.51.100.0/24', '2001:db8::/32'],
                    'targets': [{'address': f'127.0.0.1:{departure}', 'weight': 1,
                        'proxy_protocol': {'version': outgoing[:2], 'checksum': outgoing == 'v2_crc'}}]}]}
                (scratch / 'relay.json').write_text(json.dumps(config))
                (scratch / 'haproxy.cfg').write_text(haproxy_config(
                    entrance, relay_port, departure, target, incoming))
                database = scratch / 'agent.sqlite'
                try:
                    await command(binary, 'validate', '--config', scratch / 'relay.json')
                    await command(haproxy, '-c', '-f', scratch / 'haproxy.cfg')
                    for name, executable, arguments, port in [
                        ('relay', binary, ['standalone', '--config', str(scratch / 'relay.json'),
                            '--database', str(database)], relay_port),
                        ('haproxy', haproxy, ['-db', '-f', str(scratch / 'haproxy.cfg')], entrance)]:
                        log = (scratch / f'{name}.log').open('wb')
                        logs.append(log)
                        process = await asyncio.create_subprocess_exec(str(executable), *arguments,
                            stdout=log, stderr=log)
                        processes.append((process, name == 'haproxy'))
                        await ready(port, process)
                    for claim in claims:
                        family = 'TCP4' if ':' not in claim[0] else 'TCP6'
                        header = f'PROXY {family} {claim[0]} {claim[1]} {claim[2]} {claim[3]}\r\n'.encode()
                        reader, writer = await asyncio.open_connection('127.0.0.1', entrance)
                        try:
                            writer.write(header + payload)
                            await writer.drain()
                            received = await asyncio.wait_for(reader.readexactly(len(payload)), 10)
                            if received != payload:
                                raise RuntimeError('HAProxy chain changed application bytes')
                            writer.write_eof()
                            await writer.drain()
                            if await asyncio.wait_for(reader.read(1), 10) != b'':
                                raise RuntimeError('unexpected extra application byte')
                            observed = await asyncio.wait_for(observations.get(), 3)
                            if observed != claim:
                                raise RuntimeError(f'original addresses changed: {observed!r} != {claim!r}')
                        finally:
                            writer.close()
                            await writer.wait_closed()
                        cases.append({'input': incoming, 'output': outgoing, 'address_family': family,
                            'original_endpoints_preserved': True, 'binary_payload_verified_bytes': len(payload),
                            'half_close': 'passed', 'independent_haproxy_crc32c': 'passed'})
                    for process, is_haproxy in reversed(processes):
                        await stop(process, is_haproxy)
                    rows = json.loads(await command(binary, 'usage', '--database', database))
                    admitted = sum(row['upload_bytes'] + row['download_bytes'] for row in rows)
                    if len(rows) != 1 or admitted != 2 * len(claims) * len(payload):
                        raise RuntimeError(f'PROXY bytes affected application ledger: {rows!r}')
                    total += admitted
                except BaseException:
                    for log in logs:
                        log.flush()
                    for log in scratch.glob('*.log'):
                        print(log.name + ': ' + log.read_text()[-4000:])
                    raise
                finally:
                    failures = []
                    for process, is_haproxy in reversed(processes):
                        try:
                            await stop(process, is_haproxy)
                        except RuntimeError as error:
                            failures.append(str(error))
                    for log in logs:
                        log.close()
                    server.close()
                    await server.wait_closed()
                    for task in list(handlers):
                        task.cancel()
                    await asyncio.gather(*handlers, return_exceptions=True)
                    if failures:
                        raise RuntimeError('; '.join(failures))
    return {'at_utc': datetime.now(timezone.utc).isoformat(), 'platform': platform.platform(),
        'version': version, 'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
        'haproxy_version': haproxy_version, 'haproxy_binary_sha256': hashlib.sha256(haproxy.read_bytes()).hexdigest(),
        'topology': 'Python client -> HAProxy -> relay -> HAProxy -> Python observer', 'cases': cases,
        'ledger': {'expected_admitted_bytes': 2 * len(cases) * len(payload), 'recorded_bytes': total,
                   'exact_match': True, 'proxy_headers_excluded': True},
        'child_processes_stopped': True, 'limits': ['local loopback TCP only', 'no external UDP or TLS interop',
                                                  'not a performance benchmark']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=Path('target/release/relay'))
    parser.add_argument('--haproxy', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    report = asyncio.run(run(args))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({**{key: report[key] for key in ('version', 'haproxy_version', 'ledger', 'child_processes_stopped')},
                      'passed_cases': len(report['cases'])}, indent=2))


if __name__ == '__main__':
    main()
