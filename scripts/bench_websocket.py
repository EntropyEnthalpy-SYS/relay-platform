#!/usr/bin/env python3
"""Compare direct TCP and native two-hop TCP/WS/mTLS-WSS on loopback.

Each forwarded mode has two separately metered rules, with the middle link
changing transport. The application client and echo target stay ordinary TCP.
Mode order rotates each round; all application bytes and both ledgers are
verified. This is not a WAN, Realm, high-concurrency or long-duration benchmark.
Requires the optional isolated interop environment and openssl on PATH.
"""
import argparse
import asyncio
import copy
import hashlib
import json
import platform
import statistics
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from bench_budget import free_port, ready, stop
from bench_loopback import echo, tcp_measure, transfer
from check_websocket_interop import certificates, command


async def run(args):
    if args.mib < 1 or args.rounds < 1 or any(count < 1 for count in args.connections):
        raise ValueError('payload, rounds and connection counts must be positive')
    binary = args.binary.resolve()
    root = Path(__file__).resolve().parents[1]
    example = json.loads((root / 'examples/websocket-hop.json').read_text())
    processes, logs, samples, accounting = [], [], [], {}
    amount, warmup = args.mib * 1024 * 1024, 1024 * 1024
    expected = 4 * (warmup + args.rounds * amount * sum(args.connections))
    server = await asyncio.start_server(echo, '127.0.0.1', 0)
    target = server.sockets[0].getsockname()[1]
    with tempfile.TemporaryDirectory(prefix='relay-ws-bench-') as temporary:
        scratch = Path(temporary)
        tls = scratch / 'tls'
        try:
            await certificates(tls)
            endpoints = {'direct': target}
            for mode in ['tcp', 'ws', 'wss-mtls']:
                entry, middle = free_port(), free_port()
                config = copy.deepcopy(example)
                first, second = config['rules']
                first['listen'] = f'127.0.0.1:{entry}'
                first['targets'][0]['address'] = f'127.0.0.1:{middle}'
                second['listen'] = f'127.0.0.1:{middle}'
                second['targets'][0]['address'] = f'127.0.0.1:{target}'
                if mode == 'tcp':
                    del first['targets'][0]['websocket']
                    del second['inbound_websocket']
                elif mode == 'wss-mtls':
                    first['targets'][0]['tls'] = {'server_name': 'localhost', 'ca': 'root', 'identity': 'client'}
                    second['inbound_tls'] = {'identity': 'server', 'client_ca': 'root'}
                config_path = scratch / f'{mode}.json'
                config_path.write_text(json.dumps(config))
                await command(binary, 'validate', '--config', config_path)
                log = (scratch / f'{mode}.log').open('wb')
                logs.append(log)
                process = await asyncio.create_subprocess_exec(
                    str(binary), 'standalone', '--config', str(config_path),
                    '--database', str(scratch / f'{mode}.sqlite'), '--tls-directory', str(tls),
                    stdout=log, stderr=log)
                processes.append(process)
                await ready(entry, process)
                endpoints[mode] = entry
            for port in endpoints.values():
                await transfer(port, warmup)
            modes = list(endpoints)
            for connections in args.connections:
                for round_index in range(args.rounds):
                    offset = round_index % len(modes)
                    for order, mode in enumerate(modes[offset:] + modes[:offset]):
                        result = await tcp_measure(endpoints[mode], connections, amount)
                        samples.append({'mode': mode, 'connections': connections,
                                        'round': round_index + 1, 'order': order + 1, **result})
            for process in reversed(processes):
                await stop(process)
            for mode in modes[1:]:
                database, backup = scratch / f'{mode}.sqlite', scratch / f'{mode}-backup.sqlite'
                rows = json.loads(await command(binary, 'usage', '--database', database))
                recorded = sum(row['upload_bytes'] + row['download_bytes'] for row in rows)
                if len(rows) != 2 or recorded != expected or any(
                        row['upload_bytes'] + row['download_bytes'] != expected // 2 for row in rows):
                    raise RuntimeError(f'{mode} application ledger mismatch: {rows!r}')
                await command(binary, 'backup', '--database', database, '--output', backup)
                if json.loads(await command(binary, 'usage', '--database', backup)) != rows:
                    raise RuntimeError(f'{mode} backup ledger differs')
                accounting[mode] = {'expected_admitted_bytes': expected, 'recorded_bytes': recorded,
                                    'rule_records': 2, 'exact_match': True, 'backup_restore': 'identical'}
        except BaseException:
            for log in logs:
                log.flush()
            for log in scratch.glob('*.log'):
                print(log.name + ': ' + log.read_text()[-4000:])
            raise
        finally:
            failures = []
            for process in reversed(processes):
                try:
                    await stop(process)
                except RuntimeError as error:
                    failures.append(str(error))
            for log in logs:
                log.close()
            server.close()
            await server.wait_closed()
            if failures:
                raise RuntimeError('; '.join(failures))
    medians = [{'connections': connections, 'mode': mode,
                'goodput_mbps': statistics.median(row['goodput_mbps'] for row in samples
                    if row['connections'] == connections and row['mode'] == mode)}
               for connections in args.connections for mode in modes]
    return {'at_utc': datetime.now(timezone.utc).isoformat(), 'platform': platform.platform(),
            'version': (await command(binary, '--version')).strip(),
            'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
            'configuration_source': 'examples/websocket-hop.json', 'payload_mib_per_connection': args.mib,
            'rounds': args.rounds, 'warmup_bytes_each_mode': warmup, 'mode_order': 'rotated each round',
            'topology': 'TCP client -> metered entry -> TCP/WS/mTLS-WSS -> metered exit -> TCP echo',
            'rate_definition': 'one-way application bytes * 8 / full verified round-trip seconds / 1e6',
            'samples': samples, 'medians': medians, 'ledgers': accounting,
            'child_processes_stopped': True, 'limits': ['local macOS or Linux loopback',
                'Python echo/client overhead included', 'same-process native entry and exit rules',
                'no shared global budget', 'not WAN, high-concurrency or long-duration acceptance']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=Path('target/release/relay'))
    parser.add_argument('--mib', type=int, default=16)
    parser.add_argument('--rounds', type=int, default=4)
    parser.add_argument('--connections', type=int, nargs='+', default=[1, 4])
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    report = asyncio.run(run(args))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({key: report[key] for key in ['version', 'medians', 'ledgers', 'child_processes_stopped']}, indent=2))


if __name__ == '__main__':
    main()
