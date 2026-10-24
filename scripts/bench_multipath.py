#!/usr/bin/env python3
"""Single-connection multipath test through independent Python rate-limited paths.

Two real managed Agents, mTLS data links, separate process ledgers, software
path caps and an in-flight path cut. Every application byte is checked.
These are synthetic loopback paths, not a Linux/WAN capacity acceptance.
"""
import argparse
import asyncio
import hashlib
import json
import os
import platform
import statistics
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, ProxyHandler, build_opener

from bench_budget import free_port, ready, stop
from bench_loopback import echo, tcp_measure, transfer
from check_websocket_interop import certificates, command


class CappedPath:
    def __init__(self, target, rate):
        self.target, self.rate = target, rate
        self.tasks, self.connections = set(), set()
        self.upload = self.download = 0

    async def start(self):
        self.server = await asyncio.start_server(self.accept, '127.0.0.1', 0)
        self.port = self.server.sockets[0].getsockname()[1]

    def accept(self, reader, writer):
        task = asyncio.create_task(self.handle(reader, writer))
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)

    async def handle(self, reader, writer):
        remote = None
        pumps = []
        try:
            target, remote = await asyncio.open_connection('127.0.0.1', self.target)
            self.connections.add((writer, remote))

            async def pump(source, destination, direction):
                while data := await source.read(8192):
                    # No burst credit: each block waits for its byte cost before delivery.
                    await asyncio.sleep(len(data) / self.rate)
                    destination.write(data)
                    await destination.drain()
                    setattr(self, direction, getattr(self, direction) + len(data))
                if destination.can_write_eof():
                    destination.write_eof()

            pumps = [asyncio.create_task(pump(reader, remote, 'upload')),
                     asyncio.create_task(pump(target, writer, 'download'))]
            await asyncio.gather(*pumps)
        except (ConnectionError, asyncio.IncompleteReadError, OSError):
            pass
        finally:
            for task in pumps:
                task.cancel()
            await asyncio.gather(*pumps, return_exceptions=True)
            self.connections.discard((writer, remote))
            for stream in (writer, remote):
                if stream:
                    stream.close()
                    try:
                        await stream.wait_closed()
                    except (ConnectionError, OSError):
                        pass

    async def cut(self):
        for pair in list(self.connections):
            for writer in pair:
                writer.transport.abort()

    async def close(self):
        self.server.close()
        await self.server.wait_closed()
        await self.cut()
        for task in list(self.tasks):
            task.cancel()
        await asyncio.gather(*list(self.tasks), return_exceptions=True)


async def run(args):
    if args.mib < 1 or args.rounds < 1 or args.fast_mibps <= 0 or args.slow_mibps <= 0:
        raise ValueError('payload, rounds and path rates must be positive')
    binary = args.binary.resolve()
    processes, logs, paths, samples = [], [], [], []
    modes = ['single-fast', 'stripe', 'replicate']
    expected = dict.fromkeys(modes, 0)
    amount, warmup = args.mib * 1024 * 1024, 256 * 1024
    service = await asyncio.start_server(echo, '127.0.0.1', 0)
    backend = service.sockets[0].getsockname()[1]
    token = None
    with tempfile.TemporaryDirectory(prefix='relay-multipath-bench-') as temporary:
        scratch = Path(temporary)
        origin = 'http://127.0.0.1:' + str(free_port())
        async def api(method, path, body=None):
            def request():
                headers = {'Content-Type': 'application/json'}
                if token:
                    headers['Authorization'] = 'Bearer ' + token
                payload = None if body is None else json.dumps(body).encode()
                req = Request(origin + '/api/v1' + path, data=payload, headers=headers, method=method)
                with build_opener(ProxyHandler({})).open(req, timeout=10) as response:
                    return json.load(response)
            return await asyncio.to_thread(request)
        async def launch(name, *arguments):
            log = (scratch / (name + '.log')).open('wb')
            logs.append(log)
            proc = await asyncio.create_subprocess_exec(str(binary), *map(str, arguments), stdout=log, stderr=log)
            processes.append(proc)
            return proc
        try:
            await certificates(scratch / 'tls')
            control = await launch('controller', 'server', '--listen', origin.removeprefix('http://'), '--state', scratch / 'controller')
            await ready(int(origin.rsplit(':', 1)[1]), control)
            session = await api('POST', '/auth/login', {'username': 'admin', 'password': (scratch / 'controller/admin-password.secret').read_text().strip()})
            token = session['token']
            nodes = {name: await api('POST', '/nodes', {'name': name}) for name in ['entry', 'exit']}
            policies = {'window_frames': 64, 'max_sessions': 4, 'retransmit_ms': 1000, 'stall_timeout_ms': 10000}
            configs = {'entry': [], 'exit': []}
            endpoints, mode_paths = {}, {}
            for mode in modes:
                end, start = free_port(), free_port()
                endpoints[mode] = start
                mode_paths[mode] = []
                rates = [args.fast_mibps] if mode == 'single-fast' else [args.fast_mibps, args.slow_mibps]
                for rate in rates:
                    path = CappedPath(end, rate * 1024 * 1024)
                    await path.start()
                    paths.append(path)
                    mode_paths[mode].append(path)
                base = {'tenant_id': 'default', 'owner_id': session['user']['id'], 'protocol': 'tcp',
                        'meter_epoch': 'multipath-benchmark', 'connect_timeout_ms': 10000, 'idle_timeout_secs': 20}
                configs['exit'].append({**base, 'id': mode + '-exit', 'name': mode + '-exit',
                    'listen': '127.0.0.1:' + str(end), 'targets': [{'address': '127.0.0.1:' + str(backend), 'weight': 1}],
                    'inbound_tls': {'identity': 'server', 'client_ca': 'root'},
                    'inbound_multipath': {'limits': policies, 'max_paths': 2, 'allow_replication': True}})
                configs['entry'].append({**base, 'id': mode + '-entry', 'name': mode + '-entry',
                    'listen': '127.0.0.1:' + str(start),
                    'targets': [{'address': '127.0.0.1:' + str(path.port), 'weight': 1,
                        'tls': {'server_name': 'localhost', 'ca': 'root', 'identity': 'client'}} for path in mode_paths[mode]],
                    'outbound_multipath': {'limits': policies, 'mode': 'replicate' if mode == 'replicate' else 'stripe',
                        'min_paths': len(rates), 'paths': [{'upload_weight': max(1, round(rate / max(rates) * 1000)),
                            'download_weight': max(1, round(rate / max(rates) * 1000))} for rate in rates]}})
            agents = []
            for name in ['exit', 'entry']:
                node = nodes[name]['node']['id']
                await api('PUT', '/nodes/' + node + '/config', {'expected_revision': 0, 'rules': configs[name]})
                credential = scratch / (name + '.secret')
                with os.fdopen(os.open(credential, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), 'w') as file:
                    file.write(nodes[name]['enrollment_token'])
                proc = await launch(name, 'agent', '--controller', origin, '--node-id', node,
                    '--enrollment-token-file', credential, '--state', scratch / name, '--tls-directory', scratch / 'tls', '--poll-seconds', '1')
                agents.append(proc)
                await ready(int(configs[name][0]['listen'].rsplit(':', 1)[1]), proc)
            for mode in modes:
                await asyncio.wait_for(transfer(endpoints[mode], warmup), 15)
                expected[mode] += warmup
            for round_index in range(args.rounds):
                offset = round_index % len(modes)
                for mode in modes[offset:] + modes[:offset]:
                    path_before = [(path.upload, path.download) for path in mode_paths[mode]]
                    result = await asyncio.wait_for(tcp_measure(endpoints[mode], 1, amount), 60)
                    expected[mode] += amount
                    samples.append({'mode': mode, 'round': round_index + 1, 'application_connections': 1, **result,
                        'path_stream_bytes_during_sample': [
                            {'slot': slot, 'upload_bytes': path.upload - before[0], 'download_bytes': path.download - before[1]}
                            for slot, (path, before) in enumerate(zip(mode_paths[mode], path_before))]})
            # Cut exactly one subflow after payload has started, retaining the same application socket.
            failed_path = mode_paths['stripe'][0]
            before = failed_path.upload
            async def fault():
                async with asyncio.timeout(15):
                    while failed_path.upload - before < 128 * 1024:
                        await asyncio.sleep(.005)
                    await failed_path.cut()
            await asyncio.wait_for(asyncio.gather(transfer(endpoints['stripe'], amount), fault()), 60)
            expected['stripe'] += amount
            await asyncio.gather(*(stop(agent) for agent in agents))
            usage = await api('GET', '/usage')
            accounting = []
            for mode in modes:
                for side in ['entry', 'exit']:
                    rows = [row for row in usage if row['rule_id'] == mode + '-' + side]
                    if len(rows) != 1 or rows[0]['upload_bytes'] != expected[mode] or rows[0]['download_bytes'] != expected[mode]:
                        raise RuntimeError('logical ledger differs from verified application bytes: ' + mode + '-' + side)
                    accounting.append({'rule': rows[0]['rule_id'], 'upload_bytes': rows[0]['upload_bytes'],
                                       'download_bytes': rows[0]['download_bytes'], 'exact_match': True})
            for name in nodes:
                local = json.loads(await command(binary, 'usage', '--database', scratch / name / 'agent.sqlite'))
                if sum(row['upload_bytes'] + row['download_bytes'] for row in local) != 2 * sum(expected.values()):
                    raise RuntimeError('local Agent ledger differs from controller')
            metrics = [{'name': node['name'], 'multipath': node['stats'].get('multipath')} for node in await api('GET', '/nodes')]
            for row in metrics:
                stats = row['multipath']
                if not stats or stats['active_sessions'] != 0 or stats['active_paths'] != 0:
                    raise RuntimeError('final multipath diagnostics are absent or active: ' + json.dumps(row))
                if stats['delivered_payload_bytes'] != sum(expected.values()) or stats['replicated_payload_bytes'] != expected['replicate']:
                    raise RuntimeError('multipath payload/replication diagnostics differ: ' + json.dumps({'actual': row, 'expected': expected}))
                if stats['failed_paths'] < 1 or stats['peak_reorder_bytes'] > 64 * 16384 or stats['peak_send_window_bytes'] > 64 * 16384:
                    raise RuntimeError('fault or window-bound evidence missing')
            if sum(row['multipath']['retransmitted_payload_bytes'] for row in metrics) == 0:
                raise RuntimeError('fault test did not exercise protocol retransmission')
            medians = {mode: statistics.median(row['goodput_mbps'] for row in samples if row['mode'] == mode) for mode in modes}
            gain = medians['stripe'] / medians['single-fast']
            result = {'at_utc': datetime.now(timezone.utc).isoformat(), 'version': (await command(binary, '--version')).strip(),
                'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(), 'platform': platform.platform(),
                'python': platform.python_version(), 'mode_order': 'rotates each round', 'rounds': args.rounds,
                'payload_bytes_per_connection': amount, 'warmup_bytes_per_mode': warmup,
                'topology': 'one TCP application -> entry Agent -> independent capped mTLS paths -> exit Agent -> echo',
                'configured_path_mib_per_second_each_direction': [args.fast_mibps, args.slow_mibps],
                'shaper_block_bytes': 8192, 'rate_definition': 'one-way verified application bytes * 8 / elapsed round-trip seconds / 1e6',
                'samples': samples, 'median_goodput_mbps': medians, 'stripe_to_single_fast_ratio': gain,
                'single_connection_gain_observed': gain > 1.15, 'path_cut_same_application_connection': 'all bytes verified',
                'ledgers': accounting, 'node_metrics': metrics, 'child_processes_stopped': True,
                'limits': ['synthetic Python pacing on local loopback, timer and process overhead included',
                           'same-machine Agents; no claim about independent WAN links or Linux kernel MPTCP',
                           'wire caps include TLS and relay framing, exclude IP/TCP headers',
                           'no high-concurrency, long-duration, maximum throughput or third-party comparison']}
        finally:
            for path in paths:
                await path.close()
            failures = []
            for process in reversed(processes):
                try:
                    await stop(process)
                except RuntimeError as error:
                    failures.append(str(error))
            for log in logs:
                log.close()
            service.close()
            await service.wait_closed()
            if failures:
                raise RuntimeError('; '.join(failures))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=Path('target/release/relay'))
    parser.add_argument('--mib', type=int, default=4)
    parser.add_argument('--rounds', type=int, default=3)
    parser.add_argument('--fast-mibps', type=float, default=2)
    parser.add_argument('--slow-mibps', type=float, default=1)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    report = asyncio.run(run(args))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({key: report[key] for key in ['median_goodput_mbps', 'stripe_to_single_fast_ratio',
          'single_connection_gain_observed', 'node_metrics', 'child_processes_stopped']}, indent=2))


if __name__ == '__main__':
    main()
