#!/usr/bin/env python3
"""Compare two managed loopback agents with and without a shared user budget.

All application bytes are verified. A single temporary controller and four agent
processes are used; only the two agents in the measured group carry payload.
This is not a WAN, latency-injection, fairness, or production capacity benchmark.
"""
import argparse
import asyncio
import hashlib
import json
import os
import platform
import secrets
import signal
import socket
import statistics
import time
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, ProxyHandler, build_opener

from bench_loopback import echo, transfer


def free_port():
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        return listener.getsockname()[1]


async def ready(port, process):
    until = time.monotonic() + 15
    while time.monotonic() < until:
        if process.returncode is not None:
            raise RuntimeError('benchmark process exited before becoming ready')
        try:
            _, writer = await asyncio.open_connection('127.0.0.1', port)
            writer.close()
            await writer.wait_closed()
            return
        except OSError:
            await asyncio.sleep(.05)
    raise RuntimeError('benchmark listener did not become ready')


async def stop(process):
    if process.returncode is None:
        process.send_signal(signal.SIGTERM)
        try:
            await asyncio.wait_for(process.wait(), 10)
        except TimeoutError:
            process.kill()
            await process.wait()
    if process.returncode != 0:
        raise RuntimeError(f'benchmark process exited with {process.returncode}')


async def run(args):
    binary = args.binary.resolve()
    if not binary.is_file():
        raise RuntimeError('build the release binary before benchmarking')
    server = await asyncio.start_server(echo, '127.0.0.1', 0)
    target = server.sockets[0].getsockname()[1]
    quantum = args.quantum_mib * 1024 * 1024
    amount = args.mib * 1024 * 1024
    expected_each_group = 4 * 1024 * 1024 + 4 * amount * args.rounds * sum(args.connections)
    processes, agents, logs = [], [], []
    token = None
    with tempfile.TemporaryDirectory(prefix='relay-budget-bench-') as temporary:
        scratch = Path(temporary)
        control_port = free_port()
        origin = f'http://127.0.0.1:{control_port}'

        async def api(method, path, body=None):
            def request():
                headers = {'Content-Type': 'application/json'}
                if token is not None:
                    headers['Authorization'] = f'Bearer {token}'
                payload = None if body is None else json.dumps(body).encode()
                req = Request(origin + '/api/v1' + path, data=payload, headers=headers, method=method)
                with build_opener(ProxyHandler({})).open(req, timeout=10) as response:
                    return json.load(response)
            return await asyncio.to_thread(request)

        async def launch(name, *command):
            log = (scratch / f'{name}.log').open('wb')
            logs.append(log)
            process = await asyncio.create_subprocess_exec(str(binary), *command, stdout=log, stderr=log)
            processes.append(process)
            return process

        try:
            controller = await launch('controller', 'server', '--listen', f'127.0.0.1:{control_port}', '--state', str(scratch / 'controller'))
            await ready(control_port, controller)
            password = (scratch / 'controller/admin-password.secret').read_text().strip()
            session = await api('POST', '/auth/login', {'username': 'admin', 'password': password})
            token = session['token']
            unbudgeted = await api('POST', '/users', {'username': 'unbudgeted', 'password': secrets.token_urlsafe(32), 'role': 'viewer'})
            budget = await api('POST', '/budgets', {
                'scope': 'user', 'scope_id': session['user']['id'], 'name': 'two-agent benchmark',
                'limit_bytes': expected_each_group + 2 * quantum, 'quantum_bytes': quantum})
            endpoints = {'plain': [], 'budgeted': []}
            for group in endpoints:
                for index in range(2):
                    name = f'{group}-{index}'
                    enrolled = await api('POST', '/nodes', {'name': name})
                    node = enrolled['node']['id']
                    port = free_port()
                    endpoints[group].append(port)
                    owner = unbudgeted['id'] if group == 'plain' else session['user']['id']
                    rule = {
                        'id': name, 'tenant_id': 'default', 'owner_id': owner, 'name': name,
                        'listen': f'127.0.0.1:{port}', 'protocol': 'tcp',
                        'targets': [{'address': f'127.0.0.1:{target}', 'weight': 1}],
                        'meter_epoch': 'benchmark', 'max_connections': 4096, 'connect_timeout_ms': 5000}
                    published = await api('PUT', f'/nodes/{node}/config', {'expected_revision': 0, 'rules': [rule]})
                    actual = published['rules'][0].get('budget_ids', [])
                    if actual != ([] if group == 'plain' else [budget['id']]):
                        raise RuntimeError('benchmark policy binding does not match the intended group')
                    enrollment_path = scratch / f'{name}.secret'
                    with os.fdopen(os.open(enrollment_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), 'w') as file:
                        file.write(enrolled['enrollment_token'])
                    state = scratch / name
                    process = await launch(name, 'agent', '--controller', origin, '--node-id', node,
                                           '--state', str(state), '--enrollment-token-file', str(enrollment_path), '--poll-seconds', '1')
                    agents.append((process, state))
                    await ready(port, process)
            for ports in endpoints.values():
                await asyncio.gather(*(transfer(port, 1024 * 1024) for port in ports))
            measurements = []
            for connections in args.connections:
                samples = {group: [] for group in endpoints}
                for iteration in range(args.rounds):
                    order = ['plain', 'budgeted'] if iteration % 2 == 0 else ['budgeted', 'plain']
                    for group in order:
                        started = time.perf_counter()
                        await asyncio.gather(*(transfer(port, amount) for port in endpoints[group] for _ in range(connections)))
                        elapsed = time.perf_counter() - started
                        samples[group].append({'seconds': elapsed, 'one_way_payload_bytes': 2 * connections * amount,
                                               'goodput_mbps': 2 * connections * amount * 8 / elapsed / 1_000_000})
                plain = statistics.median(x['goodput_mbps'] for x in samples['plain'])
                limited = statistics.median(x['goodput_mbps'] for x in samples['budgeted'])
                measurements.append({'connections_per_agent': connections, 'total_connections': 2 * connections,
                                     **samples, 'plain_median_mbps': plain, 'budgeted_median_mbps': limited,
                                     'budgeted_to_plain_ratio': limited / plain})
            # Normal shutdown must durably seal and return unused reservations.
            await asyncio.gather(*(stop(process) for process, _ in agents))
            overview = await api('GET', '/budgets')
            measured_budget = overview['budgets'][0]
            if (measured_budget['consumed_bytes'], measured_budget['committed_bytes']) != (expected_each_group, expected_each_group):
                raise RuntimeError('shared budget consumption or unused reservation return does not match payload')
            until = time.monotonic() + 5
            while True:
                reported = await api('GET', '/usage')
                recorded = sum(row['upload_bytes'] + row['download_bytes'] for row in reported)
                if recorded == 2 * expected_each_group:
                    break
                if time.monotonic() > until:
                    raise RuntimeError('controller rule ledger does not match all admitted payload')
                await asyncio.sleep(.1)
            local_recorded = 0
            for _, state in agents:
                inspect = await asyncio.create_subprocess_exec(str(binary), 'usage', '--database', str(state / 'agent.sqlite'), stdout=asyncio.subprocess.PIPE)
                stdout, _ = await inspect.communicate()
                if inspect.returncode != 0:
                    raise RuntimeError('cannot read local benchmark ledger')
                local_recorded += sum(row['upload_bytes'] + row['download_bytes'] for row in json.loads(stdout))
            if local_recorded != recorded:
                raise RuntimeError('agent and controller ledgers differ')
            recovery = await api('GET', '/recovery')
            if not recovery['enabled'] or not recovery['healthy']:
                raise RuntimeError('controller recovery logging was not healthy during the benchmark')
            return {'at_utc': datetime.now(timezone.utc).isoformat(), 'platform': platform.platform(),
                    'machine': platform.machine(), 'python': platform.python_version(),
                    'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
                    'scope': 'two managed agents on local loopback; shared user budget versus no global budget; both use durable admission; controller recovery logging enabled; no TLS; Python echo',
                    'controller_recovery_log': recovery,
                    'rounds': args.rounds, 'mib_per_connection': args.mib, 'reservation_quantum_bytes': quantum,
                    'tcp': measurements, 'budget': {'expected_bytes': expected_each_group, 'consumed_bytes': measured_budget['consumed_bytes'],
                    'committed_bytes_after_shutdown': measured_budget['committed_bytes'], 'unused_reserved_bytes_after_shutdown': 0},
                    'ledger': {'expected_admitted_bytes': 2 * expected_each_group, 'controller_bytes': recorded, 'agent_bytes': local_recorded, 'exact_match': True}}
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=Path('target/release/relay'))
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--mib', type=int, default=32)
    parser.add_argument('--connections', type=int, nargs='+', default=[1, 4])
    parser.add_argument('--rounds', type=int, default=3)
    parser.add_argument('--quantum-mib', type=int, default=4)
    args = parser.parse_args()
    if min(args.mib, args.rounds, *args.connections) < 1 or not 1 <= args.quantum_mib <= 64:
        parser.error('workload sizes must be positive; quantum must be 1..64 MiB')
    report = asyncio.run(run(args))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({**{k: report[k] for k in ['budget', 'ledger']}, 'tcp': [{k: row[k] for k in ['total_connections', 'plain_median_mbps', 'budgeted_median_mbps', 'budgeted_to_plain_ratio']} for row in report['tcp']]}, indent=2))


if __name__ == '__main__':
    main()
