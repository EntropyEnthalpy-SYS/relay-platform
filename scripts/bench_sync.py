#!/usr/bin/env python3
"""Compare single and grouped durable sync commits using one release binary.

Two local controllers receive alternating waves of simulated node reports.
This measures control API throughput/latency, not network forwarding goodput.
Each report increments an explicitly synthetic one-byte counter. No Agent or
business listener is started, and all controller state is temporary.
"""
import argparse
import asyncio
import hashlib
import json
import platform
import secrets
import statistics
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, ProxyHandler, build_opener

from bench_budget import free_port, ready, stop


async def run(args):
    binary = args.binary.resolve()
    processes, logs = [], []
    with tempfile.TemporaryDirectory(prefix='relay-sync-bench-') as temporary:
        scratch = Path(temporary)
        groups = {}

        async def api(group, method, path, body=None, credential=None):
            def request():
                headers = {'Content-Type': 'application/json'}
                token = credential or group.get('token')
                if token:
                    headers['Authorization'] = f'Bearer {token}'
                payload = None if body is None else json.dumps(body).encode()
                req = Request(group['origin'] + '/api/v1' + path, data=payload, headers=headers, method=method)
                with build_opener(ProxyHandler({})).open(req, timeout=15) as response:
                    return json.load(response)
            return await asyncio.to_thread(request)

        async def wave(group):
            group['sequence'] += 1
            sequence = group['sequence']

            async def report(node):
                started = time.perf_counter()
                response = await api(group, 'POST', '/agent/sync', {
                    'ledger_id': node['ledger'], 'applied_revision': 1, 'apply_error': None,
                    'stats': {key: 0 for key in ['active_tcp', 'active_udp', 'accepted_tcp', 'rejected_connections',
                        'failed_connections', 'dropped_datagrams', 'forwarded_upload_bytes', 'forwarded_download_bytes']},
                    'usage': [{'rule_id': node['rule'], 'meter_epoch': 'synthetic',
                        'sequence': sequence, 'upload_bytes': sequence, 'download_bytes': 0}]}, node['credential'])
                if response['acknowledgements'] != [{'rule_id': node['rule'], 'meter_epoch': 'synthetic', 'sequence': sequence}]:
                    raise RuntimeError('sync response does not confirm the original node report')
                return (time.perf_counter() - started) * 1000

            started = time.perf_counter()
            latencies = await asyncio.gather(*(report(node) for node in group['nodes']))
            elapsed = time.perf_counter() - started
            return {'seconds': elapsed, 'requests_per_second': args.nodes / elapsed,
                'request_latency_ms': latencies}

        try:
            for label, batch in [('individual', 1), ('batched', 16)]:
                port = free_port()
                state = scratch / label
                log = (scratch / f'{label}.log').open('wb')
                logs.append(log)
                process = await asyncio.create_subprocess_exec(str(binary), 'server', '--listen',
                    f'127.0.0.1:{port}', '--state', str(state), '--sync-batch-size', str(batch), stdout=log, stderr=log)
                processes.append(process)
                await ready(port, process)
                group = {'origin': f'http://127.0.0.1:{port}', 'nodes': [], 'sequence': 0}
                groups[label] = group
                session = await api(group, 'POST', '/auth/login', {'username': 'admin',
                    'password': (state / 'admin-password.secret').read_text().strip()})
                group['token'] = session['token']
                for i in range(args.nodes):
                    node = await api(group, 'POST', '/nodes', {'name': f'control-benchmark-{i}', 'lease_policy': None})
                    node_id = node['node']['id']
                    credential = secrets.token_hex(32)
                    await api(group, 'POST', '/agent/enroll', {'node_id': node_id,
                        'enrollment_token': node['enrollment_token'], 'credential': credential})
                    rule = f'control-rule-{i}'
                    await api(group, 'PUT', f'/nodes/{node_id}/config', {'expected_revision': 0, 'rules': [{
                        'id': rule, 'tenant_id': 'default', 'owner_id': session['user']['id'], 'name': rule,
                        'listen': f'127.0.0.1:{20000 + i}', 'protocol': 'tcp', 'meter_epoch': 'synthetic',
                        'targets': [{'address': '127.0.0.1:9', 'weight': 1}]}]})
                    page = await api(group, 'POST', '/agent/reconcile', {
                        'ledger_id': None, 'after': None, 'expected_revision': None}, credential)
                    group['nodes'].append({'credential': credential, 'ledger': page['ledger_id'], 'rule': rule})
                await wave(group)
                group['before'] = await api(group, 'GET', '/control/metrics')
                group['head_before'] = (await api(group, 'GET', '/recovery'))['head']['sequence']
                group['samples'] = []
            for i in range(args.rounds):
                order = ['individual', 'batched'] if i % 2 == 0 else ['batched', 'individual']
                for label in order:
                    groups[label]['samples'].append(await wave(groups[label]))
            result = {}
            for label, group in groups.items():
                rows = await api(group, 'GET', '/usage')
                expected = args.nodes * (args.rounds + 1)
                total = sum(row['upload_bytes'] + row['download_bytes'] for row in rows)
                if total != expected:
                    raise RuntimeError('synthetic controller ledger differs from accepted reports')
                metrics = await api(group, 'GET', '/control/metrics')
                recovery = await api(group, 'GET', '/recovery')
                requests = metrics['processed_requests'] - group['before']['processed_requests']
                batches = metrics['committed_batches'] - group['before']['committed_batches']
                if requests != args.nodes * args.rounds or metrics['failed_batches'] or metrics['queue_full_rejections']:
                    raise RuntimeError('control benchmark lost, failed or rejected requests')
                if recovery['head']['sequence'] - group['head_before'] != batches:
                    raise RuntimeError('sync batches do not match durable journal commits')
                latencies = sorted(value for row in group['samples'] for value in row['request_latency_ms'])
                result[label] = {'samples': group['samples'], 'median_requests_per_second': statistics.median(
                    row['requests_per_second'] for row in group['samples']),
                    'median_request_latency_ms': statistics.median(latencies),
                    'p95_request_latency_ms': latencies[int((len(latencies) - 1) * .95)],
                    'measured_requests': requests, 'durable_commits': batches,
                    'requests_per_commit': requests / batches, 'control_metrics': metrics,
                    'synthetic_ledger_expected_bytes': expected, 'synthetic_ledger_recorded_bytes': total}
            return {'at_utc': datetime.now(timezone.utc).isoformat(), 'platform': platform.platform(),
                'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
                'scope': 'control API only; simulated node usage; local loopback; two controllers; alternating waves; same binary and durability protocol',
                'nodes_per_controller': args.nodes, 'rounds': args.rounds, 'results': result,
                'batched_to_individual_rate_ratio': result['batched']['median_requests_per_second'] / result['individual']['median_requests_per_second']}
        finally:
            failures = []
            for process in reversed(processes):
                try:
                    await stop(process)
                except RuntimeError as error:
                    failures.append(str(error))
            for log in logs:
                log.close()
            if failures:
                raise RuntimeError('; '.join(failures))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=Path('target/release/relay'))
    parser.add_argument('--nodes', type=int, default=32, choices=range(2, 65))
    parser.add_argument('--rounds', type=int, default=5)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.rounds < 1:
        parser.error('rounds must be positive')
    report = asyncio.run(run(args))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({key: {k: v for k, v in value.items() if k != 'samples'} for key, value in report['results'].items()}, indent=2))


if __name__ == '__main__':
    main()
