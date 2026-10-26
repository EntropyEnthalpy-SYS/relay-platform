#!/usr/bin/env python3
"""Verify active health selection with independent services and Release processes.

The optional throughput samples compare two rules on one managed Agent while
probes remain active. This is a local smoke measurement, not a capacity claim.
All sockets, processes, state and credentials are temporary and local.
"""
import argparse
import asyncio
import copy
import hashlib
import json
import platform
import statistics
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, ProxyHandler, build_opener

from bench_budget import free_port, ready, stop
from bench_loopback import DatagramClient, tcp_measure, transfer


class Service(asyncio.DatagramProtocol):
    def __init__(self, marker):
        self.marker = marker * 4
        self.tcp_ok = self.udp_ok = True
        self.probes = {'tcp': 0, 'udp': 0}
        self.connections = set()

    async def start(self):
        self.server = await asyncio.start_server(self.handle, '127.0.0.1', 0)
        self.port = self.server.sockets[0].getsockname()[1]
        await asyncio.get_running_loop().create_datagram_endpoint(
            lambda: self, local_addr=('127.0.0.1', self.port))

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, peer):
        if data == b'PING':
            self.probes['udp'] += 1
            reply = b'PONG' if self.udp_ok else b'FAIL'
        else:
            reply = self.marker if data == b'DATA' else data
        self.transport.sendto(reply, peer)

    async def handle(self, reader, writer):
        self.connections.add(writer)
        try:
            first = await reader.readexactly(4)
            if first == b'PING':
                self.probes['tcp'] += 1
                writer.write(b'PONG' if self.tcp_ok else b'FAIL')
            else:
                writer.write(self.marker if first == b'DATA' else first)
                while data := await reader.read(65536):
                    writer.write(data)
                    await writer.drain()
            await writer.drain()
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        finally:
            self.connections.discard(writer)
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionError:
                pass

    async def close(self):
        self.transport.close()
        self.server.close()
        await self.server.wait_closed()
        for writer in list(self.connections):
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionError:
                pass


async def run(args):
    binary = args.binary.resolve()
    first, second = Service(b'A'), Service(b'B')
    await first.start()
    await second.start()
    processes, logs, observations, measures = [], [], [], []
    expected = {'checked': 0, 'plain': 0}
    token = None
    udp = None
    with tempfile.TemporaryDirectory(prefix='relay-health-check-') as temporary:
        root = Path(temporary)
        state, agent_state = root / 'controller', root / 'agent'
        control_port = free_port()
        origin = f'http://127.0.0.1:{control_port}'

        async def api(method, path, body=None):
            def request():
                headers = {'Content-Type': 'application/json'}
                if token:
                    headers['Authorization'] = f'Bearer {token}'
                data = None if body is None else json.dumps(body).encode()
                req = Request(origin + '/api/v1' + path, data=data, headers=headers, method=method)
                with build_opener(ProxyHandler({})).open(req, timeout=10) as response:
                    return json.load(response)
            return await asyncio.to_thread(request)

        async def launch(name, *arguments):
            log = (root / (name + '.log')).open('wb')
            logs.append(log)
            process = await asyncio.create_subprocess_exec(str(binary), *map(str, arguments), stdout=log, stderr=log)
            processes.append(process)
            return process

        async def cli(*arguments):
            process = await asyncio.create_subprocess_exec(str(binary), *map(str, arguments),
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            processes.append(process)
            output, error = await asyncio.wait_for(process.communicate(), 20)
            if process.returncode:
                raise RuntimeError(f'CLI {arguments[0]}: {error.decode()}')
            return output

        async def health(label, states, timeout=15):
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                value = await api('GET', f'/nodes/{node["id"]}/health')
                reports = {(r['target_index'], r['protocol']): r for r in value['reports']}
                if len(reports) == 4 and all(reports[key]['status'] == status for key, status in states.items()):
                    observations.append({'phase': label, 'reports': value['reports']})
                    return value
                await asyncio.sleep(.05)
            raise RuntimeError(f'{label}: health did not converge: {value}')

        async def marked(protocol, marker):
            if protocol == 'tcp':
                reader, writer = await asyncio.open_connection('127.0.0.1', checked_port)
                try:
                    writer.write(b'DATA')
                    await writer.drain()
                    writer.write_eof()
                    result = await asyncio.wait_for(reader.readexactly(4), 3)
                    if await asyncio.wait_for(reader.read(1), 3):
                        raise RuntimeError('unexpected trailing bytes')
                finally:
                    writer.close()
                    await writer.wait_closed()
            else:
                udp.sendto(b'DATA')
                result = await asyncio.wait_for(datagrams.queue.get(), 3)
            if result != marker * 4:
                raise RuntimeError(f'{protocol} selected wrong target: {result!r}')
            expected['checked'] += 8

        async def check_usage():
            rows = await api('GET', '/usage')
            actual = {row['rule_id']: row['upload_bytes'] + row['download_bytes'] for row in rows}
            if actual != expected:
                raise RuntimeError(f'ledger mismatch: {actual} != {expected}')
            local = json.loads(await cli('usage', '--database', agent_state / 'agent.sqlite'))
            if {r['rule_id']: r['upload_bytes'] + r['download_bytes'] for r in local} != expected:
                raise RuntimeError('Agent ledger differs from application payloads')
            return rows

        try:
            controller = await launch('controller', 'server', '--state', state, '--listen', f'127.0.0.1:{control_port}')
            await ready(control_port, controller)
            session = await api('POST', '/auth/login', {'username': 'admin', 'password': (state / 'admin-password.secret').read_text().strip()})
            token = session['token']
            baseline = root / 'baseline.sqlite'
            await cli('backup', '--database', state / 'controller.sqlite', '--output', baseline)
            created = await api('POST', '/nodes', {'name': 'health-release-agent', 'lease_policy': {}})
            node = created['node']
            enrollment = root / 'enrollment.secret'
            enrollment.write_text(created['enrollment_token'])
            enrollment.chmod(0o600)
            checked_port, plain_port = free_port(), free_port()
            checked = {'id': 'checked', 'tenant_id': node['tenant_id'], 'owner_id': session['user']['id'],
                'name': 'Active health', 'listen': f'127.0.0.1:{checked_port}', 'protocol': 'both',
                'enabled': True, 'meter_epoch': 'initial', 'targets': [
                    {'address': f'127.0.0.1:{first.port}', 'weight': 1, 'priority': 0, 'max_sessions': 32},
                    {'address': f'127.0.0.1:{second.port}', 'weight': 1, 'priority': 10, 'max_sessions': 32}],
                'health_check': {'interval_ms': 200, 'timeout_ms': 100, 'healthy_threshold': 2,
                    'unhealthy_threshold': 2, 'recovery_delay_ms': 500, 'max_age_ms': 1500,
                    'tcp': {'kind': 'exchange', 'request_base64': 'UElORw==', 'expected_base64': 'UE9ORw=='},
                    'udp': {'request_base64': 'UElORw==', 'expected_base64': 'UE9ORw=='}}}
            plain = copy.deepcopy(checked)
            plain.update(id='plain', name='No active health', listen=f'127.0.0.1:{plain_port}')
            del plain['health_check']
            config = await api('PUT', f'/nodes/{node["id"]}/config', {'expected_revision': 0, 'rules': [checked, plain]})
            agent = await launch('agent', 'agent', '--controller', origin, '--node-id', node['id'],
                '--enrollment-token-file', enrollment, '--state', agent_state, '--poll-seconds', 1)
            all_good = {(i, p): 'healthy' for i in range(2) for p in ['tcp', 'udp']}
            await health('initial application replies', all_good)
            udp, datagrams = await asyncio.get_running_loop().create_datagram_endpoint(DatagramClient,
                remote_addr=('127.0.0.1', checked_port))
            await marked('tcp', b'A')
            await marked('udp', b'A')
            first.tcp_ok = False
            states = {**all_good, (0, 'tcp'): 'unhealthy'}
            await health('TCP failed, UDP independent', states)
            await marked('tcp', b'B')
            await marked('udp', b'A')
            first.udp_ok = False
            await health('both failed on primary', {**states, (0, 'udp'): 'unhealthy'})
            await marked('udp', b'B')  # Same client socket; retired session must not stay on A.
            first.tcp_ok = first.udp_ok = True
            await health('primary recovered after hold', all_good)
            await marked('tcp', b'A')
            # Existing healthy B UDP sessions retain affinity; a fresh client chooses A.
            udp.close()
            udp, datagrams = await asyncio.get_running_loop().create_datagram_endpoint(DatagramClient,
                remote_addr=('127.0.0.1', checked_port))
            await marked('udp', b'A')
            first.tcp_ok = second.tcp_ok = False
            await health('all TCP targets failed', {**all_good, (0, 'tcp'): 'unhealthy', (1, 'tcp'): 'unhealthy'})
            reader, writer = await asyncio.open_connection('127.0.0.1', checked_port)
            try:
                writer.write(b'DATA')
                await writer.drain()
                if await asyncio.wait_for(reader.read(4), 3):
                    raise RuntimeError('all-unhealthy pool admitted application data')
            except ConnectionError:
                pass
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except ConnectionError:
                    pass
            first.tcp_ok = second.tcp_ok = True
            await health('recovered before measurements', all_good)
            for name, port in [('plain', plain_port), ('checked', checked_port)]:
                await transfer(port, 1024 * 1024)
                expected[name] += 2 * 1024 * 1024
            for connections in args.connections:
                samples = {'plain': [], 'checked': []}
                for iteration in range(args.rounds):
                    order = ['plain', 'checked'] if iteration % 2 == 0 else ['checked', 'plain']
                    for name in order:
                        port = checked_port if name == 'checked' else plain_port
                        samples[name].append(await tcp_measure(port, connections, args.mib * 1024 * 1024))
                        expected[name] += 2 * connections * args.mib * 1024 * 1024
                medians = {name: statistics.median(r['goodput_mbps'] for r in rows) for name, rows in samples.items()}
                measures.append({'connections': connections, 'samples': samples, 'median_mbps': medians,
                    'checked_to_plain_ratio': medians['checked'] / medians['plain']})
            await health('after verified bulk payloads', all_good)
            udp.close()
            udp = None
            await stop(agent)
            usage = await check_usage()
            await stop(controller)
            inputs = [baseline, state / 'recovery.log', state / 'recovery.log.head.json']
            hashes = [hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs]
            restored = root / 'restored'
            recovery = json.loads(await cli('restore', '--backup', baseline, '--recovery-log', inputs[1], '--output', restored))
            if hashes != [hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs]:
                raise RuntimeError('restore mutated source evidence')
            controller = await launch('restored-controller', 'server', '--state', restored, '--listen', f'127.0.0.1:{control_port}')
            await ready(control_port, controller)
            if await api('GET', f'/nodes/{node["id"]}/config') != config or await api('GET', '/usage') != usage:
                raise RuntimeError('recovered configuration or ledger differs')
            restored_lease = (await api('GET', '/nodes'))[0]['lease']
            if not restored_lease['policy'] or restored_lease['recovery_wait_ms'] <= 0:
                raise RuntimeError('restored strict node did not retain its cold-start quarantine')
            first.tcp_ok = first.udp_ok = False
            restart_began = time.monotonic()
            agent = await launch('restarted-agent', 'agent', '--controller', origin, '--node-id', node['id'],
                '--state', agent_state, '--poll-seconds', 1)
            # Ownership acquisition deliberately waits up to a full TTL after a
            # controller restore; only then can fresh backend probes run.
            await health('restart observes changed service',
                {**all_good, (0, 'tcp'): 'unhealthy', (0, 'udp'): 'unhealthy'},
                timeout=15 + restored_lease['policy']['ttl_ms'] / 1000)
            restart_seconds = time.monotonic() - restart_began
            await marked('tcp', b'B')
            await stop(agent)
            await check_usage()
            await stop(controller)
            return {'at_utc': datetime.now(timezone.utc).isoformat(), 'platform': platform.platform(),
                'version': (await cli('--version')).decode().strip(),
                'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(), 'observations': observations,
                'backend_probe_counts': {'A': first.probes, 'B': second.probes},
                'ledger': {'by_rule_bytes': expected, 'total_bytes': sum(expected.values()), 'exact_match': True,
                    'source_probes_excluded': True}, 'restore': recovery, 'tcp': measures,
                'strict_restart': {'ttl_ms': restored_lease['policy']['ttl_ms'],
                    'initial_recovery_wait_ms': restored_lease['recovery_wait_ms'],
                    'fresh_health_after_restart_seconds': restart_seconds},
                'parameters': {'rounds': args.rounds, 'mib_per_connection': args.mib,
                    'probe_endpoints': 4, 'probe_interval_ms': 200, 'priority': [0, 10], 'target_max_sessions': 32},
                'child_processes_stopped': True,
                'limits': ['single macOS/host loopback; not Linux/WAN acceptance',
                    'plain and checked rules share one Agent; background probes run in both samples',
                    'sequential alternating samples; not an isolated proof of performance equivalence',
                    'UDP healthy sessions keep target affinity on recovery; only failed sessions are evicted',
                    'downstream relay probe metering verified separately by Rust mTLS/WSS test']}
        except BaseException:
            for log in logs:
                log.flush()
            for log in root.glob('*.log'):
                print(log.name + ': ' + log.read_text()[-3000:])
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
            if udp:
                udp.close()
            await first.close()
            await second.close()
            if failures:
                raise RuntimeError('; '.join(failures))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=Path('target/release/relay'))
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--connections', type=int, nargs='+', default=[1, 4])
    parser.add_argument('--rounds', type=int, default=4)
    parser.add_argument('--mib', type=int, default=16)
    args = parser.parse_args()
    if min(args.rounds, args.mib, *args.connections) < 1 or max(args.connections) > 30:
        parser.error('positive sizes and at most 30 connections required')
    report = asyncio.run(run(args))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'ledger': report['ledger'], 'restore': report['restore'],
        'tcp': [{k: row[k] for k in ['connections', 'median_mbps', 'checked_to_plain_ratio']} for row in report['tcp']]}, indent=2))


if __name__ == '__main__':
    main()
