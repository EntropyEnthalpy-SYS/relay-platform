#!/usr/bin/env python3
"""Run three real Agent processes, publish/reverse a declared chain, and restore it.

Loopback only: a temporary controller, three Agents, echo sockets and certificates.
Requires the optional scripts/requirements-interop.txt environment for shared TLS
fixtures. No system service or remote server is changed.
"""
import argparse
import asyncio
import copy
import hashlib
import json
import platform
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, ProxyHandler, build_opener

from bench_budget import free_port, ready, stop
from bench_loopback import echo, DatagramEcho
from check_websocket_interop import certificates, command


def link(configs, order, target, mode):
    for config in configs:
        rule = config['rules'][0]
        for key in ['inbound_tls', 'inbound_websocket', 'inbound_proxy']:
            rule.pop(key, None)
        rule['targets'] = [{'address': f'127.0.0.1:{target}', 'weight': 1}]
    for source, destination in zip(order, order[1:]):
        src, dst = configs[source]['rules'][0], configs[destination]['rules'][0]
        target_spec = {'address': dst['advertise'], 'weight': 1,
                       'via': {'node_id': configs[destination]['node_id'], 'rule_id': dst['id']},
                       'proxy_protocol': {'version': 'v2', 'checksum': True,
                                          'placement': 'inside_tls' if mode == 'wss' else 'before_tls'}}
        dst['inbound_proxy'] = {'version': 'v2', 'trusted_sources': ['127.0.0.0/8'],
                               'placement': target_spec['proxy_protocol']['placement']}
        if mode in ('ws', 'wss'):
            target_spec['websocket'] = {'path': '/chain', 'host': 'relay.test'}
            dst['inbound_websocket'] = {'path': '/chain', 'host': 'relay.test', 'allowed_origins': []}
        if mode == 'wss':
            target_spec['tls'] = {'server_name': 'localhost', 'ca': 'root', 'identity': 'client'}
            dst['inbound_tls'] = {'identity': 'server', 'client_ca': 'root'}
        src['targets'] = [target_spec]


def batch(configs):
    return {'updates': [{'node_id': c['node_id'], 'expected_revision': c['revision'], 'rules': c['rules']}
                        for c in configs]}


async def exchange(port, payload):
    reader, writer = await asyncio.open_connection('127.0.0.1', port)
    try:
        writer.write(payload)
        await writer.drain()
        writer.write_eof()
        returned = await asyncio.wait_for(reader.readexactly(len(payload)), 10)
        if returned != payload or await asyncio.wait_for(reader.read(1), 10):
            raise RuntimeError('TCP chain changed application bytes or half-close')
    finally:
        writer.close()
        await writer.wait_closed()


async def run(args):
    binary = args.binary.resolve()
    cases = []
    payload = bytes(index % 251 for index in range(33333))
    with tempfile.TemporaryDirectory(prefix='relay-topology-check-') as temporary:
        root = Path(temporary)
        tls = root / 'tls'
        await certificates(tls)
        for mode in ['both', 'ws', 'wss']:
            scratch = root / mode
            scratch.mkdir(mode=0o700)
            processes, logs, agents = [], [], []
            server = await asyncio.start_server(echo, '127.0.0.1', 0)
            target_port = server.sockets[0].getsockname()[1]
            udp, _ = await asyncio.get_running_loop().create_datagram_endpoint(DatagramEcho,
                            local_addr=('127.0.0.1', target_port))
            origin, token = None, None

            async def api(method, path, body=None):
                def request():
                    headers = {'Content-Type': 'application/json'}
                    if token is not None:
                        headers['Authorization'] = f'Bearer {token}'
                    data = None if body is None else json.dumps(body).encode()
                    req = Request(origin + '/api/v1' + path, data=data, headers=headers, method=method)
                    with build_opener(ProxyHandler({})).open(req, timeout=10) as response:
                        return json.load(response)
                return await asyncio.to_thread(request)

            async def launch(name, *arguments):
                log = (scratch / f'{name}.log').open('wb')
                logs.append(log)
                process = await asyncio.create_subprocess_exec(str(binary), *map(str, arguments),
                                                               stdout=log, stderr=log)
                processes.append(process)
                return process

            async def wait_applied(configs, idle=False):
                until = time.monotonic() + 20
                while time.monotonic() < until:
                    nodes = {node['id']: node for node in await api('GET', '/nodes')}
                    if all(nodes[c['node_id']]['applied_revision'] == c['revision']
                           and nodes[c['node_id']]['apply_error'] is None
                           and (not idle or (nodes[c['node_id']]['stats']['active_tcp'] == 0
                                and nodes[c['node_id']]['stats']['active_udp'] == 0)) for c in configs):
                        return
                    if any(process.returncode is not None for process in agents):
                        raise RuntimeError('Agent exited before applying topology')
                    await asyncio.sleep(.1)
                raise RuntimeError('topology did not converge')

            try:
                control_port = free_port()
                origin = f'http://127.0.0.1:{control_port}'
                state = scratch / 'controller'
                controller = await launch('controller', 'server', '--listen', f'127.0.0.1:{control_port}', '--state', state)
                await ready(control_port, controller)
                session = await api('POST', '/auth/login', {'username': 'admin', 'password': (state / 'admin-password.secret').read_text().strip()})
                token = session['token']
                configs, ports, agent_states = [], [], []
                for index in range(3):
                    created = await api('POST', '/nodes', {'name': f'{mode}-hop-{index}'})
                    node, port = created['node'], free_port()
                    ports.append(port)
                    configs.append({'api_version': 1, 'node_id': node['id'], 'revision': 0, 'rules': [{
                        'id': f'hop-{index}', 'tenant_id': node['tenant_id'], 'owner_id': session['user']['id'],
                        'name': f'{mode} hop {index}', 'listen': f'127.0.0.1:{port}',
                        'advertise': f'127.0.0.1:{port}', 'protocol': 'both' if mode == 'both' else 'tcp',
                        'meter_epoch': 'initial', 'enabled': True, 'targets': []}]})
                    enrollment = scratch / f'enrollment-{index}.secret'
                    enrollment.write_text(created['enrollment_token'])
                    enrollment.chmod(0o600)
                    agent_state = scratch / f'agent-{index}'
                    agent_states.append(agent_state)
                    agents.append(await launch(f'agent-{index}', 'agent', '--controller', origin,
                        '--node-id', node['id'], '--enrollment-token-file', enrollment,
                        '--state', agent_state, '--tls-directory', tls, '--poll-seconds', '1'))
                baseline = scratch / 'baseline.sqlite'
                await command(binary, 'backup', '--database', state / 'controller.sqlite', '--output', baseline)
                link(configs, [0, 1, 2], target_port, mode)
                preview = await api('POST', '/configurations/preview', batch(configs))
                if any(node['desired_revision'] != 0 for node in await api('GET', '/nodes')):
                    raise RuntimeError('preview modified desired configuration')
                published = await api('POST', '/configurations/publish', batch(configs))
                if preview != published:
                    raise RuntimeError('published batch differs from preview')
                configs = published['configs']
                await wait_applied(configs)
                await exchange(ports[0], payload)
                each = 2 * len(payload)
                if mode == 'both':
                    import socket
                    def probe_udp():
                        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                            client.settimeout(5)
                            client.connect(('127.0.0.1', ports[0]))
                            client.send(payload[:1200])
                            if client.recv(65536) != payload[:1200]:
                                raise RuntimeError('UDP topology payload mismatch')
                    await asyncio.to_thread(probe_udp)
                    each += 2400
                for config in configs:
                    config['rules'][0]['enabled'] = False
                configs = (await api('POST', '/configurations/publish', batch(configs)))['configs']
                await wait_applied(configs, idle=True)
                link(configs, [2, 1, 0], target_port, mode)
                for config in configs:
                    config['rules'][0]['enabled'] = True
                configs = (await api('POST', '/configurations/publish', batch(configs)))['configs']
                await wait_applied(configs)
                await exchange(ports[2], payload[:43])
                each += 86
                for process in agents:
                    await stop(process)
                usage = await api('GET', '/usage')
                recorded = sum(row['upload_bytes'] + row['download_bytes'] for row in usage)
                if recorded != 3 * each or len(usage) != 3:
                    raise RuntimeError('controller per-hop ledger differs')
                for agent_state in agent_states:
                    rows = json.loads(await command(binary, 'usage', '--database', agent_state / 'agent.sqlite'))
                    if len(rows) != 1 or rows[0]['upload_bytes'] + rows[0]['download_bytes'] != each:
                        raise RuntimeError('Agent per-hop ledger differs')
                before_restore = await api('GET', '/topology')
                await stop(controller)
                inputs = [baseline, state / 'recovery.log', state / 'recovery.log.head.json']
                fingerprints = [hashlib.sha256(path.read_bytes()).hexdigest() for path in inputs]
                restored = scratch / 'restored'
                recovery = json.loads(await command(binary, 'restore', '--backup', baseline,
                    '--recovery-log', state / 'recovery.log', '--output', restored))
                if fingerprints != [hashlib.sha256(path.read_bytes()).hexdigest() for path in inputs]:
                    raise RuntimeError('restore changed input backup or journal')
                restored_port = free_port()
                origin = f'http://127.0.0.1:{restored_port}'
                restored_process = await launch('restored-controller', 'server', '--listen', f'127.0.0.1:{restored_port}', '--state', restored)
                await ready(restored_port, restored_process)
                if await api('GET', '/topology') != before_restore or await api('GET', '/usage') != usage:
                    raise RuntimeError('restored graph, node state or usage differs')
                await stop(restored_process)
                cases.append({'transport': mode, 'agents': 3, 'forward_payload_bytes': len(payload),
                    'udp_payload_bytes': 1200 if mode == 'both' else 0, 'reverse_payload_bytes': 43,
                    'per_hop_recorded_bytes': each, 'total_recorded_bytes': recorded,
                    'preview_read_only': True, 'publish_matches_preview': True,
                    'stopped_before_reverse': True, 'binary_half_close_verified': True,
                    'restored_topology_usage_and_old_session': True, 'restore': recovery})
            except BaseException:
                for log in logs:
                    log.flush()
                for log in scratch.glob('*.log'):
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
                udp.close()
                server.close()
                await server.wait_closed()
                if failures:
                    raise RuntimeError('; '.join(failures))
    return {'at_utc': datetime.now(timezone.utc).isoformat(), 'platform': platform.platform(),
            'version': (await command(binary, '--version')).strip(),
            'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(), 'cases': cases,
            'total_recorded_bytes': sum(case['total_recorded_bytes'] for case in cases),
            'child_processes_stopped': True, 'limits': ['one machine, three Agent processes per case',
                'declared addresses only; no discovery of DNS/NAT aliases', 'per-hop accounting, not once-per-logical-flow billing',
                'asynchronous node activation, not distributed atomic rollout', 'not Linux/WAN/throughput acceptance']}


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
