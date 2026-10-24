#!/usr/bin/env python3
"""Verify node inventory, atomic edits, pause, expiry and recovery with real CLIs.
"""
import argparse
import asyncio
import hashlib
import json
import os
import platform
import signal
import sqlite3
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, ProxyHandler, build_opener
from urllib.error import HTTPError

from bench_budget import free_port, ready, stop
from bench_loopback import DatagramClient, DatagramEcho, echo


async def run(args):
    binary = args.binary.resolve()
    processes, logs = [], []
    closed_udp_observations = []
    token = None
    writer = None
    loop = asyncio.get_running_loop()
    backend = await asyncio.start_server(echo, '127.0.0.1', 0)
    target = backend.sockets[0].getsockname()[1]
    udp_backend, _ = await loop.create_datagram_endpoint(
        DatagramEcho, local_addr=('127.0.0.1', target))
    with tempfile.TemporaryDirectory(prefix='relay-node-profiles-') as temporary:
        scratch = Path(temporary)
        control_port, port = free_port(), free_port()
        origin = f'http://127.0.0.1:{control_port}'
        control_state, agent_state = scratch / 'control', scratch / 'agent'
        udp_transport, udp = await loop.create_datagram_endpoint(
            DatagramClient, remote_addr=('127.0.0.1', port))

        async def api(method, path, body=None):
            def request():
                headers = {'Content-Type': 'application/json'}
                if token:
                    headers['Authorization'] = f'Bearer {token}'
                payload = None if body is None else json.dumps(body).encode()
                req = Request(origin + '/api/v1' + path, data=payload, headers=headers, method=method)
                with build_opener(ProxyHandler({})).open(req, timeout=5) as response:
                    return json.load(response)
            return await asyncio.to_thread(request)

        async def launch(name, *command):
            log = (scratch / f'{name}.log').open('wb')
            logs.append(log)
            process = await asyncio.create_subprocess_exec(str(binary), *command, stdout=log, stderr=log)
            processes.append(process)
            return process

        async def cli(*command):
            process = await asyncio.create_subprocess_exec(str(binary), *command,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            processes.append(process)
            output, error = await asyncio.wait_for(process.communicate(), 20)
            if process.returncode:
                raise RuntimeError(f'{command[0]} failed: {error.decode()}')
            return output

        async def until_node(predicate):
            deadline = time.monotonic() + 12
            while time.monotonic() < deadline:
                node = next(n for n in await api('GET', '/nodes') if n['id'] == node_id)
                if predicate(node):
                    return node
                await asyncio.sleep(.05)
            raise RuntimeError('node did not complete ownership/recovery/application')

        async def usage_equals(expected):
            deadline = time.monotonic() + 8
            while True:
                rows = await api('GET', '/usage')
                amount = sum(row['upload_bytes'] + row['download_bytes'] for row in rows)
                if amount == expected:
                    return amount
                if amount > expected or time.monotonic() >= deadline:
                    raise RuntimeError(f'controller usage {amount} != {expected}')
                await asyncio.sleep(.05)

        async def tcp_roundtrip(length):
            payload = bytes(i % 251 for i in range(length))
            writer.write(payload)
            await writer.drain()
            if await asyncio.wait_for(reader.readexactly(length), 2) != payload:
                raise RuntimeError('TCP payload changed')

        async def udp_roundtrip(length):
            payload = bytes(i % 241 for i in range(length))
            udp_transport.sendto(payload)
            if await asyncio.wait_for(udp.queue.get(), 2) != payload:
                raise RuntimeError('UDP payload changed')

        async def local_usage():
            rows = json.loads(await cli('usage', '--database', str(agent_state / 'agent.sqlite')))
            return sum(row['upload_bytes'] + row['download_bytes'] for row in rows)

        async def update_node(settings, expected=None, name=None):
            node = next(n for n in await api('GET', '/nodes') if n['id'] == node_id)
            return await api('PUT', f'/nodes/{node_id}/profile', {
                'expected_revision': node['profile']['revision'] if expected is None else expected,
                'name': node['name'] if name is None else name, 'settings': settings})

        async def expect_status(method, path, body, status):
            try:
                await api(method, path, body)
            except HTTPError as error:
                if error.code == status:
                    return
                raise
            raise RuntimeError(f'{method} {path} unexpectedly succeeded; expected {status}')

        async def assert_closed():
            try:
                data = await asyncio.wait_for(reader.read(1), 1)
            except ConnectionResetError:
                data = b''
            if data:
                raise RuntimeError('existing TCP stream was not closed')
            try:
                _, unexpected = await asyncio.open_connection('127.0.0.1', port)
            except OSError:
                pass
            else:
                unexpected.close()
                await unexpected.wait_closed()
                raise RuntimeError('TCP listener stayed open')
            udp_transport.sendto(b'stopped')
            try:
                result = await asyncio.wait_for(udp.queue.get(), .25)
            except TimeoutError:
                closed_udp_observations.append('timeout')
                return
            if isinstance(result, OSError):
                closed_udp_observations.append(type(result).__name__)
                return
            raise RuntimeError(f'UDP forwarding stayed active: {result!r}')

        try:
            version = (await cli('--version')).decode().strip()
            controller_args = ('server', '--listen', f'127.0.0.1:{control_port}', '--state', str(control_state))
            controller = await launch('controller-original', *controller_args)
            await ready(control_port, controller)
            session = await api('POST', '/auth/login', {'username': 'admin',
                'password': (control_state / 'admin-password.secret').read_text().strip()})
            token = session['token']
            budget = await api('POST', '/budgets', {'scope': 'user', 'scope_id': session['user']['id'],
                'name': 'node lifecycle shared quota', 'limit_bytes': 8192, 'quantum_bytes': 4096})
            settings = {'kinds': ['ingress', 'relay'], 'group': 'asia', 'tags': ['premium', 'Taipei'],
                'notes': 'rack B\noperator inventory', 'enabled': True, 'expires_at_ms': None,
                'cost': {'currency': 'USD', 'amount_micros': 12500123, 'period': 'monthly'}}
            created = await api('POST', '/nodes', {'name': 'managed-entry',
                'lease_policy': {'ttl_ms': 5000}, 'settings': settings})
            node_id = created['node']['id']
            second = (await api('POST', '/nodes', {'name': 'standby-inventory'}))['node']
            filtered = await api('GET', '/nodes?kind=ingress&group=asia&tag=premium&q=RACK')
            if [n['id'] for n in filtered] != [node_id]:
                raise RuntimeError('inventory filter did not match the managed node')
            config = await api('PUT', f'/nodes/{node_id}/config', {'expected_revision': 0, 'rules': [{
                'id': 'lifecycle-both', 'tenant_id': 'default', 'owner_id': session['user']['id'],
                'name': 'lifecycle', 'listen': f'127.0.0.1:{port}', 'protocol': 'both',
                'targets': [{'address': f'127.0.0.1:{target}', 'weight': 1}],
                'connect_timeout_ms': 1000, 'meter_epoch': 'lifecycle-period'}]})
            if config['rules'][0]['budget_ids'] != [budget['id']]:
                raise RuntimeError('shared budget was not bound to the rule')
            enrollment = scratch / 'enrollment.secret'
            enrollment.write_text(created['enrollment_token'])
            enrollment.chmod(0o600)
            agent_args = ('agent', '--controller', origin, '--node-id', node_id,
                '--state', str(agent_state), '--poll-seconds', '1')
            first = await launch('agent-first', *agent_args, '--enrollment-token-file', str(enrollment))
            await until_node(lambda n: n['applied_revision'] == 1)
            backup = scratch / 'controller-before-edits.sqlite'
            await cli('backup', '--database', str(control_state / 'controller.sqlite'), '--output', str(backup))
            reader, writer = await asyncio.open_connection('127.0.0.1', port)
            await tcp_roundtrip(128)
            await udp_roundtrip(32)
            await usage_equals(320)
            settings['notes'] = 'metadata changed while one TCP stream remains open'
            settings['group'] = 'metadata-only'
            edited = await update_node(settings, name='managed-renamed')
            await tcp_roundtrip(64)
            await usage_equals(448)
            if (await api('GET', f'/nodes/{node_id}/config'))['revision'] != 1:
                raise RuntimeError('profile editing republished the forwarding configuration')
            await expect_status('PUT', f'/nodes/{node_id}/profile', {
                'expected_revision': 1, 'name': 'stale-writer', 'settings': settings}, 409)
            settings['group'] = 'bulk-group'
            second_settings = second['profile']['settings']
            second_settings['group'] = 'bulk-group'
            batch = {'updates': [
                {'node_id': node_id, 'update': {'expected_revision': edited['profile']['revision'], 'name': edited['name'], 'settings': settings}},
                {'node_id': second['id'], 'update': {'expected_revision': 0, 'name': second['name'], 'settings': second_settings}}]}
            await expect_status('POST', '/nodes/profiles', batch, 409)
            if (await until_node(lambda n: True))['profile']['settings']['group'] != 'metadata-only':
                raise RuntimeError('failed batch partially changed the first node')
            batch['updates'][1]['update']['expected_revision'] = 1
            receipts = await api('POST', '/nodes/profiles', batch)
            if len(receipts) != 2 or len(await api('GET', '/nodes?group=bulk-group')) != 2:
                raise RuntimeError('bulk save did not return both node results')
            settings['enabled'] = False
            paused = await update_node(settings)
            pause_start = time.monotonic()
            if await asyncio.wait_for(first.wait(), 8) == 0:
                raise RuntimeError('paused Agent did not exit through its lease-loss path')
            pause_seconds = time.monotonic() - pause_start
            await assert_closed()
            paused_node = await until_node(lambda n: not n['lease']['active'])
            paused_budget = (await api('GET', '/budgets'))['budgets'][0]
            if paused_node['lifecycle'] != 'disabled' or (paused_budget['consumed_bytes'], paused_budget['committed_bytes']) != (448, 448):
                raise RuntimeError('pause did not settle the confirmed usage exactly')
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass
            settings['enabled'] = True
            expires = int(time.time() * 1000) + 7000
            settings['expires_at_ms'] = expires
            await update_node(settings)
            expiring = await launch('agent-expiring', *agent_args)
            await until_node(lambda n: n['lease']['generation'] == 2 and n['applied_revision'] == 1)
            reader, writer = await asyncio.open_connection('127.0.0.1', port)
            await tcp_roundtrip(128)
            await udp_roundtrip(32)
            await usage_equals(768)
            capped = await until_node(lambda n: 0 < expires - int(time.time() * 1000) < 4000
                and abs(n['lease']['remaining_ms'] - (expires - int(time.time() * 1000))) < 150)
            await stop(controller)
            await tcp_roundtrip(64)
            await udp_roundtrip(16)
            stop_deadline = time.monotonic() + 6
            while True:
                try:
                    _, check = await asyncio.open_connection('127.0.0.1', port)
                except OSError:
                    break
                check.close()
                await check.wait_closed()
                if time.monotonic() >= stop_deadline:
                    raise RuntimeError('expiry failed to close its listener')
                await asyncio.sleep(.02)
            closed_at = int(time.time() * 1000)
            if closed_at > expires + 250:
                raise RuntimeError('listener remained open beyond configured expiry')
            await assert_closed()
            if await asyncio.wait_for(expiring.wait(), 5) == 0:
                raise RuntimeError('expired Agent unexpectedly exited without lease loss')
            durable_before_recovery = await local_usage()
            if durable_before_recovery != 928:
                raise RuntimeError('offline expiry payload was not durably accounted')
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass
            await asyncio.sleep(max(0, (expires - int(time.time() * 1000)) / 1000) + .02)
            controller = await launch('controller-restarted', *controller_args)
            await ready(control_port, controller)
            if (await until_node(lambda n: True))['lifecycle'] != 'expired':
                raise RuntimeError('controller restart forgot expiry')
            failed = await launch('agent-expired-restart', *agent_args)
            if await asyncio.wait_for(failed.wait(), 5) == 0:
                raise RuntimeError('expired node restart was permitted')
            if '410' not in (scratch / 'agent-expired-restart.log').read_text():
                raise RuntimeError('expired restart did not report the expiry reason')
            settings['expires_at_ms'] = None
            await update_node(settings)
            resumed_start = time.monotonic()
            resumed = await launch('agent-extended', *agent_args)
            recovered = await until_node(lambda n: n['lease']['generation'] == 3 and n['applied_revision'] == 1)
            resumed_seconds = time.monotonic() - resumed_start
            if not recovered['stats'].get('budget_recovery'):
                raise RuntimeError('extended node did not validate its retained reservations')
            await usage_equals(928)
            reader, writer = await asyncio.open_connection('127.0.0.1', port)
            await tcp_roundtrip(96)
            await udp_roundtrip(48)
            await stop(resumed)
            await usage_equals(1216)
            final_budget = (await api('GET', '/budgets'))['budgets'][0]
            local = await local_usage()
            if (local, final_budget['consumed_bytes'], final_budget['committed_bytes']) != (1216, 1216, 1216):
                raise RuntimeError('final lifecycle ledgers or credit return differ')
            expected_profiles = {n['id']: {'name': n['name'], 'profile': n['profile'], 'desired_revision': n['desired_revision']} for n in await api('GET', '/nodes')}
            if expected_profiles[node_id]['profile']['settings'] != settings:
                raise RuntimeError('node settings changed during lifecycle transitions')
            await stop(controller)
            restored_state = scratch / 'restored-control'
            restore = json.loads(await cli('restore', '--backup', str(backup),
                '--recovery-log', str(control_state / 'recovery.log'), '--output', str(restored_state)))
            controller = await launch('controller-restored', 'server', '--listen', f'127.0.0.1:{control_port}', '--state', str(restored_state))
            await ready(control_port, controller)
            actual_profiles = {n['id']: {'name': n['name'], 'profile': n['profile'], 'desired_revision': n['desired_revision']} for n in await api('GET', '/nodes')}
            if actual_profiles != expected_profiles:
                raise RuntimeError('journal restoration changed node inventory or lifecycle settings')
            await usage_equals(1216)
            await stop(controller)
            if any(process.returncode is None for process in processes):
                raise RuntimeError('fixture left a child process running')
            return {'at_utc': datetime.now(timezone.utc).isoformat(), 'version': version,
                'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(), 'platform': platform.platform(),
                'inventory': {'nodes': 2, 'filters_matched': True, 'cost_micros': settings['cost']['amount_micros'],
                    'same_tcp_connection_after_metadata_edit': True, 'configuration_revision_unchanged': 1,
                    'stale_edit_status': 409, 'batch_conflict_status': 409, 'batch_rollback_verified': True,
                    'batch_receipts': [{'node_id': r['node_id'], 'revision': r['profile']['revision']} for r in receipts]},
                'pause': {'agent_exit_code': first.returncode, 'seconds_until_exit': pause_seconds,
                    'tcp_and_udp_closed': True, 'consumed_and_committed_bytes': 448, 'profile_revision': paused['profile']['revision']},
                'expiry': {'expires_at_ms': expires, 'listener_closed_at_ms': closed_at,
                    'closed_before_expiry_ms': expires - closed_at, 'last_capped_lease_remaining_ms': capped['lease']['remaining_ms'],
                    'controller_was_offline': True, 'expired_restart_exit_code': failed.returncode,
                    'expired_restart_http_status': 410, 'durable_bytes_before_recovery': durable_before_recovery,
                    'unreported_bytes_recovered': 160, 'reactivation_wait_seconds': resumed_seconds,
                    'generation_after_extension': recovered['lease']['generation']},
                'ledger': {'expected_bytes': 1216, 'agent_bytes': local, 'controller_bytes': 1216,
                    'budget_consumed_bytes': final_budget['consumed_bytes'], 'budget_committed_bytes': final_budget['committed_bytes'], 'exact_match': True},
                'restore': restore, 'profiles_after_restore': list(actual_profiles.values()),
                'udp_stop_observations': closed_udp_observations,
                'all_child_processes_exited': True}
        finally:
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except OSError:
                    pass
            for process in reversed(processes):
                if process.returncode is None:
                    process.send_signal(signal.SIGTERM)
                    try:
                        await asyncio.wait_for(process.wait(), 8)
                    except TimeoutError:
                        process.kill()
                        await process.wait()
            for log in logs:
                log.close()
            udp_transport.close()
            udp_backend.close()
            backend.close()
            await backend.wait_closed()


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
