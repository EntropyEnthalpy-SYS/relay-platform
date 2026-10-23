#!/usr/bin/env python3
"""Exercise the release CLI's old-backup recovery with a live TCP connection.

Starts only local temporary controller/agent/echo processes. The backup is made
before the node exists; its identity, configuration and reservations must come
from the recovery log. No external service or installed state is changed.
"""
import argparse
import asyncio
import hashlib
import json
import os
import platform
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, ProxyHandler, build_opener

from bench_budget import free_port, ready, stop
from bench_loopback import echo


async def run(args):
    binary = args.binary.resolve()
    processes, logs = [], []
    token = None
    writer = None
    echo_server = await asyncio.start_server(echo, '127.0.0.1', 0)
    target = echo_server.sockets[0].getsockname()[1]
    with tempfile.TemporaryDirectory(prefix='relay-recovery-check-') as temporary:
        scratch = Path(temporary)
        control_port = free_port()
        origin = f'http://127.0.0.1:{control_port}'
        state = scratch / 'controller'
        backup = scratch / 'controller-backup.sqlite'
        recovered = scratch / 'recovered'

        async def api(method, path, body=None):
            def request():
                headers = {'Content-Type': 'application/json'}
                if token:
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

        async def cli(*command):
            process = await asyncio.create_subprocess_exec(str(binary), *command,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            processes.append(process)
            output, error = await asyncio.wait_for(process.communicate(), 20)
            if process.returncode != 0:
                raise RuntimeError(f'CLI {command[0]} failed: {error.decode()}')
            return output

        async def usage_equals(expected):
            until = time.monotonic() + 10
            while True:
                rows = await api('GET', '/usage')
                total = sum(row['upload_bytes'] + row['download_bytes'] for row in rows)
                if total == expected:
                    return total
                if total > expected or time.monotonic() > until:
                    raise RuntimeError(f'controller usage {total} differs from expected {expected}')
                await asyncio.sleep(.05)

        async def roundtrip(length):
            payload = bytes(range(256)) * (length // 256)
            if len(payload) != length:
                raise ValueError('smoke payload must be a multiple of 256')
            writer.write(payload)
            await writer.drain()
            received = await asyncio.wait_for(reader.readexactly(length), 10)
            if received != payload:
                raise RuntimeError('recovered TCP connection changed payload bytes')

        try:
            controller = await launch('controller', 'server', '--listen', f'127.0.0.1:{control_port}', '--state', str(state))
            await ready(control_port, controller)
            session = await api('POST', '/auth/login', {
                'username': 'admin', 'password': (state / 'admin-password.secret').read_text().strip()})
            token = session['token']
            budget = await api('POST', '/budgets', {'scope': 'user', 'scope_id': session['user']['id'],
                'name': 'recovery smoke', 'limit_bytes': 1024 * 1024, 'quantum_bytes': 65536})
            await cli('backup', '--database', str(state / 'controller.sqlite'), '--output', str(backup))
            original_backup_hash = hashlib.sha256(backup.read_bytes()).hexdigest()
            node = await api('POST', '/nodes', {'name': 'created-after-backup'})
            node_id = node['node']['id']
            relay_port = free_port()
            config = await api('PUT', f'/nodes/{node_id}/config', {'expected_revision': 0, 'rules': [{
                'id': 'recover-live-tcp', 'tenant_id': 'default', 'owner_id': session['user']['id'],
                'name': 'recover-live-tcp', 'listen': f'127.0.0.1:{relay_port}', 'protocol': 'tcp',
                'targets': [{'address': f'127.0.0.1:{target}', 'weight': 1}],
                'meter_epoch': 'recovery-smoke', 'connect_timeout_ms': 5000}]})
            if config['rules'][0]['budget_ids'] != [budget['id']]:
                raise RuntimeError('controller did not bind the shared budget')
            enrollment = scratch / 'enrollment.secret'
            with os.fdopen(os.open(enrollment, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as file:
                file.write(node['enrollment_token'])
            agent_state = scratch / 'agent'
            agent = await launch('agent', 'agent', '--controller', origin, '--node-id', node_id,
                '--state', str(agent_state), '--enrollment-token-file', str(enrollment), '--poll-seconds', '1')
            await ready(relay_port, agent)
            reader, writer = await asyncio.open_connection('127.0.0.1', relay_port)
            await roundtrip(8192)
            await usage_equals(16384)
            await stop(controller)
            old_head = json.loads((state / 'recovery.log.head.json').read_text())
            await roundtrip(4096)
            source_log_hash = hashlib.sha256((state / 'recovery.log').read_bytes()).hexdigest()
            report = json.loads(await cli('restore', '--backup', str(backup),
                '--recovery-log', str(state / 'recovery.log'), '--output', str(recovered)))
            if report['restored_sequence'] != old_head['sequence'] or report['replayed_transactions'] <= 0:
                raise RuntimeError('restore did not replay the latest committed history')
            if report['budget_allocation_paused']:
                raise RuntimeError('validated recovery failed to restore the original allocation state')
            if hashlib.sha256(backup.read_bytes()).hexdigest() != original_backup_hash:
                raise RuntimeError('restore changed its source backup')
            if hashlib.sha256((state / 'recovery.log').read_bytes()).hexdigest() != source_log_hash:
                raise RuntimeError('restore changed its source recovery log')
            restored_controller = await launch('restored-controller', 'server', '--listen',
                f'127.0.0.1:{control_port}', '--state', str(recovered))
            await ready(control_port, restored_controller)
            restored_config = await api('GET', f'/nodes/{node_id}/config')
            if restored_config != config:
                raise RuntimeError('post-backup node configuration was not recovered')
            await usage_equals(24576)
            # Exceeds the old reservation and therefore proves new grants work.
            await roundtrip(131072)
            writer.close()
            await writer.wait_closed()
            writer = None
            await stop(agent)
            expected = 2 * (8192 + 4096 + 131072)
            recorded = await usage_equals(expected)
            measured = (await api('GET', '/budgets'))['budgets'][0]
            if (measured['consumed_bytes'], measured['committed_bytes']) != (expected, expected):
                raise RuntimeError('recovered budget duplicated consumption or retained unused reservations')
            local = json.loads(await cli('usage', '--database', str(agent_state / 'agent.sqlite')))
            local_total = sum(row['upload_bytes'] + row['download_bytes'] for row in local)
            if local_total != expected:
                raise RuntimeError('agent and recovered controller ledgers differ')
            status = await api('GET', '/recovery')
            if not status['enabled'] or not status['healthy'] or status['head']['journal_id'] != old_head['journal_id']:
                raise RuntimeError('recovered controller did not continue the same journal')
            await stop(restored_controller)
            return {'at_utc': datetime.now(timezone.utc).isoformat(), 'platform': platform.platform(),
                'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(), 'restore': report,
                'checks': ['CLI online backup before node creation', 'post-backup node identity and configuration recovered',
                    'old API session retained', 'same TCP connection survives controller replacement',
                    'offline consumption reconciled', 'new reservations issued after validated replay',
                    'source backup and log unchanged', 'graceful shutdown returns unused reservations',
                    'all spawned processes exited successfully'],
                'ledger': {'expected_bytes': expected, 'controller_bytes': recorded, 'agent_bytes': local_total,
                    'budget_consumed_bytes': measured['consumed_bytes'], 'budget_committed_bytes': measured['committed_bytes'],
                    'exact_match': True}, 'limits': ['local macOS loopback only', 'no power-loss or remote storage durability test']}
        finally:
            if writer:
                writer.close()
                await writer.wait_closed()
            failures = []
            for process in reversed(processes):
                try:
                    await stop(process)
                except RuntimeError as error:
                    failures.append(str(error))
            for log in logs:
                log.close()
            echo_server.close()
            await echo_server.wait_closed()
            if failures:
                raise RuntimeError('; '.join(failures))


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
