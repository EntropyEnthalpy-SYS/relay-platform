#!/usr/bin/env python3
"""Verify retained-state budget recovery after real SIGKILL with Release CLIs.

The controller is stopped before new TCP/UDP payload is admitted, so that
payload exists only in the Agent ledger at the kill boundary. Both processes
then restart from their original state. No snapshot is presented as complete.
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

from bench_budget import free_port, ready, stop
from bench_loopback import DatagramClient, DatagramEcho, echo


async def run(args):
    binary = args.binary.resolve()
    processes, logs = [], []
    token = None
    writer = None
    loop = asyncio.get_running_loop()
    backend = await asyncio.start_server(echo, '127.0.0.1', 0)
    target = backend.sockets[0].getsockname()[1]
    udp_backend, _ = await loop.create_datagram_endpoint(
        DatagramEcho, local_addr=('127.0.0.1', target))
    with tempfile.TemporaryDirectory(prefix='relay-budget-recovery-') as temporary:
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
                node = (await api('GET', '/nodes'))[0]
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

        try:
            version = (await cli('--version')).decode().strip()
            controller_args = ('server', '--listen', f'127.0.0.1:{control_port}', '--state', str(control_state))
            controller = await launch('controller-before', *controller_args)
            await ready(control_port, controller)
            session = await api('POST', '/auth/login', {'username': 'admin',
                'password': (control_state / 'admin-password.secret').read_text().strip()})
            token = session['token']
            budget = await api('POST', '/budgets', {'scope': 'user', 'scope_id': session['user']['id'],
                'name': 'retained-state recovery', 'limit_bytes': 65536, 'quantum_bytes': 65536})
            enrolled = await api('POST', '/nodes', {'name': 'original-state', 'lease_policy': {'ttl_ms': 5000}})
            node_id = enrolled['node']['id']
            config = await api('PUT', f'/nodes/{node_id}/config', {'expected_revision': 0, 'rules': [{
                'id': 'budget-recovery-both', 'tenant_id': 'default', 'owner_id': session['user']['id'],
                'name': 'retained-state', 'listen': f'127.0.0.1:{port}', 'protocol': 'both',
                'targets': [{'address': f'127.0.0.1:{target}', 'weight': 1}],
                'connect_timeout_ms': 1000, 'meter_epoch': 'crash-recovery'}]})
            if config['rules'][0]['budget_ids'] != [budget['id']]:
                raise RuntimeError('rule did not bind the intended shared budget')
            enrollment = scratch / 'enrollment.secret'
            with os.fdopen(os.open(enrollment, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), 'w') as file:
                file.write(enrolled['enrollment_token'])
            agent_args = ('agent', '--controller', origin, '--node-id', node_id,
                          '--state', str(agent_state), '--poll-seconds', '1')
            first = await launch('agent-before', *agent_args, '--enrollment-token-file', str(enrollment))
            before = await until_node(lambda n: n['applied_revision'] == 1 and n['lease']['active'])
            original_run = before['lease']['holder_run_id']
            reader, writer = await asyncio.open_connection('127.0.0.1', port)
            await tcp_roundtrip(128)
            await usage_equals(256)
            held = (await api('GET', f'/budgets/{budget["id"]}/reservations'))['reservations']
            if len(held) != 1 or held[0]['allocated_bytes'] != 65536:
                raise RuntimeError('expected one fully reserved shared budget')
            await stop(controller)
            # Only existing prepaid credit is used while sync is impossible.
            started_offline = time.monotonic()
            await tcp_roundtrip(8192)
            await udp_roundtrip(4096)
            first.kill()
            await asyncio.wait_for(first.wait(), 3)
            if first.returncode != -signal.SIGKILL:
                raise RuntimeError('Agent was not killed before ordinary lease/cleanup exit')
            offline_payload_seconds = time.monotonic() - started_offline
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass
            writer = None
            durable = await local_usage()
            with sqlite3.connect(f'file:{control_state / "controller.sqlite"}?mode=ro', uri=True) as db:
                confirmed = db.execute('SELECT COALESCE(SUM(upload_bytes+download_bytes),0) FROM usage').fetchone()[0]
            if (confirmed, durable) != (256, 24832):
                raise RuntimeError(f'kill boundary was not independently established: controller={confirmed}, Agent={durable}')

            restart_began = time.monotonic()
            controller = await launch('controller-after', *controller_args)
            await ready(control_port, controller)
            unconfirmed = (await api('GET', f'/budgets/{budget["id"]}/reservations'))['reservations']
            if len(unconfirmed) != 1 or unconfirmed[0]['outstanding_bytes'] != 65280:
                raise RuntimeError('controller unexpectedly refunded or inferred unknown offline consumption')
            second = await launch('agent-after', *agent_args)
            await asyncio.sleep(.5)
            try:
                _, unexpected = await asyncio.open_connection('127.0.0.1', port)
            except OSError:
                pass
            else:
                unexpected.close()
                await unexpected.wait_closed()
                raise RuntimeError('listener activated before cold-start quarantine and recovery')
            after = await until_node(lambda n: n['lease']['generation'] == 2 and n['applied_revision'] == 1
                and n['stats'].get('budget_recovery') is not None)
            recovery_seconds = time.monotonic() - restart_began
            if after['lease']['holder_run_id'] != original_run:
                raise RuntimeError('continuous recovery did not preserve its durable budget run')
            stats = after['stats']['budget_recovery']
            if stats['validated_grants'] != 1:
                raise RuntimeError('original grant was not checked before listener activation')
            await usage_equals(durable)
            recovered_budget = (await api('GET', '/budgets'))['budgets'][0]
            if recovered_budget['consumed_bytes'] != durable:
                raise RuntimeError('offline consumption was not recovered exactly')
            reader, writer = await asyncio.open_connection('127.0.0.1', port)
            await tcp_roundtrip(16384)
            await udp_roundtrip(3968)
            await usage_equals(65536)
            writer.write(b'x')
            await writer.drain()
            try:
                extra = await asyncio.wait_for(reader.read(1), .3)
            except (TimeoutError, ConnectionResetError):
                extra = b''
            if extra:
                raise RuntimeError('recovery allowed payload past the shared limit')
            await stop(second)
            await usage_equals(65536)
            final_budget = (await api('GET', '/budgets'))['budgets'][0]
            final_local = await local_usage()
            remaining = await api('GET', f'/budgets/{budget["id"]}/reservations')
            final_node = (await api('GET', '/nodes'))[0]
            if (final_budget['consumed_bytes'], final_budget['committed_bytes'], final_local) != (65536, 65536, 65536):
                raise RuntimeError('final ledgers or unused-credit return differ')
            if remaining['reservations'] or final_node['lease']['active']:
                raise RuntimeError('normal stop left an open reservation or lease')
            if final_node['stats'].get('budget_recovery') != stats:
                raise RuntimeError('final heartbeat discarded the recovery result')
            await stop(controller)
            if any(process.returncode is None for process in processes):
                raise RuntimeError('a fixture process was left running')
            return {'at_utc': datetime.now(timezone.utc).isoformat(), 'version': version,
                'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
                'platform': platform.platform(), 'machine': platform.machine(), 'python': platform.python_version(),
                'scope': 'real SIGKILL; separate local Release processes; original Agent and controller databases; TCP/UDP; single controller; not physical power loss or snapshot completeness',
                'policy': {'ttl_ms': 5000, 'shared_limit_bytes': 65536, 'quantum_bytes': 65536},
                'kill_boundary': {'agent_exit_code': first.returncode, 'offline_payload_seconds': offline_payload_seconds,
                    'controller_confirmed_bytes': confirmed, 'agent_durable_bytes': durable,
                    'unreported_bytes': durable - confirmed, 'controller_outstanding_bytes': unconfirmed[0]['outstanding_bytes']},
                'recovery': {'seconds_from_controller_restart': recovery_seconds, 'generation': 2,
                    'same_durable_run': True, 'listeners_waited': True, 'stats': stats,
                    'consumed_bytes_after_recovery': recovered_budget['consumed_bytes'],
                    'diagnostics_preserved_after_stop': True},
                'ledger': {'expected_bytes': 65536, 'agent_bytes': final_local, 'controller_bytes': 65536,
                    'budget_consumed_bytes': final_budget['consumed_bytes'], 'budget_committed_bytes': final_budget['committed_bytes'],
                    'open_reservations_after_stop': 0, 'extra_payload_rejected': True, 'exact_match': True},
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
