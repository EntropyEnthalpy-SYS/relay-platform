#!/usr/bin/env python3
"""Exercise strict execution leases with separate release CLI processes.

Copies an active Agent database, checks exclusivity across repeated renewals,
then verifies clean takeover, exact TCP/UDP accounting and loss of control.
Only temporary local processes and loopback sockets are used.
"""
import argparse
import asyncio
import hashlib
import json
import os
import platform
import secrets
import signal
import sqlite3
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, ProxyHandler, build_opener

from bench_budget import free_port, ready, stop
from bench_loopback import DatagramClient, DatagramEcho, echo, transfer


async def run(args):
    binary = args.binary.resolve()
    processes, logs = [], []
    token = None
    expected = 0
    keeper = None
    loop = asyncio.get_running_loop()
    backend = await asyncio.start_server(echo, '127.0.0.1', 0)
    target = backend.sockets[0].getsockname()[1]
    udp_backend, _ = await loop.create_datagram_endpoint(
        DatagramEcho, local_addr=('127.0.0.1', target))
    with tempfile.TemporaryDirectory(prefix='relay-lease-check-') as temporary:
        scratch = Path(temporary)
        control_port, port = free_port(), free_port()
        origin = f'http://127.0.0.1:{control_port}'
        controller_state = scratch / 'controller'
        original, copied = scratch / 'original', scratch / 'copied'
        copied.mkdir(mode=0o700)
        udp_client, udp = await loop.create_datagram_endpoint(
            DatagramClient, remote_addr=('127.0.0.1', port))

        async def api(method, path, body=None):
            def request():
                headers = {'Content-Type': 'application/json'}
                if token:
                    headers['Authorization'] = f'Bearer {token}'
                data = None if body is None else json.dumps(body).encode()
                req = Request(origin + '/api/v1' + path, data=data, headers=headers, method=method)
                with build_opener(ProxyHandler({})).open(req, timeout=5) as response:
                    return json.load(response)
            return await asyncio.to_thread(request)

        async def launch(name, *arguments):
            log = (scratch / f'{name}.log').open('wb')
            logs.append(log)
            process = await asyncio.create_subprocess_exec(str(binary), *arguments, stdout=log, stderr=log)
            processes.append(process)
            return process

        async def cli(*arguments):
            process = await asyncio.create_subprocess_exec(
                str(binary), *arguments, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            processes.append(process)
            output, error = await asyncio.wait_for(process.communicate(), 20)
            if process.returncode:
                raise RuntimeError(f'{arguments[0]} failed: {error.decode()}')
            return output

        async def wait_node(predicate):
            deadline = time.monotonic() + 12
            while time.monotonic() < deadline:
                node = (await api('GET', '/nodes'))[0]
                if predicate(node):
                    return node
                await asyncio.sleep(.05)
            raise RuntimeError('node did not reach the required ownership/application state')

        async def usage_equals(amount):
            deadline = time.monotonic() + 8
            while True:
                rows = await api('GET', '/usage')
                value = sum(r['upload_bytes'] + r['download_bytes'] for r in rows)
                if value == amount:
                    return value
                if value > amount or time.monotonic() >= deadline:
                    raise RuntimeError(f'controller ledger {value} != expected {amount}')
                await asyncio.sleep(.05)

        async def local_usage(state):
            rows = json.loads(await cli('usage', '--database', str(state / 'agent.sqlite')))
            return sum(r['upload_bytes'] + r['download_bytes'] for r in rows)

        async def payload(tcp_bytes, udp_bytes):
            nonlocal expected
            await transfer(port, tcp_bytes)
            packet = secrets.token_bytes(udp_bytes)
            udp_client.sendto(packet)
            reply = await asyncio.wait_for(udp.queue.get(), 3)
            if reply != packet:
                raise RuntimeError('UDP payload changed during lease test')
            expected += 2 * (tcp_bytes + udp_bytes)

        try:
            version = (await cli('--version')).decode().strip()
            controller = await launch('controller', 'server', '--listen', f'127.0.0.1:{control_port}',
                                      '--state', str(controller_state))
            await ready(control_port, controller)
            session = await api('POST', '/auth/login', {'username': 'admin',
                'password': (controller_state / 'admin-password.secret').read_text().strip()})
            token = session['token']
            budget = await api('POST', '/budgets', {'scope': 'user', 'scope_id': session['user']['id'],
                'name': 'strict lease smoke', 'limit_bytes': 1024 * 1024, 'quantum_bytes': 4096})
            enrolled = await api('POST', '/nodes', {'name': 'copied-state', 'lease_policy': {'ttl_ms': 5000}})
            node_id = enrolled['node']['id']
            config = await api('PUT', f'/nodes/{node_id}/config', {'expected_revision': 0, 'rules': [{
                'id': 'leased-both', 'tenant_id': 'default', 'owner_id': session['user']['id'],
                'name': 'leased-both', 'listen': f'127.0.0.1:{port}', 'protocol': 'both',
                'targets': [{'address': f'127.0.0.1:{target}', 'weight': 1}], 'meter_epoch': 'lease-smoke'}]})
            if config['rules'][0]['budget_ids'] != [budget['id']]:
                raise RuntimeError('strict node rule was not bound to the intended budget')
            enrollment = scratch / 'enrollment.secret'
            with os.fdopen(os.open(enrollment, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as file:
                file.write(enrolled['enrollment_token'])
            common = ('agent', '--controller', origin, '--node-id', node_id, '--poll-seconds', '1')
            first = await launch('first', *common, '--state', str(original), '--enrollment-token-file', str(enrollment))
            owner = await wait_node(lambda n: n['applied_revision'] == 1 and n['lease']['active'])
            await payload(256, 1200)
            reader, keeper = await asyncio.open_connection('127.0.0.1', port)
            keeper.write(bytes(range(128)))
            await keeper.drain()
            if await asyncio.wait_for(reader.readexactly(128), 3) != bytes(range(128)):
                raise RuntimeError('persistent TCP echo changed')
            expected += 256
            await usage_equals(expected)
            snapshot_bytes = expected
            await cli('backup', '--database', str(original / 'agent.sqlite'),
                      '--output', str(copied / 'agent.sqlite'))
            second = await launch('second', *common, '--state', str(copied))
            began_wait = time.monotonic()
            for _ in range(6):
                await asyncio.sleep(1)
                await payload(256, 1200)
                current = (await api('GET', '/nodes'))[0]
                if (current['lease']['holder_run_id'], current['lease']['generation']) != (
                        owner['lease']['holder_run_id'], owner['lease']['generation']):
                    raise RuntimeError('clone displaced a renewing lease holder')
                if first.returncode is not None or second.returncode is not None:
                    raise RuntimeError('an Agent exited while clone was waiting')
            waited = time.monotonic() - began_wait
            if await local_usage(copied) != snapshot_bytes:
                raise RuntimeError('waiting clone altered its copied ledger')
            with sqlite3.connect(f'file:{copied / "agent.sqlite"}?mode=ro', uri=True) as db:
                old_run = db.execute("SELECT value FROM metadata WHERE key='agent_budget_run'").fetchone()[0]
            if old_run != owner['lease']['holder_run_id']:
                raise RuntimeError('waiting clone changed its budget run before ownership')
            await usage_equals(expected)
            keeper.close()
            await keeper.wait_closed()
            keeper = None
            handoff_start = time.monotonic()
            await stop(first)
            replacement = await wait_node(lambda n: n['lease']['generation'] == 2
                and n['lease']['active'] and n['applied_revision'] == 1)
            handoff_seconds = time.monotonic() - handoff_start
            if replacement['lease']['holder_run_id'] == owner['lease']['holder_run_id']:
                raise RuntimeError('replacement reused a previous process identity')
            for _ in range(3):
                await payload(512, 1200)
            await stop(second)
            await usage_equals(expected)
            local_clean = await local_usage(copied)
            measured = (await api('GET', '/budgets'))['budgets'][0]
            clean = await wait_node(lambda n: not n['lease']['active'])
            if local_clean != expected or (measured['consumed_bytes'], measured['committed_bytes']) != (expected, expected):
                raise RuntimeError('clean takeover did not reconcile exact usage and unused reservations')
            if clean['stats']['active_tcp'] or clean['stats']['active_udp']:
                raise RuntimeError('clean handoff left active business sessions')
            clean_result = {'generation': 2, 'clone_wait_seconds': waited,
                'clean_takeover_seconds': handoff_seconds, 'copied_snapshot_bytes': snapshot_bytes,
                'controller_bytes': expected, 'agent_bytes': local_clean,
                'budget_consumed_bytes': measured['consumed_bytes'],
                'budget_committed_bytes': measured['committed_bytes'], 'unused_reserved_bytes': 0,
                'waiting_clone_kept_original_budget_run': True, 'exact_match': True}

            # A fresh process must acquire a new lease before using this cache.
            third = await launch('third', *common, '--state', str(copied))
            await wait_node(lambda n: n['lease']['generation'] == 3 and n['applied_revision'] == 1)
            await payload(1024, 1200)
            reader, keeper = await asyncio.open_connection('127.0.0.1', port)
            keeper.write(b'live')
            await keeper.drain()
            if await asyncio.wait_for(reader.readexactly(4), 3) != b'live':
                raise RuntimeError('outage TCP connection was not established')
            expected += 8
            await usage_equals(expected)
            before_outage = (await api('GET', '/budgets'))['budgets'][0]
            outage_start = time.monotonic()
            await stop(controller)
            exit_code = await asyncio.wait_for(third.wait(), 8)
            stopped_after = time.monotonic() - outage_start
            if exit_code == 0 or 'node execution lease lost' not in (scratch / 'third.log').read_text():
                raise RuntimeError('Agent did not report lost execution lease after control failure')
            try:
                if await asyncio.wait_for(reader.read(1), 1):
                    raise RuntimeError('TCP connection returned unexpected bytes after lease loss')
            except (ConnectionResetError, BrokenPipeError):
                pass
            try:
                _, unexpected = await asyncio.open_connection('127.0.0.1', port)
            except OSError:
                pass
            else:
                unexpected.close()
                await unexpected.wait_closed()
                raise RuntimeError('TCP listener remained open after lease loss')
            udp_client.sendto(b'after-expiry')
            try:
                reply = await asyncio.wait_for(udp.queue.get(), .3)
            except TimeoutError:
                pass
            else:
                if not isinstance(reply, OSError):
                    raise RuntimeError('UDP forwarding survived lease loss')
            local_after = await local_usage(copied)
            # The usage CLI reads an Agent ledger. Read the stopped controller's
            # authoritative usage table independently, without opening it for writes.
            with sqlite3.connect(f'file:{controller_state / "controller.sqlite"}?mode=ro', uri=True) as db:
                controller_bytes = db.execute('SELECT COALESCE(SUM(upload_bytes+download_bytes),0) FROM usage').fetchone()[0]
            if local_after != expected or controller_bytes != expected:
                raise RuntimeError(f'outage ledger mismatch: expected={expected}, local={local_after}, controller={controller_bytes}')
            if not all(p.returncode is not None for p in processes):
                raise RuntimeError('a CLI child was left running')
            return {'at_utc': datetime.now(timezone.utc).isoformat(), 'version': version,
                'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
                'platform': platform.platform(), 'machine': platform.machine(), 'python': platform.python_version(),
                'scope': 'separate local release processes; one controller; copied node database; shared budget; TCP and UDP; no cross-host, physical suspend, or multi-controller claim',
                'policy': {'ttl_ms': 5000, 'strict': True}, 'clean_handoff': clean_result,
                'control_loss': {'generation': 3, 'agent_exit_code': exit_code,
                    'agent_exit_after_control_stop_seconds': stopped_after,
                    'tcp_connection_closed': True, 'tcp_listener_closed': True, 'udp_echo_stopped': True,
                    'controller_bytes_before_outage': controller_bytes, 'local_bytes_after_exit': local_after,
                    'all_outage_usage_confirmed_before_control_stop': True, 'exact_match': True,
                    'unused_reservation_before_outage_bytes': before_outage['committed_bytes'] - before_outage['consumed_bytes'],
                    'expiry_does_not_refund_unconfirmed_reservations': True},
                'all_child_processes_exited': True}
        finally:
            if keeper is not None:
                keeper.close()
                try:
                    await keeper.wait_closed()
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
            udp_client.close()
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
