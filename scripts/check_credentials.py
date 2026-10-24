#!/usr/bin/env python3
"""Exercise real CLI credential rotation, lost replies, SIGKILL and log recovery.

The temporary loopback proxy only injects failures into the rotation endpoint.
It never logs credentials or includes them in the output report.
"""
import argparse
import asyncio
import hashlib
import json
import platform
import sqlite3
import tempfile
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, ProxyHandler, build_opener

from bench_budget import free_port, ready, stop
from bench_loopback import DatagramClient, DatagramEcho, echo


async def run(args):
    binary = args.binary.resolve()
    processes, logs, writers, retired = [], [], [], []
    token = None
    mode = {'value': None, 'calls': 0}
    loop = asyncio.get_running_loop()
    backend = await asyncio.start_server(echo, '127.0.0.1', 0)
    target = backend.sockets[0].getsockname()[1]
    udp_backend, _ = await loop.create_datagram_endpoint(DatagramEcho, local_addr=('127.0.0.1', target))
    with tempfile.TemporaryDirectory(prefix='relay-credentials-') as temporary:
        scratch = Path(temporary)
        control_port, port = free_port(), free_port()
        origin = f'http://127.0.0.1:{control_port}'
        control_state, agent_state = scratch / 'control', scratch / 'agent'

        class Proxy(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def forward(self):
                length = int(self.headers.get('Content-Length', '0'))
                if length > 2 * 1024 * 1024:
                    self.send_error(413)
                    return
                body = self.rfile.read(length) if length else None
                inject = mode['value'] if self.path == '/api/v1/agent/credential/rotate' else None
                if inject != 'before':
                    headers = {key: value for key, value in self.headers.items()
                               if key.lower() not in ('host', 'connection', 'content-length')}
                    request = Request(origin + self.path, data=body, headers=headers, method=self.command)
                    try:
                        response = build_opener(ProxyHandler({})).open(request, timeout=5)
                    except HTTPError as error:
                        response = error
                    except OSError:
                        self.send_error(502)
                        return
                    with response:
                        status, payload = response.status, response.read()
                if inject:
                    mode['calls'] += 1
                    status, payload = 503, b'{"error":"injected rotation confirmation failure"}'
                self.send_response(status)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(payload)))
                self.send_header('Connection', 'close')
                self.end_headers()
                try:
                    self.wfile.write(payload)
                except OSError:
                    pass

            do_GET = forward
            do_POST = forward
            do_PUT = forward

        proxy = ThreadingHTTPServer(('127.0.0.1', 0), Proxy)
        thread = threading.Thread(target=proxy.serve_forever, daemon=True)
        thread.start()
        agent_origin = f'http://127.0.0.1:{proxy.server_port}'
        udp_transport, udp = await loop.create_datagram_endpoint(DatagramClient, remote_addr=('127.0.0.1', port))

        async def api(method, path, body=None, auth=None):
            def request():
                headers = {'Content-Type': 'application/json'}
                actual = token if auth is None else auth
                if actual:
                    headers['Authorization'] = f'Bearer {actual}'
                request = Request(origin + '/api/v1' + path, data=None if body is None else json.dumps(body).encode(), headers=headers, method=method)
                with build_opener(ProxyHandler({})).open(request, timeout=5) as response:
                    return json.load(response)
            return await asyncio.to_thread(request)

        async def launch(name, *command):
            log = (scratch / f'{name}.log').open('wb')
            logs.append(log)
            process = await asyncio.create_subprocess_exec(str(binary), *command, stdout=log, stderr=log)
            processes.append(process)
            return process

        async def cli(*command):
            process = await asyncio.create_subprocess_exec(str(binary), *command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            processes.append(process)
            output, error = await asyncio.wait_for(process.communicate(), 20)
            if process.returncode:
                raise RuntimeError(f'{command[0]} failed: {error.decode()}')
            return output

        def credential():
            with sqlite3.connect(f'file:{agent_state / "agent.sqlite"}?mode=ro', uri=True) as conn:
                row = conn.execute("SELECT value FROM metadata WHERE key='agent_credential'").fetchone()
                return json.loads(row[0]) if row else {}

        async def wait_for(predicate, label, seconds=15):
            deadline = time.monotonic() + seconds
            while time.monotonic() < deadline:
                result = await predicate()
                if result:
                    return result
                await asyncio.sleep(.05)
            raise RuntimeError(f'timeout: {label}')

        async def node_ready(generation):
            nodes = await api('GET', '/nodes')
            node = next(n for n in nodes if n['id'] == node_id)
            return node if node['applied_revision'] == 1 and node['lease']['generation'] == generation and node['lease']['active'] else None

        async def local_revision(revision):
            current = credential()
            return current if current.get('revision') == revision and not current.get('pending_rotation') else None

        async def usage_equals(expected):
            async def check():
                rows = await api('GET', '/usage')
                amount = sum(r['upload_bytes'] + r['download_bytes'] for r in rows)
                if amount > expected:
                    raise RuntimeError('usage exceeded the known payload')
                return amount == expected
            await wait_for(check, 'controller usage')

        async def connect():
            reader, writer = await asyncio.open_connection('127.0.0.1', port)
            writers.append(writer)
            return reader, writer

        async def exchange(pair, tcp_length, udp_length):
            reader, writer = pair
            payload = bytes(i % 251 for i in range(tcp_length))
            writer.write(payload)
            await writer.drain()
            if await asyncio.wait_for(reader.readexactly(tcp_length), 3) != payload:
                raise RuntimeError('TCP payload changed')
            payload = bytes(i % 241 for i in range(udp_length))
            udp_transport.sendto(payload)
            if await asyncio.wait_for(udp.queue.get(), 3) != payload:
                raise RuntimeError('UDP payload changed')

        async def old_rejected(old):
            for path, body in [('lease', {'run_id': 'retired-copy', 'token': 'a' * 64}), ('reconcile', {'ledger_id': None, 'after': None, 'expected_revision': None})]:
                try:
                    await api('POST', '/agent/' + path, body, auth=old)
                except HTTPError as error:
                    if error.code == 401:
                        continue
                    raise
                raise RuntimeError('retired credential was accepted')

        try:
            version = (await cli('--version')).decode().strip()
            controller_args = ('server', '--listen', f'127.0.0.1:{control_port}', '--state', str(control_state))
            controller = await launch('controller-original', *controller_args)
            await ready(control_port, controller)
            session = await api('POST', '/auth/login', {'username': 'admin', 'password': (control_state / 'admin-password.secret').read_text().strip()})
            token = session['token']
            await api('POST', '/budgets', {'scope': 'user', 'scope_id': session['user']['id'], 'name': 'credential acceptance', 'limit_bytes': 8192, 'quantum_bytes': 4096})
            created = await api('POST', '/nodes', {'name': 'rotation-node', 'lease_policy': {'ttl_ms': 5000}})
            node_id = created['node']['id']
            await api('PUT', f'/nodes/{node_id}/config', {'expected_revision': 0, 'rules': [{
                'id': 'rotate-both', 'tenant_id': 'default', 'owner_id': session['user']['id'], 'name': 'rotation',
                'listen': f'127.0.0.1:{port}', 'protocol': 'both', 'targets': [{'address': f'127.0.0.1:{target}', 'weight': 1}],
                'connect_timeout_ms': 1000, 'meter_epoch': 'rotation-period'}]})
            enrollment = scratch / 'enrollment.secret'
            enrollment.write_text(created['enrollment_token'])
            enrollment.chmod(0o600)
            agent_args = ('agent', '--controller', agent_origin, '--node-id', node_id, '--state', str(agent_state), '--poll-seconds', '1')
            running = await launch('agent-original', *agent_args, '--enrollment-token-file', str(enrollment))
            initial = await wait_for(lambda: node_ready(1), 'initial Agent')
            backup = scratch / 'before-rotations.sqlite'
            await cli('backup', '--database', str(control_state / 'controller.sqlite'), '--output', str(backup))
            pair = await connect()
            await exchange(pair, 128, 32)
            await usage_equals(320)
            retired.append(credential()['token'])
            await api('POST', f'/nodes/{node_id}/credential/rotate', {'expected_revision': 1})
            await wait_for(lambda: local_revision(2), 'online rotation')
            await old_rejected(retired[-1])
            await exchange(pair, 64, 16)
            await usage_equals(480)
            await asyncio.sleep(2)
            online = await node_ready(1)
            if not online or online['lease']['holder_run_id'] != initial['lease']['holder_run_id'] or running.returncode is not None:
                raise RuntimeError('online rotation interrupted node ownership')
            crashes = []
            for index, failure in enumerate(('before', 'after')):
                revision = index + 2
                mode.update(value=failure, calls=0)
                retired.append(credential()['token'])
                requested = await api('POST', f'/nodes/{node_id}/credential/rotate', {'expected_revision': revision})
                async def injected():
                    current = credential()
                    return current if mode['calls'] and current.get('pending_rotation') else None
                durable = await wait_for(injected, 'durable transition and injected failure')
                candidate = durable['pending_rotation']['token']
                if durable['pending_rotation']['request']['id'] != requested['pending']['id']:
                    raise RuntimeError('pending credential belongs to another task')
                state = await api('GET', f'/nodes/{node_id}/credential')
                expected = revision + int(failure == 'after')
                if state['revision'] != expected or durable['revision'] != revision:
                    raise RuntimeError('injection missed the intended commit boundary')
                if failure == 'before':
                    await exchange(pair, 32, 16)
                    await usage_equals(576)
                running.kill()
                exit_code = await asyncio.wait_for(running.wait(), 5)
                pair[1].close()
                mode['value'] = None
                began = time.monotonic()
                running = await launch(f'agent-resume-{failure}', *agent_args)
                await wait_for(lambda: node_ready(index + 2), 'recovered Agent lease')
                accepted = await wait_for(lambda: local_revision(revision + 1), 'recovered credential')
                if accepted['token'] != candidate:
                    raise RuntimeError('restart generated a replacement instead of recovering the durable candidate')
                await old_rejected(retired[-1])
                pair = await connect()
                await exchange(pair, 32 if failure == 'before' else 64, 16 if failure == 'before' else 32)
                await usage_equals(672 if failure == 'before' else 864)
                crashes.append({'boundary': failure + '_controller_commit', 'terminated_exit_code': exit_code,
                    'controller_revision_at_kill': state['revision'], 'local_revision_at_kill': durable['revision'],
                    'recovered_revision': accepted['revision'], 'same_durable_candidate': True,
                    'recovery_seconds': time.monotonic() - began})
            pair[1].close()
            await stop(running)
            retired.append(credential()['token'])
            await api('POST', f'/nodes/{node_id}/credential/rotate', {'expected_revision': 4})
            queued = await api('GET', f'/nodes/{node_id}/credential')
            if queued['revision'] != 4 or not queued['pending']:
                raise RuntimeError('offline task did not remain queued')
            running = await launch('agent-offline-queued', *agent_args)
            await wait_for(lambda: node_ready(4), 'offline Agent return')
            await wait_for(lambda: local_revision(5), 'offline queued rotation')
            pair = await connect()
            await exchange(pair, 16, 8)
            await usage_equals(912)
            pair[1].close()
            await stop(running)
            completed = await api('GET', f'/nodes/{node_id}/credential')
            await stop(controller)
            restored = scratch / 'restored-controller'
            restore = json.loads(await cli('restore', '--backup', str(backup), '--recovery-log', str(control_state / 'recovery.log'), '--output', str(restored)))
            controller = await launch('controller-restored', 'server', '--listen', f'127.0.0.1:{control_port}', '--state', str(restored))
            await ready(control_port, controller)
            if await api('GET', f'/nodes/{node_id}/credential') != completed:
                raise RuntimeError('restored credential task history changed')
            for old in retired:
                await old_rejected(old)
            running = await launch('agent-after-controller-restore', *agent_args)
            node = await wait_for(lambda: node_ready(5), 'restored controller ownership')
            pair = await connect()
            await exchange(pair, 32, 8)
            pair[1].close()
            await stop(running)
            await usage_equals(992)
            budget = (await api('GET', '/budgets'))['budgets'][0]
            local_usage = json.loads(await cli('usage', '--database', str(agent_state / 'agent.sqlite')))
            admitted = sum(r['upload_bytes'] + r['download_bytes'] for r in local_usage)
            if admitted != 992 or budget['consumed_bytes'] != 992 or budget['committed_bytes'] != 992:
                raise RuntimeError('final local/controller/budget accounting differs')
            if node['desired_revision'] != 1 or credential()['revision'] != 5:
                raise RuntimeError('rotation altered forwarding revision or lost credential progress')
            await stop(controller)
            report = {'version': version, 'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
                'at_utc': datetime.now(timezone.utc).isoformat(), 'platform': platform.platform(),
                'online': {'same_tcp_connection': True, 'udp_verified': True, 'same_lease_generation': 1, 'configuration_revision': 1},
                'forced_exit_recovery': crashes, 'offline_task_completed_revision': 5,
                'retired_credentials_rejected_after_restore': len(retired), 'restore': restore,
                'final_lease_generation': node['lease']['generation'],
                'ledger': {'agent': admitted, 'controller': 992, 'budget_consumed': budget['consumed_bytes'], 'budget_committed': budget['committed_bytes']},
                'scope': 'One macOS loopback host, real CLI processes, temporary fault-injection proxy; no Linux/WAN or compromise-replacement claim.'}
            args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
            print(json.dumps(report, ensure_ascii=False, indent=2))
        finally:
            for writer in writers:
                writer.close()
            for process in reversed(processes):
                if process.returncode is None:
                    await stop(process)
            for log in logs:
                log.close()
            udp_transport.close()
            await asyncio.to_thread(proxy.shutdown)
            proxy.server_close()
            thread.join(timeout=5)
            if thread.is_alive():
                raise RuntimeError('temporary proxy did not stop')
            backend.close()
            await backend.wait_closed()
            udp_backend.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=Path('target/release/relay'))
    parser.add_argument('--output', type=Path, default=Path('docs/credentials-smoke.json'))
    asyncio.run(run(parser.parse_args()))
