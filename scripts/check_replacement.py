#!/usr/bin/env python3
"""Exercise revoked node replacement with real CLI processes on one loopback host.

Unknown original-node usage is deliberately retained only in that node's state.
The report distinguishes known usage, observed unreported bytes and held budget.
Temporary credentials and private databases are never included in the report.
"""
import argparse
import asyncio
import errno
import hashlib
import json
import platform
import secrets
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
    loop = asyncio.get_running_loop()
    # Reserve both protocols before exposing the backend to concurrent clients.
    for _ in range(100):
        backend = await asyncio.start_server(echo, '127.0.0.1', 0)
        target = backend.sockets[0].getsockname()[1]
        try:
            udp_backend, _ = await loop.create_datagram_endpoint(DatagramEcho, local_addr=('127.0.0.1', target))
            break
        except OSError as error:
            backend.close()
            await backend.wait_closed()
            if error.errno != errno.EADDRINUSE:
                raise
    else:
        raise RuntimeError('cannot reserve a shared TCP/UDP echo port')
    processes, logs, writers, retired = [], [], [], []
    token = None
    isolated = threading.Event()
    with tempfile.TemporaryDirectory(prefix='relay-replacement-') as temporary:
        scratch = Path(temporary)
        control_port, port = free_port(), free_port()
        origin = f'http://127.0.0.1:{control_port}'
        control_state = scratch / 'control'
        original_state, replacement_state = scratch / 'original', scratch / 'replacement'
        final_state, expired_state = scratch / 'final', scratch / 'expired'

        class Proxy(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def forward(self):
                length = int(self.headers.get('Content-Length', '0'))
                if length > 2 * 1024 * 1024:
                    self.send_error(413)
                    return
                body = self.rfile.read(length) if length else None
                if isolated.is_set():
                    status, payload = 503, b'{"error":"original node isolated"}'
                else:
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
        original_origin = f'http://127.0.0.1:{proxy.server_port}'
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

        async def rejected(method, path, body, expected, auth=None):
            try:
                await api(method, path, body, auth)
            except HTTPError as error:
                if error.code == expected:
                    return
                raise RuntimeError(f'{path}: expected HTTP {expected}, got {error.code}') from None
            raise RuntimeError(f'{path}: rejected request unexpectedly succeeded')

        async def launch(name, *command):
            log = (scratch / f'{name}.log').open('wb')
            logs.append(log)
            process = await asyncio.create_subprocess_exec(str(binary), *command, stdout=log, stderr=log)
            processes.append(process)
            return process

        async def cli(*command):
            process = await asyncio.create_subprocess_exec(str(binary), *command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            processes.append(process)
            output, _ = await asyncio.wait_for(process.communicate(), 20)
            if process.returncode:
                raise RuntimeError(f'{command[0]} failed with {process.returncode}')
            return output

        def metadata(state, key):
            path = state / 'agent.sqlite'
            if not path.exists():
                return None
            with sqlite3.connect(f'file:{path}?mode=ro', uri=True) as conn:
                exists = conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='metadata'").fetchone()
                if not exists:
                    return None
                row = conn.execute('SELECT value FROM metadata WHERE key=?', (key,)).fetchone()
                return json.loads(row[0]) if row else None

        def credential(state):
            return metadata(state, 'agent_credential') or {}

        async def wait_for(predicate, label, seconds=15):
            deadline = time.monotonic() + seconds
            while time.monotonic() < deadline:
                result = await predicate()
                if result:
                    return result
                await asyncio.sleep(.05)
            raise RuntimeError(f'timeout: {label}')

        async def local_revision(state, revision):
            current = credential(state)
            return current if current.get('revision') == revision and not current.get('pending_rotation') and not current.get('pending_enrollment_token') else None

        async def node():
            return next(n for n in await api('GET', '/nodes') if n['id'] == node_id)

        async def node_ready(generation):
            value = await node()
            return value if value['applied_revision'] == 1 and value['lease']['generation'] == generation and value['lease']['active'] else None

        async def usage_equals(expected):
            async def check():
                rows = await api('GET', '/usage')
                amount = sum(r['upload_bytes'] + r['download_bytes'] for r in rows)
                if amount > expected:
                    raise RuntimeError('controller usage exceeds the known payload')
                return amount == expected
            await wait_for(check, f'controller usage {expected}')

        async def local_usage(state):
            rows = json.loads(await cli('usage', '--database', str(state / 'agent.sqlite')))
            return sum(r['upload_bytes'] + r['download_bytes'] for r in rows)

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
            stats = {key: 0 for key in ('active_tcp', 'active_udp', 'accepted_tcp', 'rejected_connections',
                'failed_connections', 'dropped_datagrams', 'forwarded_upload_bytes', 'forwarded_download_bytes')}
            proof = {'run_id': 'retired-run', 'generation': 1, 'token': 'a' * 64}
            cases = [
                ('lease', {'run_id': 'retired-run', 'token': 'a' * 64, 'generation': None}),
                ('lease/release', {'proof': proof, 'stats': stats}),
                ('reconcile', {'ledger_id': None, 'after': None, 'expected_revision': None}),
                ('sync', {'ledger_id': 'retired-ledger', 'need_config': False, 'applied_revision': 0,
                    'usage': [], 'apply_error': None, 'stats': stats, 'budget': None}),
                ('budgets/recover', {'lease': proof, 'ledger_id': 'retired-ledger', 'run_id': 'retired-run', 'claims': [], 'requests': []}),
                ('credential/rotate', {'request_id': 'retired-task', 'expected_revision': 1, 'credential': 'b' * 64, 'lease': proof}),
            ]
            for path, body in cases:
                await rejected('POST', '/agent/' + path, body, 401, auth=old)

        def revoke(revision, name):
            return {'operation_id': name, 'expected_revision': revision, 'reason': 'isolated node acceptance test'}

        def ticket(revision, name, seconds=600):
            return {'operation_id': name, 'expected_revision': revision, 'enrollment_token': secrets.token_hex(32), 'valid_for_seconds': seconds}

        async def identity(action, body):
            return await api('POST', f'/nodes/{node_id}/credential/{action}', body)

        async def agent(name, state, enrollment_token=None, controller_origin=None):
            command = ['agent', '--controller', controller_origin or origin, '--node-id', node_id,
                       '--state', str(state), '--poll-seconds', '1']
            if enrollment_token is not None:
                file = scratch / f'{name}.secret'
                file.write_text(enrollment_token)
                file.chmod(0o600)
                command += ['--enrollment-token-file', str(file)]
            return await launch(name, *command)

        try:
            version = (await cli('--version')).decode().strip()
            controller = await launch('controller', 'server', '--listen', f'127.0.0.1:{control_port}', '--state', str(control_state))
            await ready(control_port, controller)
            session = await api('POST', '/auth/login', {'username': 'admin', 'password': (control_state / 'admin-password.secret').read_text().strip()})
            token = session['token']
            await api('POST', '/budgets', {'scope': 'user', 'scope_id': session['user']['id'],
                'name': 'replacement acceptance', 'limit_bytes': 8192, 'quantum_bytes': 1024})
            created = await api('POST', '/nodes', {'name': 'replace-node', 'lease_policy': {'ttl_ms': 5000}})
            node_id = created['node']['id']
            await api('PUT', f'/nodes/{node_id}/config', {'expected_revision': 0, 'rules': [{
                'id': 'replace-both', 'tenant_id': 'default', 'owner_id': session['user']['id'], 'name': 'replacement',
                'listen': f'127.0.0.1:{port}', 'protocol': 'both', 'targets': [{'address': f'127.0.0.1:{target}', 'weight': 1}],
                'connect_timeout_ms': 1000, 'meter_epoch': 'replacement-period'}]})
            original = await agent('original', original_state, created['enrollment_token'], original_origin)
            await wait_for(lambda: node_ready(1), 'initial Agent')
            pair = await connect()
            await exchange(pair, 128, 32)
            await usage_equals(320)
            backup = scratch / 'before-revocation.sqlite'
            await cli('backup', '--database', str(control_state / 'controller.sqlite'), '--output', str(backup))
            retired.append(credential(original_state)['token'])
            isolated.set()
            await exchange(pair, 64, 16)
            if await local_usage(original_state) != 480:
                raise RuntimeError('original local usage is not durable')
            began = time.monotonic()
            first_revoke = revoke(1, 'revoke-original')
            revoked = await identity('revoke', first_revoke)
            assert revoked['phase'] == 'revoked' and revoked['revision'] == 2
            await usage_equals(320)
            budget = (await api('GET', '/budgets'))['budgets'][0]
            assert budget['consumed_bytes'] == 320 and budget['committed_bytes'] == 1024
            replacement_ticket = ticket(2, 'issue-first')
            issued = await identity('replace', replacement_ticket)
            assert issued['phase'] == 'replacement_pending' and issued['revision'] == 3
            running = await agent('replacement', replacement_state, replacement_ticket['enrollment_token'])
            await wait_for(lambda: local_revision(replacement_state, 3), 'replacement enrollment')
            waiting = await node()
            assert waiting['lease']['recovery_wait_ms'] > 0 and not waiting['lease']['active']
            assert metadata(replacement_state, 'agent_budget_run') is None
            original_exit = await asyncio.wait_for(original.wait(), 7)
            assert original_exit == 1
            stopped_seconds = time.monotonic() - began
            try:
                assert await asyncio.wait_for(pair[0].read(1), 1) == b''
            except (ConnectionResetError, BrokenPipeError):
                pass
            pair[1].close()
            await wait_for(lambda: node_ready(3), 'replacement ownership')
            takeover_seconds = time.monotonic() - began
            await old_rejected(retired[0])
            pair = await connect()
            await exchange(pair, 32, 16)
            await usage_equals(416)
            replay = await identity('revoke', first_revoke)
            assert replay['phase'] == 'active' and replay['revision'] == 3
            await exchange(pair, 32, 16)
            await usage_equals(512)
            retired.append(credential(replacement_state)['token'])
            await identity('rotate', {'expected_revision': 3})
            await wait_for(lambda: local_revision(replacement_state, 4), 'routine rotation of replaced identity')
            assert await node_ready(3)
            await old_rejected(retired[-1])
            retired.append(credential(replacement_state)['token'])
            pair[1].close()
            await stop(running)
            budget = (await api('GET', '/budgets'))['budgets'][0]
            assert budget['consumed_bytes'] == 512 and budget['committed_bytes'] == 1216
            assert await local_usage(replacement_state) == 512
            second_revoke = revoke(4, 'revoke-replacement')
            assert (await identity('revoke', second_revoke))['revision'] == 5
            expired_ticket = ticket(5, 'issue-expiring', 1)
            expiring = await identity('replace', expired_ticket)
            assert expiring['revision'] == 6
            legacy_body = {'node_id': node_id, 'enrollment_token': expired_ticket['enrollment_token'], 'credential': secrets.token_hex(32)}
            await rejected('POST', '/agent/enroll', legacy_body, 426, auth='')
            await asyncio.sleep(1.1)
            legacy_body['identity_revision_supported'] = True
            await rejected('POST', '/agent/enroll', legacy_body, 410, auth='')
            failed = await agent('expired', expired_state, expired_ticket['enrollment_token'])
            expired_exit = await asyncio.wait_for(failed.wait(), 5)
            assert expired_exit == 1
            assert '410' in (scratch / 'expired.log').read_text()
            assert (await identity('replace', expired_ticket)) == expiring
            fresh_ticket = ticket(6, 'reissue-ticket')
            fresh = await identity('replace', fresh_ticket)
            assert fresh['revision'] == 7
            await rejected('POST', '/agent/enroll', legacy_body, 401, auth='')
            running = await agent('final', final_state, fresh_ticket['enrollment_token'])
            await wait_for(lambda: node_ready(5), 'reissued ticket Agent')
            assert credential(final_state)['revision'] == 7
            pair = await connect()
            await exchange(pair, 32, 8)
            pair[1].close()
            await stop(running)
            await usage_equals(592)
            completed = await api('GET', f'/nodes/{node_id}/credential')
            await stop(controller)
            restored = scratch / 'restored-controller'
            restore = json.loads(await cli('restore', '--backup', str(backup), '--recovery-log', str(control_state / 'recovery.log'), '--output', str(restored)))
            controller = await launch('restored-controller', 'server', '--listen', f'127.0.0.1:{control_port}', '--state', str(restored))
            await ready(control_port, controller)
            assert await api('GET', f'/nodes/{node_id}/credential') == completed
            for old in retired:
                await old_rejected(old)
            for action, body in [('revoke', first_revoke), ('revoke', second_revoke),
                                 ('replace', replacement_ticket), ('replace', expired_ticket), ('replace', fresh_ticket)]:
                assert await identity(action, body) == completed
            for old_ticket in (created['enrollment_token'], replacement_ticket['enrollment_token'], expired_ticket['enrollment_token'], fresh_ticket['enrollment_token']):
                body = {'node_id': node_id, 'enrollment_token': old_ticket, 'credential': secrets.token_hex(32), 'identity_revision_supported': True}
                await rejected('POST', '/agent/enroll', body, 401, auth='')
            began_restore = time.monotonic()
            running = await agent('after-restore', final_state)
            last = await wait_for(lambda: node_ready(6), 'restored controller ownership')
            restored_seconds = time.monotonic() - began_restore
            pair = await connect()
            await exchange(pair, 16, 8)
            pair[1].close()
            await stop(running)
            await usage_equals(640)
            budget = (await api('GET', '/budgets'))['budgets'][0]
            assert budget['consumed_bytes'] == 640 and budget['committed_bytes'] == 1344
            assert await local_usage(final_state) == 640
            assert await local_usage(original_state) == 480
            assert last['desired_revision'] == 1 and credential(final_state)['revision'] == 7
            await stop(controller)
            report = {'version': version, 'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
                'at_utc': datetime.now(timezone.utc).isoformat(), 'platform': platform.platform(),
                'isolated_original': {'known_before_revocation': 320, 'durable_local_bytes': 480,
                    'observed_unreported_bytes': 160, 'exit_code': original_exit, 'tcp_closed': True,
                    'seconds_from_revocation_to_observed_exit': stopped_seconds},
                'replacement': {'fresh_private_state': True, 'enrollment_revision': 3,
                    'waited_for_prior_window': True, 'budget_run_absent_while_waiting': True,
                    'lease_generation': 3, 'seconds_from_revocation_to_ready': takeover_seconds,
                    'routine_rotation_revision': 4, 'same_lease_during_rotation': True,
                    'replayed_revocation_kept_current_identity': True, 'tcp_udp_verified': True},
                'tickets': {'legacy_client_http': 426, 'expired_ticket_http': 410, 'expired_agent_exit_code': expired_exit,
                    'retry_did_not_extend_expiry': True, 'reissue_revision': 7, 'superseded_ticket_http': 401},
                'restore': restore, 'restored_identity_and_operations_match': True,
                'retired_credentials_rejected_after_restore': len(retired), 'rejected_endpoints_per_credential': 6,
                'old_enrollment_tickets_rejected': 4, 'restore_to_ready_seconds': restored_seconds,
                'final_credential_revision': 7, 'final_lease_generation': 6, 'configuration_revision': 1,
                'ledger': {'all_observed_application_bytes': 800, 'controller_known_bytes': 640,
                    'latest_agent_known_bytes': 640, 'observed_unreported_original_bytes': 160,
                    'budget_consumed_known_bytes': budget['consumed_bytes'], 'budget_committed_bytes': budget['committed_bytes'],
                    'unknown_original_reservation_still_held': 704, 'unknown_bytes_fabricated_or_refunded': False},
                'scope': 'One loopback host; real CLI processes and original-node control isolation. No Linux/WAN, adversarial-host shutdown or per-rule quota claim; quota fencing has separate Rust integration coverage.'}
            encoded = json.dumps(report, ensure_ascii=False, indent=2) + '\n'
            for secret in retired + [credential(final_state)['token'], token, created['enrollment_token'],
                                     replacement_ticket['enrollment_token'], expired_ticket['enrollment_token'], fresh_ticket['enrollment_token']]:
                assert secret not in encoded and hashlib.sha256(secret.encode()).hexdigest() not in encoded
            args.output.write_text(encoded)
            print(encoded, end='')
        finally:
            for writer in writers:
                writer.close()
            for process in reversed(processes):
                if process.returncode is None:
                    process.terminate()
                    try:
                        await asyncio.wait_for(process.wait(), 10)
                    except TimeoutError:
                        process.kill()
                        await process.wait()
            for log in logs:
                log.close()
            udp_transport.close()
            await asyncio.to_thread(proxy.shutdown)
            proxy.server_close()
            thread.join(timeout=5)
            if thread.is_alive():
                raise RuntimeError('temporary isolation proxy did not stop')
            backend.close()
            await backend.wait_closed()
            udp_backend.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=Path('target/release/relay'))
    parser.add_argument('--output', type=Path, default=Path('docs/replacement-smoke.json'))
    asyncio.run(run(parser.parse_args()))
