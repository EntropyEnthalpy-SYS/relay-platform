#!/usr/bin/env python3
"""Exercise signed deployment CLI, SIGKILL recovery and real staged processes.

This never installs system services. Generated wrappers run as the current user
inside a temporary filesystem; native systemd/OpenRC execution needs Linux.
"""
import argparse
import asyncio
import errno
import hashlib
import json
import platform
from pathlib import Path
import signal
import sys
import tempfile
import time
from datetime import datetime, timezone
from urllib.request import Request, ProxyHandler, build_opener

from bench_budget import free_port, ready, stop
from bench_loopback import echo, DatagramEcho, DatagramClient
from deployment import bundle
from deployment.install import Layout


async def run(args):
    binary = args.binary.resolve()
    tool = Path(__file__).with_name('relay_deploy.py').resolve()
    loop = asyncio.get_running_loop()
    for _ in range(100):
        backend = await asyncio.start_server(echo, '127.0.0.1', 0)
        target = backend.sockets[0].getsockname()[1]
        try:
            udp_backend, _ = await loop.create_datagram_endpoint(DatagramEcho, local_addr=('127.0.0.1', target))
            break
        except OSError as error:
            backend.close(); await backend.wait_closed()
            if error.errno != errno.EADDRINUSE:
                raise
    else:
        raise RuntimeError('no shared TCP/UDP echo port available')
    processes, logs = [], []
    session = None
    with tempfile.TemporaryDirectory(prefix='relay-deployment-cli-') as temporary:
        scratch = Path(temporary).resolve()
        root = scratch / 'staged'
        controller_layout = Layout(root, 'controller', 'systemd')
        agent_layout = Layout(root, 'agent', 'openrc')
        port1, port2, forwarding = free_port(), free_port(), free_port()
        origin = f'http://127.0.0.1:{port1}'
        udp_transport, udp = await loop.create_datagram_endpoint(DatagramClient, remote_addr=('127.0.0.1', forwarding))

        async def command(program, *arguments, expected=0):
            process = await asyncio.create_subprocess_exec(str(program), *map(str, arguments), stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            processes.append(process)
            output, error = await asyncio.wait_for(process.communicate(), 90)
            allowed = expected if isinstance(expected, tuple) else (expected,)
            if process.returncode not in allowed:
                raise RuntimeError(f'command returned {process.returncode}, expected {expected}: {error.decode()[:1000]}')
            return output

        async def deploy_cli(*arguments, expected=0):
            output = await command(sys.executable, tool, *arguments, expected=expected)
            return json.loads(output) if output.strip() else None

        async def role_cli(action, role, *arguments):
            manager = 'systemd' if role == 'controller' else 'openrc'
            return await deploy_cli(action, '--root', root, '--role', role, '--manager', manager, *arguments)

        async def launch(name, program):
            log = (scratch / f'{name}.log').open('wb'); logs.append(log)
            process = await asyncio.create_subprocess_exec(str(program), stdout=log, stderr=log)
            processes.append(process)
            return process

        async def api(method, path, body=None):
            def request():
                headers = {'Content-Type': 'application/json'}
                if session:
                    headers['Authorization'] = f'Bearer {session}'
                value = Request(origin + '/api/v1' + path, data=None if body is None else json.dumps(body).encode(), headers=headers, method=method)
                with build_opener(ProxyHandler({})).open(value, timeout=5) as reply:
                    return json.load(reply)
            return await asyncio.to_thread(request)

        async def wait_node(generation):
            until = time.monotonic() + 20
            while time.monotonic() < until:
                node = next(row for row in await api('GET', '/nodes') if row['id'] == node_id)
                if node['applied_revision'] == 1 and node['lease']['generation'] == generation and node['lease']['active']:
                    return node
                await asyncio.sleep(.05)
            raise RuntimeError('Agent did not acquire its expected lease and configuration')

        async def exchange(tcp_bytes, udp_bytes):
            reader, writer = await asyncio.open_connection('127.0.0.1', forwarding)
            try:
                payload = b't' * tcp_bytes
                writer.write(payload); await writer.drain()
                if await asyncio.wait_for(reader.readexactly(tcp_bytes), 3) != payload:
                    raise RuntimeError('TCP payload changed')
            finally:
                writer.close(); await writer.wait_closed()
            payload = b'u' * udp_bytes; udp_transport.sendto(payload)
            if await asyncio.wait_for(udp.queue.get(), 3) != payload:
                raise RuntimeError('UDP payload changed')

        def state_hashes(directory):
            return {p.relative_to(directory).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                    for p in directory.rglob('*') if p.is_file()}

        try:
            version = (await command(binary, '--version')).decode().strip()
            info = json.loads(await command(binary, 'build-info'))
            keys = await deploy_cli('keygen', '--directory', scratch / 'test-only-signer')
            archives = []
            for revision in (1, 2):
                path = scratch / f'fixture-{revision}.tar.gz'
                # Fixture labels deliberately are not claims about a published source commit.
                await deploy_cli('pack', '--binary', binary, '--signing-key', keys['private_key'],
                    '--source-revision', str(revision) * 40, '--output', path)
                checked = await deploy_cli('verify', '--bundle', path, '--trusted-key', keys['public_key'])
                assert checked['verified'] and not checked['payload_executed']
                archives.append(path)
            native = await deploy_cli('preflight', '--role', 'controller', '--manager', 'systemd', expected=(0, 2))
            assert not native['changes_system']
            configuration = scratch / 'controller.json'
            configuration.write_text(json.dumps({'listen': f'127.0.0.1:{port1}'}))
            first = await role_cli('install', 'controller', '--bundle', archives[0], '--trusted-key', keys['public_key'], '--config', configuration)
            assert first['staged'] and first['service_state'] == 'staged'
            controller = await launch('controller-original', controller_layout.current / 'run')
            await ready(port1, controller)
            login = await api('POST', '/auth/login', {'username': 'admin', 'password': (controller_layout.state / 'admin-password.secret').read_text().strip()})
            session = login['token']
            await api('POST', '/budgets', {'scope': 'user', 'scope_id': login['user']['id'], 'name': 'deployment-test', 'limit_bytes': 4096, 'quantum_bytes': 1024})
            created = await api('POST', '/nodes', {'name': 'deployed-agent', 'lease_policy': {'ttl_ms': 5000}})
            node_id = created['node']['id']
            await api('PUT', f'/nodes/{node_id}/config', {'expected_revision': 0, 'rules': [{
                'id': 'deployment-both', 'tenant_id': 'default', 'owner_id': login['user']['id'], 'name': 'deployment',
                'listen': f'127.0.0.1:{forwarding}', 'protocol': 'both', 'targets': [{'address': f'127.0.0.1:{target}', 'weight': 1}],
                'connect_timeout_ms': 1000, 'meter_epoch': 'deployment-period'}]})
            token = scratch / 'enrollment.secret'; token.write_text(created['enrollment_token']); token.chmod(0o600)
            agent_config = scratch / 'agent.json'
            agent_settings = {'controller': origin, 'node_id': node_id, 'poll_seconds': 1}
            agent_config.write_text(json.dumps(agent_settings))
            first_agent = await role_cli('install', 'agent', '--bundle', archives[0], '--trusted-key', keys['public_key'], '--config', agent_config, '--enrollment-token-file', token)
            assert (agent_layout.config / 'enrollment.secret').stat().st_mode & 0o777 == 0o600
            await command('/bin/sh', '-n', controller_layout.current / 'run')
            await command('/bin/sh', '-n', agent_layout.service_path('openrc'))
            agent = await launch('agent-original', agent_layout.current / 'run')
            await wait_node(1)
            await exchange(64, 16)
            await stop(agent); await stop(controller)
            original_controller = state_hashes(controller_layout.state)
            original_agent = state_hashes(agent_layout.state)
            configuration.write_text(json.dumps({'listen': f'127.0.0.1:{port2}'}))
            # Separate real process dies after atomic pointer selection, before its
            # installation receipt is updated. The CLI then resumes that intent.
            fault = scratch / 'interrupt-installer.py'
            fault.write_text('''import json,os,signal,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from deployment import bundle,install
def boundary(name):
    if name == "selection_durable": os.kill(os.getpid(),signal.SIGKILL)
layout=install.Layout(sys.argv[2],"controller","systemd")
install.deploy(layout,bundle.verify(sys.argv[3],sys.argv[4]),json.loads(Path(sys.argv[5]).read_text()),checkpoint=boundary)
''')
            await command(sys.executable, fault, tool.parent, root, archives[1], keys['public_key'], configuration, expected=-signal.SIGKILL)
            interrupted = await role_cli('status', 'controller')
            assert interrupted['pending'] and interrupted['current'] != first['current']
            upgraded = await role_cli('recover', 'controller')
            assert upgraded['pending'] is None and upgraded['previous'] == first['current']
            assert state_hashes(controller_layout.state) == original_controller
            controller = await launch('controller-upgraded', controller_layout.current / 'run')
            await ready(port2, controller)
            origin = f'http://127.0.0.1:{port2}'
            later = await api('POST', '/nodes', {'name': 'created-after-program-switch'})
            await stop(controller)
            updated_controller = state_hashes(controller_layout.state)
            rolled = await role_cli('rollback', 'controller')
            assert rolled['current'] == first['current'] and not rolled['runtime_state_restored']
            assert state_hashes(controller_layout.state) == updated_controller
            origin = f'http://127.0.0.1:{port1}'
            controller = await launch('controller-rolled-back', controller_layout.current / 'run')
            await ready(port1, controller)
            assert any(n['id'] == later['node']['id'] for n in await api('GET', '/nodes'))
            agent_config.write_text(json.dumps({**agent_settings, 'poll_seconds': 2}))
            second_agent = await role_cli('install', 'agent', '--bundle', archives[1], '--trusted-key', keys['public_key'], '--config', agent_config)
            assert second_agent['previous'] == first_agent['current']
            assert state_hashes(agent_layout.state) == original_agent
            rolled_agent = await role_cli('rollback', 'agent')
            assert rolled_agent['current'] == first_agent['current']
            assert state_hashes(agent_layout.state) == original_agent
            agent = await launch('agent-after-rollbacks', agent_layout.current / 'run')
            await wait_node(2)
            await exchange(32, 16)
            await stop(agent)
            rows = await api('GET', '/usage'); known = sum(row['upload_bytes'] + row['download_bytes'] for row in rows)
            budget = (await api('GET', '/budgets'))['budgets'][0]
            admitted_rows = json.loads(await command(binary, 'usage', '--database', agent_layout.state / 'agent.sqlite'))
            admitted = sum(row['upload_bytes'] + row['download_bytes'] for row in admitted_rows)
            assert known == admitted == budget['consumed_bytes'] == budget['committed_bytes'] == 256
            await stop(controller)
            final_controller, final_agent = state_hashes(controller_layout.state), state_hashes(agent_layout.state)
            removed_controller = await role_cli('remove', 'controller')
            assert removed_controller['removed'] and not removed_controller['runtime_state_deleted']
            assert (await role_cli('status', 'agent'))['installed']
            removed_agent = await role_cli('remove', 'agent')
            assert removed_agent['removed'] and not removed_agent['runtime_state_deleted']
            assert state_hashes(controller_layout.state) == final_controller
            assert state_hashes(agent_layout.state) == final_agent
            # Reinstall is allowed only from the retained ownership/compatibility
            # receipt. It must reuse the current state, not a pre-upgrade copy.
            configuration.write_text(json.dumps({'listen': f'127.0.0.1:{port1}'}))
            await role_cli('install', 'controller', '--bundle', archives[0], '--trusted-key', keys['public_key'], '--config', configuration)
            await role_cli('install', 'agent', '--bundle', archives[0], '--trusted-key', keys['public_key'], '--config', agent_config)
            assert state_hashes(controller_layout.state) == final_controller
            assert state_hashes(agent_layout.state) == final_agent
            controller = await launch('controller-reinstalled', controller_layout.current / 'run')
            await ready(port1, controller)
            assert any(n['id'] == later['node']['id'] for n in await api('GET', '/nodes'))
            agent = await launch('agent-reinstalled', agent_layout.current / 'run')
            await wait_node(3)
            await exchange(16, 16)
            await stop(agent)
            rows = await api('GET', '/usage'); known = sum(row['upload_bytes'] + row['download_bytes'] for row in rows)
            budget = (await api('GET', '/budgets'))['budgets'][0]
            admitted_rows = json.loads(await command(binary, 'usage', '--database', agent_layout.state / 'agent.sqlite'))
            admitted = sum(row['upload_bytes'] + row['download_bytes'] for row in admitted_rows)
            assert known == admitted == budget['consumed_bytes'] == budget['committed_bytes'] == 320
            await stop(controller)
            final_controller, final_agent = state_hashes(controller_layout.state), state_hashes(agent_layout.state)
            await role_cli('remove', 'controller'); await role_cli('remove', 'agent')
            assert state_hashes(controller_layout.state) == final_controller
            assert state_hashes(agent_layout.state) == final_agent
            report = {'version': version, 'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
                'at_utc': datetime.now(timezone.utc).isoformat(), 'platform': platform.platform(), 'build_info': info,
                'signed_bundles_verified': 2, 'signing': 'RSA-3072 PKCS1v1.5 with SHA-256; temporary test-only signer',
                'fixture_source_labels_are_not_release_provenance': True,
                'native_system_install_performed': False, 'staged_service_formats': ['systemd', 'openrc'],
                'native_host_preflight_ready': native['ready'],
                'generated_wrappers_executed_real_processes': True, 'controller_listen_changed_then_rolled_back': True,
                'forced_exit': {'code': -signal.SIGKILL, 'boundary': 'selection_durable', 'recovered_exact_target': True},
                'runtime_state_unchanged_by_switch_and_rollback': True,
                'record_created_after_switch_preserved_after_rollback': True,
                'original_agent_credential_and_budget_state_retained': True,
                'reinstall_from_retained_receipts_forwarded_tcp_udp': True,
                'final_lease_generation': 3, 'ledger': {'agent': admitted, 'controller': known,
                    'budget_consumed': budget['consumed_bytes'], 'budget_committed': budget['committed_bytes']},
                'removal_preserved_runtime_state_and_other_role': True,
                'scope': 'Native processes in an isolated staged filesystem; no actual Linux init service, account creation, logrotate execution, release-key custody, cross-version migration or cross-machine acceptance.'}
            args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + '\n')
            print(json.dumps(report, indent=2, ensure_ascii=False))
        finally:
            for process in reversed(processes):
                if process.returncode is None:
                    process.terminate()
                    try:
                        await asyncio.wait_for(process.wait(), 10)
                    except TimeoutError:
                        process.kill(); await process.wait()
            for log in logs:
                log.close()
            udp_transport.close(); udp_backend.close()
            backend.close(); await backend.wait_closed()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=Path('target/release/relay'))
    parser.add_argument('--output', type=Path, default=Path('docs/deployment-smoke.json'))
    asyncio.run(run(parser.parse_args()))
