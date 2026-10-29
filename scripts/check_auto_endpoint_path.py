#!/usr/bin/env python3
"""Exercise automatic endpoints through three real local Agents.

Requires a built relay, Node.js, and the optional Relay SS compatibility client.
All listeners and test traffic use loopback. Temporary credentials are removed.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

from bench_budget import free_port
from check_shadowsocks_interop import Associate, socks, wait_port


def run(args):
    repo = Path(__file__).resolve().parent.parent
    binary, client = args.binary.resolve(), args.ss_client.resolve()
    checks, children, logs = [], [], []
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    token = None
    with tempfile.TemporaryDirectory(prefix='relay-auto-path-') as directory:
        root = Path(directory)
        root.chmod(0o700)
        port = free_port()
        origin = f'http://127.0.0.1:{port}'

        def launch(name, command):
            log = (root / (name + '.log')).open('wb')
            logs.append(log)
            proc = subprocess.Popen(list(map(str, command)), stdout=log, stderr=log)
            children.append(proc)
            return proc

        def api(method, path, body=None):
            headers = {'Content-Type': 'application/json'}
            if token:
                headers['Authorization'] = 'Bearer ' + token
            request = urllib.request.Request(origin + '/api/v1' + path, method=method,
                headers=headers, data=None if body is None else json.dumps(body).encode())
            with opener.open(request, timeout=10) as response:
                return json.load(response)

        def check(name, condition):
            checks.append({'case': name, 'passed': bool(condition)})
            assert condition, name

        def acknowledge():
            until = time.monotonic() + 20
            while time.monotonic() < until:
                nodes = api('GET', '/nodes')
                if all(n['enrolled'] and n['applied_revision'] == n['desired_revision']
                       and not n['apply_error'] for n in nodes):
                    return
                time.sleep(.1)
            raise AssertionError('Agents did not apply the proposed configuration')

        try:
            controller = launch('controller', [binary, 'server', '--listen', f'127.0.0.1:{port}', '--state', root / 'controller'])
            wait_port(port, controller)
            session = api('POST', '/auth/login', {'username': 'admin', 'password': (root / 'controller/admin-password.secret').read_text().strip()})
            token = session['token']
            # Use a range that is currently free on this test machine. The
            # allocator itself relies on managed configurations, not OS probing.
            start = None
            for candidate in range(26000, 36000, 50):
                sockets = []
                try:
                    for p in range(candidate, candidate + 12):
                        for kind in [socket.SOCK_STREAM, socket.SOCK_DGRAM]:
                            s = socket.socket(socket.AF_INET, kind); sockets.append(s)
                            s.bind(('127.0.0.1', p))
                    start = candidate
                    break
                except OSError:
                    pass
                finally:
                    for s in sockets:
                        s.close()
            assert start is not None
            ids = []
            for i, name in enumerate(['Entry', 'Relay', 'SS exit']):
                created = api('POST', '/nodes', {'name': name, 'lease_policy': None})
                node = created['node']; ids.append(node['id'])
                api('PUT', f"/nodes/{node['id']}/profile", {'expected_revision': node['profile']['revision'], 'name': name,
                    'settings': {**node['profile']['settings'], 'forwarding': {'host': '127.0.0.1', 'port_start': start, 'port_end': start + 11}}})
                secret = root / f'enrollment-{i}.secret'; secret.write_text(created['enrollment_token']); secret.chmod(0o600)
                launch(f'agent-{i}', [binary, 'agent', '--controller', origin, '--node-id', node['id'], '--state', root / f'agent-{i}', '--enrollment-token-file', secret, '--poll-seconds', '1'])
            acknowledge()
            echo_port = free_port()
            echo = launch('echo', [sys.executable, repo / 'scripts/echo_fixture.py', '--port', echo_port])
            wait_port(echo_port, echo)
            allocated = []
            for mode in ['forward', 'ss']:
                before = api('GET', '/topology')
                plan = api('POST', '/configurations/allocate-endpoints', {'hops': [{'node_id': node} for node in ids]})
                check(mode + '-distinct-automatic-endpoints', len({e['advertise'] for e in plan['endpoints']}) == 3 and all(not e['error'] for e in plan['endpoints']))
                key = base64.b64encode(os.urandom(32)).decode()
                value = {'snapshot': {**before, 'configs': plan['configs']}, 'input': {'name': mode + ' automatic acceptance', 'owner': session['user'], 'mode': mode, 'protocol': 'both', 'transport': 'plain',
                    'hops': plan['endpoints'], 'targets': [{'address': f'127.0.0.1:{echo_port}', 'weight': 1}], 'shadowsocks': {'method': '2022-blake3-aes-256-gcm', 'password': key, 'allow_private_destinations': True, 'udp_over_tcp': True}}}
                js = "const fs=require('node:fs'); const w=require('./scripts/web_i18n_helpers.cjs').loadWorkflows(); const v=JSON.parse(fs.readFileSync(0,'utf8')); const batch=w.buildForwardingPath(v.snapshot,v.input,()=>require('node:crypto').randomUUID()); const diagram=w.forwardingDiagram({...v.snapshot,configs:batch.updates},{node_id:batch.updates[0].node_id,rule_id:batch.updates[0].rules.at(-1).id}); process.stdout.write(JSON.stringify({batch,diagram}));"
                built = json.loads(subprocess.run([args.node, '-e', js], cwd=repo, input=json.dumps(value), text=True, check=True, capture_output=True).stdout)
                batch = built['batch']
                api('POST', '/configurations/preview', batch)
                check(mode + '-preview-is-read-only', api('GET', '/topology')['configs'] == before['configs'])
                api('POST', '/configurations/publish', batch)
                acknowledge()
                actual = api('GET', '/topology')
                actual_rules = [next(c for c in actual['configs'] if c['node_id'] == node)['rules'][-1] for node in ids]
                diagram = built['diagram']['root']; diagram_hops = []
                while diagram.get('node_id'):
                    diagram_hops.append((diagram['node_id'], diagram['endpoint']))
                    diagram = diagram['children'][0]['next'] if diagram['children'] else {}
                check(mode + '-diagram-matches-applied-path', diagram_hops == [(n, r['advertise']) for n, r in zip(ids, actual_rules)])
                check(mode + '-SS-placement', [bool(r.get('inbound_shadowsocks')) for r in actual_rules] == ([False, False, True] if mode == 'ss' else [False] * 3))
                check(mode + '-preserves-previous-rules', all(len(next(c for c in actual['configs'] if c['node_id'] == node)['rules']) == (1 if mode == 'forward' else 2) for node in ids))
                entry = int(plan['endpoints'][0]['advertise'].rsplit(':', 1)[1]); allocated.append([e['advertise'] for e in plan['endpoints']])
                transports = ['native', 'uot'] if mode == 'ss' else ['native']
                for transport in transports:
                    proxy = None
                    if mode == 'ss':
                        proxy = free_port()
                        outbound = {'type': 'shadowsocks', 'server': '127.0.0.1', 'server_port': entry, 'method': '2022-blake3-aes-256-gcm', 'password': key, 'udp_fragment': True}
                        if transport == 'uot':
                            outbound['udp_over_tcp'] = {'enabled': True, 'version': 2}
                        config = root / f'client-{transport}.json'
                        config.write_text(json.dumps({'log': {'level': 'error'}, 'inbounds': [{'type': 'socks', 'listen': '127.0.0.1', 'listen_port': proxy}], 'outbounds': [outbound]})); config.chmod(0o600)
                        proc = launch('client-' + transport, [client, 'run', '-c', config]); wait_port(proxy, proc)
                    body = bytes(range(251)) * 2048
                    with socks(proxy, '127.0.0.1', echo_port) if proxy else socket.create_connection(('127.0.0.1', entry), timeout=10) as conn:
                        conn.settimeout(10); conn.sendall(body); conn.shutdown(socket.SHUT_WR)
                        received = bytearray()
                        while data := conn.recv(65536):
                            received.extend(data)
                        check(mode + '-' + transport + '-TCP-half-close', received == body)
                    udp = Associate(proxy) if proxy else socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    try:
                        for size in [1, 64, 1200, 4096, 8192]:
                            body = os.urandom(size)
                            if proxy:
                                reply = udp.exchange('127.0.0.1', echo_port, body)
                                ok = reply is not None and reply[1] == body
                            else:
                                udp.settimeout(5); udp.sendto(body, ('127.0.0.1', entry)); ok = udp.recv(65535) == body
                            check(mode + '-' + transport + '-UDP-' + str(size), ok)
                    finally:
                        udp.close()
            check('new-path-avoids-prior-path-ports', not set(allocated[0]) & set(allocated[1]))
            return {'passed': True, 'scope': 'Three real local macOS Agents; loopback only; no VPS or WAN claim', 'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(), 'client_sha256': hashlib.sha256(client.read_bytes()).hexdigest(), 'allocated_endpoints': allocated, 'checks': checks}
        finally:
            for proc in reversed(children):
                proc.terminate()
                try:
                    proc.wait(5)
                except subprocess.TimeoutExpired:
                    proc.kill(); proc.wait()
            for log in logs:
                log.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--ss-client', type=Path, required=True)
    parser.add_argument('--node', default='node')
    args = parser.parse_args()
    print(json.dumps(run(args), indent=2))
