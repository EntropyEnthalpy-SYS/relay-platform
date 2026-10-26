#!/usr/bin/env python3
"""Local subscription format and permission check.

Starts a real controller, publishes a Shadowsocks rule plus a plain TCP rule,
creates one subscription per client format, fetches the public endpoint without
a session and parses the result with independent Python parsers (PyYAML for
Clash, base64 for V2Ray). It also checks preview skip reasons and rotation.
No external network or client is used.
"""
import argparse
import base64
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

PASSWORD = 'subscription-fixture-29x!'
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def request(origin, path, body=None, token=None, method=None):
    headers = {'Content-Type': 'application/json'}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(origin + path, data, headers, method=method)
    try:
        with opener.open(req, timeout=5) as response:
            raw = response.read()
            return response.status, dict(response.headers), raw
    except urllib.error.HTTPError as error:
        return error.code, dict(error.headers), error.read()


def json_request(origin, path, body=None, token=None, method=None):
    status, _, raw = request(origin, path, body, token, method)
    try:
        return status, json.loads(raw)
    except json.JSONDecodeError:
        return status, {'error': raw.decode('utf-8', 'replace')}


def free_port():
    with socket.socket() as reservation:
        reservation.bind(('127.0.0.1', 0))
        return reservation.getsockname()[1]


def start(binary, state, password):
    port = free_port()
    log = open(state.parent / 'controller.log', 'w')
    process = subprocess.Popen(
        [str(binary), 'server', '--state', str(state), '--listen', f'127.0.0.1:{port}',
         '--admin-password-file', str(password)],
        stdout=log, stderr=log,
    )
    for _ in range(120):
        if process.poll() is not None:
            raise SystemExit('controller exited; inspect controller.log')
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=.1):
                return process, f'http://127.0.0.1:{port}'
        except OSError:
            time.sleep(.05)
    process.terminate()
    raise SystemExit('controller startup timed out')


def stop(process):
    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def ss_rule(owner):
    return {
        'id': 'ss-tokyo',
        'tenant_id': 'default',
        'owner_id': owner,
        'name': 'Tokyo',
        'listen': '0.0.0.0:8388',
        'protocol': 'both',
        'inbound_shadowsocks': {
            'method': '2022-blake3-aes-256-gcm',
            'password': 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=',
            'allow_private_destinations': False,
        },
        'advertise': 'edge.example.com:9000',
        'targets': [],
        'quota_bytes': None,
        'expires_at_ms': None,
        'rate_bytes_per_sec': None,
        'meter_epoch': 'fixture',
    }


def plain_rule(owner):
    return {
        'id': 'plain',
        'tenant_id': 'default',
        'owner_id': owner,
        'name': 'Plain forwarding',
        'listen': '127.0.0.1:18081',
        'protocol': 'tcp',
        'targets': [{'address': '127.0.0.1:9', 'weight': 1}],
        'quota_bytes': None,
        'expires_at_ms': None,
        'rate_bytes_per_sec': None,
        'meter_epoch': 'fixture',
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve()
    with tempfile.TemporaryDirectory(prefix='subscription-check-') as directory:
        directory = Path(directory)
        password = directory / 'password'
        password.write_text(PASSWORD)
        os.chmod(password, 0o600)
        process, origin = start(binary, directory / 'state', password)
        try:
            status, login = json_request(origin, '/api/v1/auth/login', {'username': 'admin', 'password': PASSWORD})
            assert status == 200, login
            session, owner = login['token'], login['user']['id']
            status, node = json_request(origin, '/api/v1/nodes', {
                'name': 'edge', 'lease_policy': None, 'settings': {},
            }, session)
            assert status == 200, node
            node_id = node['node']['id']
            status, published = json_request(origin, f'/api/v1/nodes/{node_id}/config', {
                'expected_revision': 0, 'rules': [ss_rule(owner), plain_rule(owner)],
            }, session, method='PUT')
            assert status == 200, (status, published)

            subscriptions = {}
            for format_name in ('v2ray', 'clash', 'surge', 'shadowrocket'):
                status, created = json_request(origin, '/api/v1/subscriptions', {
                    'name': format_name, 'format': format_name,
                    'template': {'name_prefix': 'Relay ', 'node_tags': [], 'udp': True},
                    'expires_in_days': 30,
                }, session)
                assert status == 200, created
                subscriptions[format_name] = created
            # One preview exposes the incompatible plain rule.
            first = subscriptions['clash']['subscription']['id']
            status, preview = json_request(origin, f'/api/v1/subscriptions/{first}/preview', token=session)
            assert status == 200 and len(preview['entries']) == 1, preview
            assert len(preview['skipped']) == 1 and 'not a Shadowsocks' in preview['skipped'][0]['reason'], preview

            results = {}
            for format_name, created in subscriptions.items():
                status, headers, raw = request(origin, '/sub/' + created['token'])
                assert status == 200, (format_name, status, raw[:200])
                content_type = next((value for key, value in headers.items() if key.lower() == 'content-type'), None)
                results[format_name] = {'status': status, 'content_type': content_type, 'bytes': len(raw)}
                if format_name == 'v2ray':
                    lines = base64.b64decode(raw).decode().splitlines()
                    assert lines and lines[0].startswith('ss://2022-blake3-aes-256-gcm:') and 'edge.example.com:9000' in lines[0], lines
                elif format_name == 'shadowrocket':
                    text = raw.decode()
                    assert text.startswith('ss://') and '@edge.example.com:9000#' in text, text[:200]
                elif format_name == 'clash':
                    import yaml
                    config = yaml.safe_load(raw)
                    proxy = config['proxies'][0]
                    assert proxy['type'] == 'ss' and proxy['server'] == 'edge.example.com' and proxy['port'] == 9000, proxy
                    assert proxy['cipher'] == '2022-blake3-aes-256-gcm' and proxy['udp'] is True, proxy
                    assert config['proxy-groups'][0]['proxies'][0] == proxy['name'], config
                    assert config['rules'] == ['MATCH,Relay'], config
                elif format_name == 'surge':
                    text = raw.decode()
                    assert '[Proxy]' in text and 'edge.example.com, 9000' in text, text[:300]
                    assert 'encrypt-method=2022-blake3-aes-256-gcm' in text and 'MATCH,Relay' in text, text[-200:]

            target = subscriptions['v2ray']
            old, new = target['token'], None
            status, rotated = json_request(origin, f"/api/v1/subscriptions/{target['subscription']['id']}/rotate", {}, session)
            assert status == 200, rotated
            new = rotated['token']
            assert request(origin, '/sub/' + old)[0] == 401
            assert request(origin, '/sub/' + new)[0] == 200
            status, _ = json_request(origin, f"/api/v1/subscriptions/{target['subscription']['id']}", token=session)
            assert status == 200
            # DELETE is not supported by this helper; use urllib directly.
            req = urllib.request.Request(origin + f"/api/v1/subscriptions/{target['subscription']['id']}",
                                         headers={'Authorization': 'Bearer ' + session}, method='DELETE')
            with opener.open(req, timeout=5) as response:
                assert response.status == 200
            assert request(origin, '/sub/' + new)[0] == 401

            summary = {
                'binary': binary.name,
                'formats': results,
                'preview_skipped': preview['skipped'],
                'rotation': {'old_status': 401, 'new_status_before_delete': 200, 'after_delete': 401},
            }
            text = json.dumps(summary, indent=2, sort_keys=True)
            print(text)
            if args.output:
                args.output.write_text(text + '\n')
        finally:
            stop(process)
    return 0


if __name__ == '__main__':
    sys.exit(main())
