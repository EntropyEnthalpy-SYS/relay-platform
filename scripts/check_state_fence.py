#!/usr/bin/env python3
"""Cross-version state-fence checks for 0.20.0.

Runs local controllers with fresh temporary state and supplied binaries:
  * 0.20 enables MFA, then 0.19/0.18 must refuse the schema-v5 database;
  * a 0.19 schema-v4 controller migrates in place, keeps its recovery log
    continuous, and rejects the old binary afterwards;
  * a 0.19 schema-v4 backup plus its log restores under 0.20 and serves.

No remote host, real credential or production state is used. The script only
prints versions, status codes, schema numbers and recovery sequence numbers.
"""
import argparse
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

PASSWORD = 'state-fence-fixture-29x!'
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def build_info(binary):
    return json.loads(subprocess.check_output([str(binary), 'build-info'], timeout=20))


def request(origin, path, body=None, token=None, method=None):
    headers = {'Content-Type': 'application/json'}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(origin + path, data, headers, method=method)
    try:
        with opener.open(req, timeout=5) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as error:
        raw = error.read()
        try:
            return error.code, json.loads(raw)
        except json.JSONDecodeError:
            return error.code, {'error': raw.decode('utf-8', 'replace')[:200]}


def totp(secret, offset=0):
    secret += '=' * (-len(secret) % 8)
    step = int(time.time()) // 30 + offset
    digest = hmac.new(base64.b32decode(secret), struct.pack('>Q', step), hashlib.sha1).digest()
    offset = digest[-1] & 15
    return f'{(struct.unpack(">I", digest[offset:offset+4])[0] & 0x7fffffff) % 1000000:06d}'


def free_port():
    with socket.socket() as reservation:
        reservation.bind(('127.0.0.1', 0))
        return reservation.getsockname()[1]


def start(binary, state, password, log):
    port = free_port()
    process = subprocess.Popen(
        [str(binary), 'server', '--state', str(state), '--listen', f'127.0.0.1:{port}',
         '--admin-password-file', str(password)],
        stdout=log, stderr=log,
    )
    for _ in range(120):
        if process.poll() is not None:
            return None, None, port
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=.1):
                return process, f'http://127.0.0.1:{port}', port
        except OSError:
            time.sleep(.05)
    process.terminate()
    return None, None, port


def stop(process):
    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def expect_refusal(binary, state, password, log):
    process, _, _ = start(binary, state, password, log)
    if process is not None:
        stop(process)
        return {'refused': False, 'reason': 'started and served'}
    log.flush()
    text = Path(log.name).read_text(errors='replace')
    reason = next((line.strip() for line in text.splitlines()
                   if 'schema newer' in line or 'schema' in line.lower()), 'process exited')
    return {'refused': True, 'reason': reason[-240:]}


def login(origin, extra=None):
    body = {'username': 'admin', 'password': PASSWORD}
    if extra:
        body.update(extra)
    return request(origin, '/api/v1/auth/login', body)


def recovery_head(origin, token):
    status, body = request(origin, '/api/v1/recovery', token=token)
    assert status == 200, body
    return body['head']


def fresh_mfa_fence(new, old_binaries):
    with tempfile.TemporaryDirectory(prefix='state-fence-mfa-') as directory:
        directory = Path(directory)
        password = directory / 'password'
        password.write_text(PASSWORD)
        os.chmod(password, 0o600)
        state = directory / 'state'
        log = (directory / 'new.log').open('w')
        process, origin, _ = start(new, state, password, log)
        assert process, '0.20.0 controller did not start'
        try:
            status, body = login(origin)
            assert status == 200, body
            token = body['token']
            status, setup = request(origin, '/api/v1/account/mfa/setup', {'password': PASSWORD}, token)
            assert status == 200, setup
            status, body = request(origin, '/api/v1/account/mfa/enable', {'code': totp(setup['secret'])}, token)
            assert status == 200, body
            recovery = body['recovery_codes'][0]
            protected, _ = login(origin)
            assert protected == 401, protected
            # API-token revocation is part of the same persisted security
            # state; it must remain revoked after the schema upgrade too.
            status, body = login(origin, {'second_factor': totp(setup['secret'], 1)})
            assert status == 200, body
            session = body['token']
            status, created = request(origin, '/api/v1/api-tokens', {
                'name': 'fence-token', 'scopes': ['read'], 'expires_in_days': 1,
            }, session)
            assert status == 200, created
            api_token = created['token']
            token_id = created['api_token']['id']
            usable, _ = request(origin, '/api/v1/session', token=api_token)
            assert usable == 200, usable
            status, _ = request(origin, f'/api/v1/api-tokens/{token_id}', token=session, method='DELETE')
            assert status == 200, status
            revoked, _ = request(origin, '/api/v1/session', token=api_token)
            assert revoked == 401, revoked
        finally:
            stop(process)
        refusals = []
        for old in old_binaries:
            with (directory / f'{old.name}.log').open('w') as old_log:
                result = expect_refusal(old, state, password, old_log)
            result['version'] = build_info(old)['version']
            refusals.append(result)
        # A fresh 0.20 start still enforces MFA; the fence did not corrupt state.
        log = (directory / 'new-again.log').open('w')
        process, origin, _ = start(new, state, password, log)
        assert process, '0.20.0 could not reopen its own state'
        try:
            password_only, _ = login(origin)
            status, body = login(origin, {'second_factor': recovery})
            assert status == 200, body
            revoked_after, _ = request(origin, '/api/v1/session', token=api_token)
            assert revoked_after == 401, revoked_after
            head = recovery_head(origin, body['token'])
        finally:
            stop(process)
        return {
            'mfa_password_only_020': protected,
            'password_only_after_reopen': password_only,
            'mfa_recovery_after_reopen': status,
            'api_token_before_revoke': usable,
            'api_token_after_revoke': revoked,
            'api_token_after_reopen': revoked_after,
            'recovery_schema': head['schema'],
            'refusals': refusals,
        }


def migration(old, new):
    with tempfile.TemporaryDirectory(prefix='state-fence-migrate-') as directory:
        directory = Path(directory)
        password = directory / 'password'
        password.write_text(PASSWORD)
        os.chmod(password, 0o600)
        state = directory / 'state'
        log = (directory / 'old.log').open('w')
        process, origin, _ = start(old, state, password, log)
        assert process, '0.19.0 controller did not start'
        try:
            status, body = login(origin)
            assert status == 200
            token = body['token']
            before = recovery_head(origin, token)
        finally:
            stop(process)
        new_log = (directory / 'new.log').open('w')
        process, origin, _ = start(new, state, password, new_log)
        if not process:
            raise SystemExit('0.20.0 failed to migrate a 0.19 schema-v4 state; see new.log')
        try:
            status, body = login(origin)
            assert status == 200, body
            token = body['token']
            _, _ = request(origin, '/api/v1/users', {
                'username': 'fence-user', 'password': PASSWORD,
                'role': 'viewer', 'tenant_id': None,
            }, token)
            after = recovery_head(origin, token)
        finally:
            stop(process)
        assert after['sequence'] > before['sequence'], (before, after)
        with (directory / 'old-fenced.log').open('w') as old_log:
            refusal = expect_refusal(old, state, password, old_log)
        with (directory / 'new-again.log').open('w') as again:
            process, origin, _ = start(new, state, password, again)
            assert process, '0.20.0 could not reopen the migrated state'
            try:
                status, body = login(origin)
                assert status == 200, body
                final_seq = recovery_head(origin, body['token'])['sequence']
            finally:
                stop(process)
        return {
            'before_sequence': before['sequence'],
            'after_sequence': after['sequence'],
            'final_sequence': final_seq,
            'log_schema': after['schema'],
            'old_binary': refusal,
        }


def restore_v4(old, new):
    with tempfile.TemporaryDirectory(prefix='state-fence-restore-') as directory:
        directory = Path(directory)
        password = directory / 'password'
        password.write_text(PASSWORD)
        os.chmod(password, 0o600)
        state = directory / 'state'
        log = (directory / 'old.log').open('w')
        process, origin, _ = start(old, state, password, log)
        assert process, '0.19.0 controller did not start'
        try:
            status, body = login(origin)
            assert status == 200
        finally:
            stop(process)
        backup = directory / 'backup.sqlite'
        subprocess.run([str(old), 'backup', '--database', str(state / 'controller.sqlite'),
                        '--output', str(backup)], check=True, timeout=30)
        restored = directory / 'restored'
        result = subprocess.run(
            [str(new), 'restore', '--backup', str(backup),
             '--recovery-log', str(state / 'recovery.log'), '--output', str(restored)],
            capture_output=True, text=True, timeout=60,
        )
        assert result.returncode == 0, result.stderr
        report = json.loads(result.stdout)
        new_log = (directory / 'new.log').open('w')
        process, origin, _ = start(new, restored, password, new_log)
        assert process, 'restored state did not start'
        try:
            status, body = login(origin)
            assert status == 200, body
            head = recovery_head(origin, body['token'])
        finally:
            stop(process)
        return {
            'restored_sequence': report.get('restored_sequence'),
            'backup_sequence': report.get('backup_sequence'),
            'served_schema': head['schema'],
            'login': status,
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--new', type=Path, required=True, help='0.20.0 relay binary')
    parser.add_argument('--old', type=Path, required=True, help='0.19.0 relay binary')
    parser.add_argument('--legacy', type=Path, help='optional 0.18.0 relay binary')
    parser.add_argument('--output', type=Path, help='write the JSON summary here')
    args = parser.parse_args()
    new = args.new.resolve()
    old = args.old.resolve()
    legacy = args.legacy.resolve() if args.legacy else None
    info = {'new': build_info(new), 'old': build_info(old)}
    if legacy:
        info['legacy'] = build_info(legacy)
    new_version = tuple(int(part) for part in info['new']['version'].split('.')[:2])
    assert new_version >= (0, 20), info['new']['version']
    assert info['old']['version'] == '0.19.0'
    assert info['new']['state_contract'] != info['old']['state_contract']
    assert info['new']['controller_schema'] == 5
    result = {'build': info}
    result['mfa_fence'] = fresh_mfa_fence(new, [b for b in (old, legacy) if b])
    result['migration'] = migration(old, new)
    result['restore_schema_v4'] = restore_v4(old, new)
    text = json.dumps(result, indent=2, sort_keys=True)
    print(text)
    if args.output:
        args.output.write_text(text + '\n')
    return 0


if __name__ == '__main__':
    sys.exit(main())
