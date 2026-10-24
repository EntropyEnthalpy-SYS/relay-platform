#!/usr/bin/env python3
"""Check relay-stream-v1 through Python websockets -> relay -> Python websockets.

Install scripts/requirements-interop.txt in an isolated virtual environment.
Only loopback sockets, temporary certificates/state and child processes are used.
No service, certificate or package is installed globally. This is a functional
interop check, not a generic WebSocket proxy or a performance benchmark.
"""
import argparse
import asyncio
import hashlib
import importlib.metadata
import json
import logging
import platform
import ssl
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from websockets.asyncio.client import connect
from websockets.asyncio.server import serve
from websockets.exceptions import ConnectionClosed, InvalidHandshake

from bench_budget import free_port, ready, stop

SUBPROTOCOL = 'relay-stream-v1'
ORIGIN = 'https://console.example'
MAX_PAYLOAD = 65536


async def command(*arguments, cwd=None):
    process = await asyncio.create_subprocess_exec(
        *(str(argument) for argument in arguments), cwd=cwd,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    try:
        output, error = await asyncio.wait_for(process.communicate(), 30)
    except BaseException:
        if process.returncode is None:
            process.kill()
            await process.wait()
        raise
    if process.returncode != 0:
        raise RuntimeError(f'{arguments[0]} failed: {error.decode(errors="replace")[-2000:]}')
    return output.decode()


async def certificates(root):
    """Ephemeral RSA PKCS#8 keys; modern CA constraints work with strict Python TLS."""
    root.mkdir(mode=0o700)
    for profile in ['root', 'server', 'client']:
        (root / profile).mkdir(mode=0o700)
        await command('openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt',
                      'rsa_keygen_bits:2048', '-out', f'{profile}/key.pem', cwd=root)
        (root / profile / 'key.pem').chmod(0o600)
    (root / 'ca.cnf').write_text('''[req]
distinguished_name=dn
x509_extensions=ca
prompt=no
[dn]
CN=Relay temporary interoperability CA
[ca]
basicConstraints=critical,CA:true
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
''')
    await command('openssl', 'req', '-new', '-x509', '-sha256', '-days', '2',
                  '-key', 'root/key.pem', '-config', 'ca.cnf', '-out', 'root/ca.pem', cwd=root)
    for profile, usage in [('server', 'serverAuth'), ('client', 'clientAuth')]:
        extension = '''basicConstraints=critical,CA:false
keyUsage=critical,digitalSignature,keyEncipherment
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
'''
        extension += f'extendedKeyUsage={usage}\n'
        if profile == 'server':
            extension += 'subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1\n'
        (root / f'{profile}.ext').write_text(extension)
        await command('openssl', 'req', '-new', '-sha256', '-key', f'{profile}/key.pem',
                      '-subj', f'/CN=relay-{profile}', '-out', f'{profile}.csr', cwd=root)
        await command('openssl', 'x509', '-req', '-sha256', '-days', '2',
                      '-in', f'{profile}.csr', '-CA', 'root/ca.pem', '-CAkey', 'root/key.pem',
                      '-CAcreateserial', '-extfile', f'{profile}.ext',
                      '-out', f'{profile}/cert.pem', cwd=root)


def tls_contexts(root, mutual):
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.minimum_version = ssl.TLSVersion.TLSv1_2
    server.load_cert_chain(root / 'server/cert.pem', root / 'server/key.pem')
    server.set_alpn_protocols(['http/1.1'])
    if mutual:
        server.load_verify_locations(root / 'root/ca.pem')
        server.verify_mode = ssl.CERT_REQUIRED
    client = ssl.create_default_context(cafile=root / 'root/ca.pem')
    client.minimum_version = ssl.TLSVersion.TLSv1_2
    client.set_alpn_protocols(['http/1.1'])
    if mutual:
        client.load_cert_chain(root / 'client/cert.pem', root / 'client/key.pem')
    return server, client


async def send_data(websocket, payload):
    for offset in range(0, len(payload), MAX_PAYLOAD):
        await websocket.send(b'\x00' + payload[offset:offset + MAX_PAYLOAD])
    await websocket.send(b'\x01')


async def receive_data(websocket):
    payload = bytearray()
    while True:
        record = await asyncio.wait_for(websocket.recv(), 10)
        if not isinstance(record, bytes):
            raise RuntimeError('received a non-binary relay record')
        if record == b'\x01':
            return bytes(payload)
        if not 2 <= len(record) <= MAX_PAYLOAD + 1 or record[0] != 0:
            raise RuntimeError('received an invalid relay record')
        payload.extend(record[1:])
        if len(payload) > 2 * 1024 * 1024:
            raise RuntimeError('peer exceeded the test payload bound')


async def run(args):
    binary = args.binary.resolve()
    version = (await command(binary, '--version')).strip()
    payload = bytes((index * 31 + 7) % 256 for index in range(256 * 1024 + 37))
    cases, total = [], 0
    with tempfile.TemporaryDirectory(prefix='relay-ws-interop-') as temporary:
        scratch = Path(temporary)
        tls = scratch / 'tls'
        await certificates(tls)
        for mode in ['ws', 'wss', 'wss-mtls']:
            secure, mutual = mode != 'ws', mode == 'wss-mtls'
            server_tls, client_tls = tls_contexts(tls, mutual) if secure else (None, None)
            relay_port = free_port()
            observations, errors = [], []

            async def backend(websocket):
                try:
                    if (websocket.subprotocol != SUBPROTOCOL
                            or websocket.request.path != '/target?version=1'
                            or websocket.request.headers['Host'] != f'localhost:{target_port}'
                            or websocket.request.headers['Origin'] != ORIGIN):
                        raise RuntimeError('outbound endpoint parameters changed')
                    received = await receive_data(websocket)
                    if received != payload:
                        raise RuntimeError('backend payload differs')
                    # Wait for the application FIN before replying. A WebSocket
                    # close in place of FIN would lose this opposite direction.
                    await send_data(websocket, received[::-1])
                    await asyncio.wait_for(websocket.wait_closed(), 5)
                    if websocket.close_code not in (1000, 1005):
                        raise RuntimeError(f'abnormal backend close: {websocket.close_code}')
                    observations.append({'bytes': len(received), 'close_code': websocket.close_code})
                except Exception as error:
                    errors.append(repr(error))
                    raise

            async with serve(backend, '127.0.0.1', 0, ssl=server_tls,
                             origins=[ORIGIN], subprotocols=[SUBPROTOCOL], compression=None,
                             max_size=MAX_PAYLOAD + 1, ping_interval=None, close_timeout=3) as server:
                target_port = server.sockets[0].getsockname()[1]
                target = {'address': f'127.0.0.1:{target_port}', 'weight': 1,
                          'websocket': {'path': '/target?version=1',
                                        'host': f'localhost:{target_port}', 'origin': ORIGIN}}
                rule = {'id': 'interop', 'tenant_id': 'default', 'owner_id': 'admin',
                        'name': mode, 'listen': f'127.0.0.1:{relay_port}', 'protocol': 'tcp',
                        'targets': [target], 'meter_epoch': 'interop', 'connect_timeout_ms': 2000,
                        'inbound_websocket': {'path': '/relay?version=1',
                            'host': f'127.0.0.1:{relay_port}', 'allowed_origins': [ORIGIN]}}
                if secure:
                    rule['inbound_tls'] = {'identity': 'server'}
                    target['tls'] = {'server_name': 'localhost', 'ca': 'root'}
                    if mutual:
                        rule['inbound_tls']['client_ca'] = 'root'
                        target['tls']['identity'] = 'client'
                config = {'api_version': 1, 'node_id': 'interop', 'revision': 1, 'rules': [rule]}
                config_path, database = scratch / f'{mode}.json', scratch / f'{mode}.sqlite'
                config_path.write_text(json.dumps(config))
                await command(binary, 'validate', '--config', config_path)
                process = None
                with (scratch / f'{mode}.log').open('wb') as log:
                    try:
                        process = await asyncio.create_subprocess_exec(
                            str(binary), 'standalone', '--config', str(config_path),
                            '--database', str(database), '--tls-directory', str(tls),
                            stdout=log, stderr=log)
                        await ready(relay_port, process)
                        uri = f'{"wss" if secure else "ws"}://127.0.0.1:{relay_port}/relay?version=1'
                        options = {'subprotocols': [SUBPROTOCOL], 'origin': ORIGIN, 'compression': None,
                                   'proxy': None, 'max_size': MAX_PAYLOAD + 1, 'ping_interval': None,
                                   'open_timeout': 3, 'close_timeout': 3}
                        if secure:
                            options['ssl'] = client_tls
                        async with connect(uri, **options) as websocket:
                            if websocket.subprotocol != SUBPROTOCOL:
                                raise RuntimeError('inbound subprotocol negotiation failed')
                            ping = await websocket.ping(b'independent-peer')
                            await asyncio.wait_for(ping, 3)
                            await send_data(websocket, payload)
                            if await receive_data(websocket) != payload[::-1]:
                                raise RuntimeError('reply payload differs')
                            await asyncio.wait_for(websocket.wait_closed(), 5)
                            if websocket.close_code not in (1000, 1005):
                                raise RuntimeError(f'abnormal client close: {websocket.close_code}')
                            close_code = websocket.close_code
                        negatives = []
                        variants = [('wrong-origin', {'origin': 'https://untrusted.example'}),
                                    ('wrong-subprotocol', {'subprotocols': ['different-v1']})]
                        if mutual:
                            _, unauthenticated = tls_contexts(tls, False)
                            variants.append(('missing-client-certificate', {'ssl': unauthenticated}))
                        for name, override in variants:
                            try:
                                async with connect(uri, **{**options, **override}) as rejected:
                                    # TLS 1.3 may surface the client-certificate alert
                                    # after initial connection establishment.
                                    await rejected.send(b'\x00must-not-be-billed')
                                    await asyncio.wait_for(rejected.recv(), 3)
                            except (InvalidHandshake, ConnectionClosed, OSError):
                                negatives.append(name)
                            else:
                                raise RuntimeError(f'{name} was not rejected')
                        await stop(process)
                        rows = json.loads(await command(binary, 'usage', '--database', database))
                        admitted = sum(row['upload_bytes'] + row['download_bytes'] for row in rows)
                        if admitted != 2 * len(payload) or len(rows) != 1:
                            raise RuntimeError(f'framing or rejected sessions affected ledger: {rows!r}')
                        if errors or len(observations) != 1:
                            raise RuntimeError(f'backend failures/extra connections: {errors}, {observations}')
                        total += admitted
                        cases.append({'transport': mode, 'payload_each_direction': len(payload),
                            'reversed_reply_verified': True, 'half_close': 'passed', 'ping_pong': 'passed',
                            'client_close_code': close_code, 'backend': observations[0],
                            'host_path_origin_subprotocol': 'passed', 'negative_cases': negatives,
                            'recorded_bytes': admitted})
                    except BaseException:
                        log.flush()
                        print((scratch / f'{mode}.log').read_text()[-4000:])
                        raise
                    finally:
                        if process is not None:
                            await stop(process)
    return {'at_utc': datetime.now(timezone.utc).isoformat(), 'platform': platform.platform(),
            'version': version, 'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
            'python_version': platform.python_version(), 'websockets_version': importlib.metadata.version('websockets'),
            'openssl_version': ssl.OPENSSL_VERSION, 'topology': 'Python websockets -> relay -> Python websockets',
            'subprotocol': SUBPROTOCOL, 'cases': cases,
            'ledger': {'expected_admitted_bytes': 2 * len(cases) * len(payload), 'recorded_bytes': total,
                       'exact_match': True, 'framing_and_control_excluded': True},
            'child_processes_stopped': True, 'limits': ['loopback IPv4 only', 'ephemeral private CA',
                'no external PROXY+WebSocket peer', 'not a performance or generic WebSocket proxy benchmark']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=Path('target/release/relay'))
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    # Expected rejected upgrade probes should not emit noisy peer tracebacks.
    logging.getLogger('websockets.server').setLevel(logging.CRITICAL)
    report = asyncio.run(run(args))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({key: report[key] for key in
                     ['version', 'websockets_version', 'cases', 'ledger', 'child_processes_stopped']}, indent=2))


if __name__ == '__main__':
    main()
