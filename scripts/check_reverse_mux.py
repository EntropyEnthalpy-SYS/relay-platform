#!/usr/bin/env python3
"""Real CLI mux regression checks: telemetry, half-close, TLS isolation and capacity."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import socket
import socketserver
import ssl
import subprocess
import tempfile
import threading
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    binary = str(args.binary.resolve())
    spec = importlib.util.spec_from_file_location('fixtures', args.source / 'scripts/check_subscriptions.py')
    fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture)
    results = {}

    def save(name, values):
        results[name] = values
        args.output.write_text(json.dumps(results, indent=2) + '\n')
        print(name + ': ' + json.dumps(values), flush=True)

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(8)
            try:
                first = self.request.recv(4096)
                if first.startswith(b'eof:'):
                    request = first
                    while more := self.request.recv(4096):
                        request += more
                    self.request.sendall(b'response-after-eof:' + request)
                else:
                    self.request.sendall(first)
                    while more := self.request.recv(4096):
                        self.request.sendall(more)
            except (OSError, TimeoutError):
                pass

    class Target(socketserver.ThreadingTCPServer):
        daemon_threads = True

    processes = []
    logs = []
    with tempfile.TemporaryDirectory(prefix='relay-mux-regression-') as directory:
        root = Path(directory)
        token_text = 'local-review-token-095'
        token = root / 'token'
        token.write_text(token_text)
        os.chmod(token, 0o600)

        def launch(name, *command):
            log = open(root / (name + '.log'), 'w')
            logs.append(log)
            process = subprocess.Popen([binary, *map(str, command)], stdout=log, stderr=log)
            processes.append(process)
            return process

        def connect_when_ready(port, process):
            for _ in range(100):
                if process.poll() is not None:
                    raise AssertionError('server exited at startup')
                try:
                    return socket.create_connection(('127.0.0.1', port), timeout=2)
                except OSError:
                    time.sleep(.05)
            raise AssertionError('listener not ready')

        target = Target(('127.0.0.1', 0), Handler)
        threading.Thread(target=target.serve_forever, daemon=True).start()
        try:
            target_port = target.server_address[1]
            control_port, public_port = fixture.free_port(), fixture.free_port()
            metrics_port = fixture.free_port()
            server = launch('mux-server', 'reverse-mux-server', '--control-listen',
                            f'127.0.0.1:{control_port}', '--public-listen',
                            f'127.0.0.1:{public_port}', '--token-file', token,
                            '--metrics-listen', f'127.0.0.1:{metrics_port}')
            connect_when_ready(control_port, server).close()
            launch('mux-client', 'reverse-mux-client', '--server',
                   f'127.0.0.1:{control_port}', '--target',
                   f'127.0.0.1:{target_port}', '--token-file', token)
            with socket.create_connection(('127.0.0.1', public_port), timeout=6) as live:
                live.sendall(b'live-mux-echo')
                echoed = live.recv(4096)
                assert echoed == b'live-mux-echo', echoed

                password = root / 'password'
                password.write_text(fixture.PASSWORD)
                os.chmod(password, 0o600)
                controller, origin = fixture.start(Path(binary), root / 'state', password)
                processes.append(controller)
                status, login = fixture.json_request(origin, '/api/v1/auth/login',
                    {'username': 'admin', 'password': fixture.PASSWORD})
                assert status == 200
                status, _, raw = fixture.request(origin, '/api/v1/metrics', token=login['token'])
                assert status == 200
                mux_metrics = [line for line in raw.decode().splitlines()
                               if line.startswith('relay_reverse_mux_')]
                assert len(mux_metrics) == 7, mux_metrics
                assert all(line.endswith(' 0') for line in mux_metrics), mux_metrics
                status, _, raw_mux = fixture.request(f'http://127.0.0.1:{metrics_port}', '/metrics')
                assert status == 200
                actual = [line for line in raw_mux.decode().splitlines() if line.startswith('relay_reverse_mux_')]
                assert 'relay_reverse_mux_process_available 1' in actual
                assert 'relay_reverse_mux_controls 1' in actual
                assert 'relay_reverse_mux_streams 1' in actual
                assert 'relay_reverse_mux_bytes{direction="public_to_target"} 13' in actual
                assert 'relay_reverse_mux_bytes{direction="target_to_public"} 13' in actual
                save('R95_06_metrics_from_tunnel_process', {
                    'passed': True, 'deployment': 'separate actual CLI processes',
                    'verified_echo_bytes_each_direction': len(echoed),
                    'public_connection_open_during_scrape': True,
                    'controller_metrics': mux_metrics, 'tunnel_metrics': actual})

            def eof_exchange(port):
                with socket.create_connection(('127.0.0.1', port), timeout=5) as conn:
                    conn.sendall(b'eof:request-body')
                    conn.shutdown(socket.SHUT_WR)
                    response = b''
                    try:
                        while more := conn.recv(4096):
                            response += more
                    except OSError as error:
                        return response, type(error).__name__
                    return response, None

            direct, direct_error = eof_exchange(target_port)
            tunneled, tunnel_error = eof_exchange(public_port)
            assert direct == b'response-after-eof:eof:request-body' and direct_error is None
            assert tunneled == direct and tunnel_error is None
            save('R95_03_half_close_preserves_response', {
                'passed': True, 'direct_response': direct.decode(),
                'tunneled_response': tunneled.decode(errors='replace'),
                'direct_error': direct_error, 'tunnel_error': tunnel_error})

            conf = root / 'openssl.cnf'
            conf.write_text('[req]\nprompt=no\ndistinguished_name=dn\nx509_extensions=v3\n'
                            '[dn]\nCN=reverse.test\n[v3]\nsubjectAltName=DNS:reverse.test\n'
                            'basicConstraints=critical,CA:TRUE\n')
            cert, key = root / 'cert.pem', root / 'key.pem'
            subprocess.run(['/usr/bin/openssl', 'req', '-x509', '-newkey', 'rsa:2048',
                            '-nodes', '-days', '1', '-config', str(conf), '-out', str(cert),
                            '-keyout', str(key)], check=True, capture_output=True)
            tls_port, tls_public = fixture.free_port(), fixture.free_port()
            tls_server = launch('tls-server', 'reverse-mux-server', '--control-listen',
                                f'127.0.0.1:{tls_port}', '--public-listen',
                                f'127.0.0.1:{tls_public}', '--token-file', token,
                                '--tls-cert', cert, '--tls-key', key)
            blocker = connect_when_ready(tls_port, tls_server)
            time.sleep(.2)
            authorized = {}
            started = threading.Event()

            def authorized_client():
                try:
                    context = ssl.create_default_context(cafile=str(cert))
                    with socket.create_connection(('127.0.0.1', tls_port), timeout=20) as raw_conn:
                        started.set()
                        with context.wrap_socket(raw_conn, server_hostname='reverse.test') as conn:
                            conn.sendall(('REVERSE-MUX ' + token_text + '\n').encode())
                            authorized['reply'] = conn.recv(4096).decode()
                except Exception as error:
                    authorized['error'] = repr(error)

            thread = threading.Thread(target=authorized_client, daemon=True)
            thread.start()
            assert started.wait(3)
            before = time.monotonic()
            thread.join(timeout=2)
            blocked_seconds = time.monotonic() - before
            completed_while_blocker_open = not thread.is_alive() and authorized.get('reply') == 'READY\n'
            blocker.close()
            thread.join(timeout=5)
            assert completed_while_blocker_open and authorized.get('reply') == 'READY\n', authorized
            save('R95_02_silent_control_tls_does_not_block_accepts', {
                'passed': True, 'silent_connections': 1,
                'legitimate_clients': 1, 'completed_with_silent_socket_open': completed_while_blocker_open,
                'legitimate_connect_seconds': round(blocked_seconds, 3),
                'reply_before_silent_socket_closed': authorized['reply'],
                'certificate_verified_against_local_test_ca': True})
            # Each TLS handshake completes before the next begins. No pending
            # handshakes should remain while these authorized controls stay open.
            context = ssl.create_default_context(cafile=str(cert))
            controls = []
            def new_authorized_control():
                raw_conn = socket.create_connection(('127.0.0.1', tls_port), timeout=3)
                try:
                    conn = context.wrap_socket(raw_conn, server_hostname='reverse.test')
                    conn.sendall(('REVERSE-MUX ' + token_text + '\n').encode())
                    assert conn.recv(6) == b'READY\n'
                    return conn
                except BaseException:
                    raw_conn.close()
                    raise
            try:
                time.sleep(.2)
                for _ in range(80):
                    controls.append(new_authorized_control())
                save('R96_04_authenticated_controls_release_handshake_slots', {
                    'passed': True, 'simultaneously_authenticated_controls': len(controls),
                    'pending_handshakes': 0, 'closed_controls_to_admit_65th': 0,
                    'all_replies': 'READY'})
            finally:
                for conn in controls:
                    conn.close()
        finally:
            for process in reversed(processes):
                fixture.stop(process)
            target.shutdown()
            target.server_close()
            for log in logs:
                log.close()


if __name__ == '__main__':
    main()
