#!/usr/bin/env python3
"""Bounded mux wire compatibility probe against an explicitly supplied older CLI."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import socketserver
import subprocess
import tempfile
import threading
import time
from check_subscriptions import free_port, stop


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--old', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    new, old = args.binary.resolve(), args.old.resolve()
    results = {'new_version': subprocess.check_output([new, '--version'], text=True).strip(),
               'old_version': subprocess.check_output([old, '--version'], text=True).strip(),
               'pairs': []}

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(5)
            request = bytearray()
            while chunk := self.request.recv(4096):
                request.extend(chunk)
                assert len(request) <= 65536
            self.request.sendall(b'eof-reply:' + request)

    class Target(socketserver.ThreadingTCPServer):
        daemon_threads = True

    with tempfile.TemporaryDirectory(prefix='relay-mux-compat-') as directory:
        root = Path(directory)
        token = root / 'token'
        token.write_text('local-compatibility-fixture')
        os.chmod(token, 0o600)
        target = Target(('127.0.0.1', 0), Handler)
        threading.Thread(target=target.serve_forever, daemon=True).start()
        try:
            for label, server_binary, client_binary in [('new_server_old_client', new, old),
                                                        ('old_server_new_client', old, new)]:
                control, public = free_port(), free_port()
                processes = []
                with open(root / (label + '.log'), 'w') as log:
                    try:
                        server = subprocess.Popen([server_binary, 'reverse-mux-server',
                            '--control-listen', f'127.0.0.1:{control}', '--public-listen', f'127.0.0.1:{public}',
                            '--token-file', token], stdout=log, stderr=log)
                        processes.append(server)
                        for _ in range(100):
                            assert server.poll() is None
                            try:
                                socket.create_connection(('127.0.0.1', control), timeout=.1).close()
                                break
                            except OSError:
                                time.sleep(.03)
                        client = subprocess.Popen([client_binary, 'reverse-mux-client',
                            '--server', f'127.0.0.1:{control}', '--target', f'127.0.0.1:{target.server_address[1]}',
                            '--token-file', token], stdout=log, stderr=log)
                        processes.append(client)
                        data = bytes(range(256)) * 128
                        with socket.create_connection(('127.0.0.1', public), timeout=5) as conn:
                            conn.sendall(data)
                            conn.shutdown(socket.SHUT_WR)
                            response = bytearray()
                            while chunk := conn.recv(4096):
                                response.extend(chunk)
                        assert response == b'eof-reply:' + data
                        results['pairs'].append({'pair': label, 'passed': True,
                            'request_bytes': len(data), 'response_bytes': len(response),
                            'response_sha256': hashlib.sha256(response).hexdigest()})
                    finally:
                        for process in reversed(processes):
                            stop(process)
        finally:
            target.shutdown()
            target.server_close()
    args.output.write_text(json.dumps(results, indent=2) + '\n')
    print(json.dumps(results, indent=2))


if __name__ == '__main__':
    main()
