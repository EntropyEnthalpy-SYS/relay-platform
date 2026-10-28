#!/usr/bin/env python3
"""Bounded loopback UDP interoperability with a retained pre-fix mux binary."""
import argparse
import json
import os
from pathlib import Path
import socket
import socketserver
import subprocess
import tempfile
import threading
import time


def free_port(kind):
    with socket.socket(socket.AF_INET, kind) as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        payload, sock = self.request
        sock.sendto(payload, self.client_address)


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
    targets = [socketserver.UDPServer(('127.0.0.1', 0), Echo) for _ in range(2)]
    for target in targets:
        threading.Thread(target=target.serve_forever, daemon=True).start()
    try:
        with tempfile.TemporaryDirectory(prefix='relay-udp-compat-') as directory:
            root = Path(directory)
            token = root / 'token'
            token.write_text('loopback-udp-compatibility-token')
            os.chmod(token, 0o600)
            for mode in ['fixed', 'socks5']:
                for label, server_binary, client_binary in [('new_server_old_client', new, old),
                                                            ('old_server_new_client', old, new)]:
                    control, public = free_port(socket.SOCK_STREAM), free_port(socket.SOCK_STREAM)
                    udp = free_port(socket.SOCK_DGRAM)
                    processes = []
                    with (root / f'{mode}-{label}.log').open('w') as log:
                        try:
                            server = subprocess.Popen([server_binary, 'reverse-mux-server',
                                '--control-listen', f'127.0.0.1:{control}', '--public-listen', f'127.0.0.1:{public}',
                                '--udp-listen', f'127.0.0.1:{udp}', '--max-controls', '1', '--token-file', token],
                                stdout=log, stderr=log)
                            processes.append(server)
                            for _ in range(100):
                                assert server.poll() is None, 'server stopped during startup'
                                try:
                                    socket.create_connection(('127.0.0.1', control), timeout=.1).close()
                                    break
                                except OSError:
                                    time.sleep(.02)
                            else:
                                raise AssertionError('server startup timed out')
                            command = [client_binary, 'reverse-mux-client', '--server', f'127.0.0.1:{control}',
                                       '--target', '127.0.0.1:9', '--token-file', token]
                            if mode == 'socks5':
                                command += ['--udp-socks5', '--udp-socks5-allow-private', '--udp-allow-cidr', '127.0.0.1/32']
                            else:
                                command += ['--udp-target', f'127.0.0.1:{targets[0].server_address[1]}']
                            client = subprocess.Popen(command, stdout=log, stderr=log)
                            processes.append(client)
                            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
                                probe.bind(('127.0.0.1', 0))
                                probe.settimeout(.2)
                                for index in range(16):
                                    target = targets[index % 2 if mode == 'socks5' else 0].server_address
                                    payload = index.to_bytes(2, 'big') + bytes(range(256)) * 4
                                    header = b'\0\0\0\x01' + socket.inet_aton(target[0]) + target[1].to_bytes(2, 'big')
                                    packet = header + payload if mode == 'socks5' else payload
                                    deadline = time.monotonic() + 4
                                    while True:
                                        assert server.poll() is None and client.poll() is None
                                        probe.sendto(packet, ('127.0.0.1', udp))
                                        try:
                                            reply, sender = probe.recvfrom(65535)
                                            assert sender == ('127.0.0.1', udp)
                                            if reply == packet:
                                                break
                                        except TimeoutError:
                                            pass
                                        assert time.monotonic() < deadline, (label, mode, index, 'echo timeout')
                            results['pairs'].append({'pair': label, 'mode': mode, 'passed': True,
                                                     'verified_datagrams': 16, 'payload_bytes_per_datagram': 1026,
                                                     'distinct_targets': 2 if mode == 'socks5' else 1})
                            args.output.write_text(json.dumps(results, indent=2) + '\n')
                            print(label, mode, 'passed', flush=True)
                        finally:
                            for process in processes:
                                process.terminate()
                            for process in processes:
                                try:
                                    process.wait(timeout=5)
                                except subprocess.TimeoutExpired:
                                    process.kill()
                                    process.wait()
    finally:
        for target in targets:
            target.shutdown()
            target.server_close()


if __name__ == '__main__':
    main()
