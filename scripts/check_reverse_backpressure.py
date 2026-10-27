#!/usr/bin/env python3
"""Bounded local test: one slow public reader and one unrelated echo stream."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import socket
import socketserver
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
    spec = importlib.util.spec_from_file_location('fixtures', args.source / 'scripts/check_subscriptions.py')
    f = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(f)
    bulk_started = threading.Event()
    upload_started = threading.Event()
    release_upload = threading.Event()

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(15)
            try:
                message = self.request.recv(4096)
                if message.startswith(b'upload'):
                    upload_started.set()
                    release_upload.wait(10)
                elif message == b'bulk':
                    bulk_started.set()
                    # At most 32 MiB offered, not an unbounded producer.
                    for _ in range(2048):
                        self.request.sendall(b'x' * 16384)
                else:
                    self.request.sendall(message)
            except OSError:
                pass

    class Target(socketserver.ThreadingTCPServer):
        daemon_threads = True

    with tempfile.TemporaryDirectory(prefix='relay-backpressure-regression-') as directory:
        root = Path(directory)
        token = root / 'token'
        token.write_text('local-review-token')
        os.chmod(token, 0o600)
        target = Target(('127.0.0.1', 0), Handler)
        threading.Thread(target=target.serve_forever, daemon=True).start()
        control, public, metrics = f.free_port(), f.free_port(), f.free_port()
        processes, logs = [], []
        sockets = []
        try:
            def launch(name, *command):
                log = open(root / (name + '.log'), 'w')
                logs.append(log)
                process = subprocess.Popen([str(args.binary.resolve()), *map(str, command)],
                                           stdout=log, stderr=log)
                processes.append(process)
                return process

            launch('server', 'reverse-mux-server', '--control-listen', f'127.0.0.1:{control}',
                   '--public-listen', f'127.0.0.1:{public}', '--token-file', token,
                   '--idle-timeout-secs', '1', '--metrics-listen', f'127.0.0.1:{metrics}')
            for _ in range(100):
                try:
                    socket.create_connection(('127.0.0.1', control), timeout=.1).close()
                    break
                except OSError:
                    time.sleep(.03)
            launch('client', 'reverse-mux-client', '--server', f'127.0.0.1:{control}',
                   '--target', f'127.0.0.1:{target.server_address[1]}', '--token-file', token)
            with socket.create_connection(('127.0.0.1', public), timeout=5) as baseline:
                baseline.sendall(b'baseline')
                assert baseline.recv(4096) == b'baseline'

            slow = socket.socket()
            slow.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024)
            slow.settimeout(5)
            slow.connect(('127.0.0.1', public))
            sockets.append(slow)
            slow.sendall(b'bulk')
            assert bulk_started.wait(3)
            held_start = time.monotonic()
            time.sleep(.1)
            # Exercise a neighbor before the 1-second idle cleanup can fire.
            early_start = time.monotonic()
            with socket.create_connection(('127.0.0.1', public), timeout=.7) as during:
                during.sendall(b'echo-while-bulk-active')
                assert during.recv(4096) == b'echo-while-bulk-active'
                early_latency = time.monotonic() - early_start
                _, _, during_metrics = f.request(f'http://127.0.0.1:{metrics}', '/metrics')
                assert 'relay_reverse_mux_streams 2' in during_metrics.decode().splitlines()
            time.sleep(2)
            ping = socket.create_connection(('127.0.0.1', public), timeout=2)
            sockets.append(ping)
            ping.sendall(b'unrelated-ping')
            try:
                early = ping.recv(4096)
            except socket.timeout:
                early = None
            status, _, body = f.request(f'http://127.0.0.1:{metrics}', '/metrics')
            assert status == 200
            active = next(line for line in body.decode().splitlines()
                          if line.startswith('relay_reverse_mux_streams '))
            held_seconds = time.monotonic() - held_start
            slow.close()
            ping.settimeout(4)
            late = ping.recv(4096) if early is None else b''
            result = {'passed': early == b'unrelated-ping',
                      'neighbor_echo_with_two_active_streams': True,
                      'neighbor_echo_before_idle_deadline_seconds': round(early_latency, 6),
                      'baseline_echo_passed': True, 'configured_idle_timeout_seconds': 1,
                      'slow_reader_held_seconds': round(held_seconds, 3),
                      'unrelated_stream_timed_out_after_seconds': 2 if early is None else None,
                      'unrelated_reply_before_slow_reader_closed': None if early is None else early.decode(),
                      'unrelated_reply_after_slow_reader_closed': late.decode(),
                      'active_stream_metric_before_close': active,
                      'maximum_backend_bytes_offered': 32 * 1024 * 1024}
            assert result['passed'], result
            assert active == 'relay_reverse_mux_streams 1', active
            ping.close()
            time.sleep(1.2)
            _, _, closed_metrics = f.request(f'http://127.0.0.1:{metrics}', '/metrics')
            assert 'relay_reverse_mux_streams 0' in closed_metrics.decode().splitlines()
            # Reverse direction: the target accepts but stops reading upload.
            upload = socket.create_connection(('127.0.0.1', public), timeout=2)
            sockets.append(upload)
            upload.sendall(b'upload')
            assert upload_started.wait(2)
            def send_upload():
                try:
                    for _ in range(2048):
                        upload.sendall(b'u' * 16384)
                except OSError:
                    pass
            sender = threading.Thread(target=send_upload, daemon=True)
            sender.start()
            time.sleep(2)
            with socket.create_connection(('127.0.0.1', public), timeout=2) as other:
                other.sendall(b'neighbor-of-upload')
                assert other.recv(4096) == b'neighbor-of-upload'
            upload.close()
            release_upload.set()
            sender.join(timeout=3)
            assert not sender.is_alive()
            time.sleep(1.2)
            _, _, final_metrics = f.request(f'http://127.0.0.1:{metrics}', '/metrics')
            assert 'relay_reverse_mux_streams 0' in final_metrics.decode().splitlines()
            result.update(slow_target_neighbor_echo_passed=True,
                          active_streams_after_cleanup=0,
                          upload_maximum_bytes_offered=32 * 1024 * 1024)
            args.output.write_text(json.dumps(result, indent=2) + '\n')
            print(json.dumps(result, indent=2))

        finally:
            release_upload.set()
            for conn in sockets:
                conn.close()
            for process in reversed(processes):
                f.stop(process)
            target.shutdown()
            target.server_close()
            for log in logs:
                log.close()


if __name__ == '__main__':
    main()
