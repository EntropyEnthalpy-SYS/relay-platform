#!/usr/bin/env python3
"""Check the Shadowsocks server against the shadowsocks-rust client (sslocal).

TCP client -> SOCKS5 -> sslocal -> relay standalone -> echo, and the same for
UDP through SOCKS5 UDP ASSOCIATE, for every method, by IP and by domain name,
plus the rejections: private destinations under the default policy, a wrong
key and a replayed request or datagram. A 2022 association must follow its
client to a new address. Only loopback sockets, temporary state and child
processes are used. Download sslocal from
https://github.com/shadowsocks/shadowsocks-rust/releases and check its .sha256.
"""
import argparse
import base64
import hashlib
import json
import platform
import socket
import struct
import subprocess
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from bench_budget import free_port

METHODS = ['2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm', '2022-blake3-chacha20-poly1305',
           'aes-128-gcm', 'aes-256-gcm', 'chacha20-ietf-poly1305']
PAYLOAD = bytes((index * 31 + 7) % 256 for index in range(4 * 1024 * 1024 + 37))
# Datagram sizes: empty, small, typical MTU-bound payloads and near the limit.
DATAGRAM_SIZES = [0, 1, 64, 512, 1200, 1400, 1472, 4096, 16384, 60000]


def key(method):
    if not method.startswith('2022-'):
        return 'interop password'
    return base64.b64encode(hashlib.sha256(method.encode()).digest()[:16 if '128' in method else 32]).decode()


def wait_port(port, process):
    until = time.monotonic() + 15
    while time.monotonic() < until:
        if process.poll() is not None:
            raise RuntimeError('child exited before listening')
        try:
            socket.create_connection(('127.0.0.1', port), timeout=1).close()
            return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError(f'port {port} never opened')


def echo_server():
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen(64)

    def serve(connection):
        with connection:
            while data := connection.recv(1 << 16):
                connection.sendall(data)
            connection.shutdown(socket.SHUT_WR)

    def accept():
        while True:
            connection, _ = listener.accept()
            threading.Thread(target=serve, args=(connection,), daemon=True).start()

    threading.Thread(target=accept, daemon=True).start()
    return listener.getsockname()[1]


def udp_echo_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(('127.0.0.1', 0))

    def serve():
        while True:
            data, peer = server.recvfrom(65535)
            server.sendto(data, peer)

    threading.Thread(target=serve, daemon=True).start()
    return server.getsockname()[1]


def socks_address(host, port):
    try:
        address = b'\x01' + socket.inet_aton(host)
    except OSError:
        address = b'\x03' + bytes([len(host)]) + host.encode()
    return address + struct.pack('>H', port)


class Associate:
    """A SOCKS5 UDP ASSOCIATE through sslocal, open while its TCP control
    connection is."""

    def __init__(self, port):
        self.control = socket.create_connection(('127.0.0.1', port), timeout=10)
        self.control.sendall(b'\x05\x01\x00')
        if self.control.recv(2) != b'\x05\x00':
            raise RuntimeError('sslocal refused the SOCKS method')
        self.control.sendall(b'\x05\x03\x00\x01' + bytes(6))
        reply = self.control.recv(10)
        if reply[:2] != b'\x05\x00':
            raise RuntimeError('sslocal refused UDP ASSOCIATE')
        self.relay = (socket.inet_ntoa(reply[4:8]), struct.unpack('>H', reply[8:10])[0])
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.settimeout(2)

    def send(self, host, port, payload):
        self.udp.sendto(b'\x00\x00\x00' + socks_address(host, port) + payload, self.relay)

    def exchange(self, host, port, payload):
        """Returns (source, payload) of the reply, or None after 2 s."""
        self.send(host, port, payload)
        try:
            data, _ = self.udp.recvfrom(65535)
        except socket.timeout:
            return None
        if data[3] != 1:
            raise RuntimeError('reply source is not an IPv4 address')
        return (socket.inet_ntoa(data[4:8]), struct.unpack('>H', data[8:10])[0]), data[10:]

    def close(self):
        self.udp.close()
        self.control.close()


def socks(port, host, destination_port):
    """Opens a SOCKS5 CONNECT; returns the socket or None when refused."""
    s = socket.create_connection(('127.0.0.1', port), timeout=10)
    s.sendall(b'\x05\x01\x00')
    if s.recv(2) != b'\x05\x00':
        raise RuntimeError('sslocal refused the SOCKS method')
    try:
        address = b'\x01' + socket.inet_aton(host)
    except OSError:
        address = b'\x03' + bytes([len(host)]) + host.encode()
    s.sendall(b'\x05\x01\x00' + address + struct.pack('>H', destination_port))
    if s.recv(10)[:2] != b'\x05\x00':
        raise RuntimeError('sslocal refused the SOCKS request')
    return s


def exchange(s, payload):
    """Sends payload, half-closes, and returns everything echoed until EOF."""
    def send():
        s.sendall(payload)
        s.shutdown(socket.SHUT_WR)
    sender = threading.Thread(target=send)
    sender.start()
    received = bytearray()
    try:
        while data := s.recv(1 << 20):
            received += data
    except OSError:
        pass
    sender.join()
    s.close()
    return bytes(received)


def run(args):
    binary, sslocal = args.binary.resolve(), args.sslocal.resolve()
    echo, udp_echo = echo_server(), udp_echo_server()
    cases, udp_cases, negatives, processes = [], [], {}, []
    with tempfile.TemporaryDirectory(prefix='relay-ss-interop-') as temporary:
        scratch = Path(temporary)
        ports = {method: free_port() for method in METHODS}
        guarded = free_port()
        rules = [{'id': f'ss{index}', 'tenant_id': 'default', 'owner_id': 'admin', 'name': method,
                  'listen': f'127.0.0.1:{ports[method]}', 'protocol': 'both', 'targets': [],
                  'meter_epoch': 'interop', 'connect_timeout_ms': 2000,
                  'inbound_shadowsocks': {'method': method, 'password': key(method),
                                          'allow_private_destinations': True}}
                 for index, method in enumerate(METHODS)]
        rules.append({**rules[1], 'id': 'guarded', 'listen': f'127.0.0.1:{guarded}',
                      'inbound_shadowsocks': {'method': METHODS[1], 'password': key(METHODS[1])}})
        config = scratch / 'config.json'
        config.write_text(json.dumps({'api_version': 1, 'node_id': 'interop', 'revision': 1, 'rules': rules}))
        subprocess.run([binary, 'validate', '--config', config], check=True, capture_output=True)
        database = scratch / 'ledger.sqlite'
        log = (scratch / 'relay.log').open('wb')
        relay = subprocess.Popen([binary, 'standalone', '--config', config, '--database', database, '--watch'],
                                 stdout=log, stderr=log)
        processes.append(relay)

        def client(server_port, method, password):
            local = free_port()
            process = subprocess.Popen([sslocal, '-b', f'127.0.0.1:{local}', '-s', f'127.0.0.1:{server_port}',
                                        '-m', method, '-k', password, '-U'],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            processes.append(process)
            wait_port(local, process)
            return local

        try:
            wait_port(guarded, relay)
            expected = 0
            for method in METHODS:
                local = client(ports[method], method, key(method))
                started = time.monotonic()
                by_ip = exchange(socks(local, '127.0.0.1', echo), PAYLOAD) == PAYLOAD
                seconds = time.monotonic() - started
                by_name = exchange(socks(local, 'localhost', echo), PAYLOAD[:65536]) == PAYLOAD[:65536]
                if not (by_ip and by_name):
                    raise RuntimeError(f'{method}: echo differs')
                expected += 2 * (len(PAYLOAD) + 65536)
                cases.append({'method': method, 'bytes_each_direction': len(PAYLOAD), 'by_ip': 'verified',
                              'by_domain_name': 'verified', 'half_close': 'passed',
                              'seconds': round(seconds, 3)})
                associate = Associate(local)
                for size in DATAGRAM_SIZES:
                    payload = bytes((index * 7 + size) % 256 for index in range(size))
                    if associate.exchange('127.0.0.1', udp_echo, payload) != (('127.0.0.1', udp_echo), payload):
                        raise RuntimeError(f'{method}: {size}-byte datagram differs')
                if associate.exchange('localhost', udp_echo, b'by name') != (('127.0.0.1', udp_echo), b'by name'):
                    raise RuntimeError(f'{method}: datagram by name differs')
                associate.close()
                expected += 2 * (sum(DATAGRAM_SIZES) + len(b'by name'))
                udp_cases.append({'method': method, 'datagram_sizes': DATAGRAM_SIZES, 'by_ip': 'verified',
                                  'by_domain_name': 'verified', 'reply_source': 'echo address'})
            local = client(guarded, METHODS[1], key(METHODS[1]))
            negatives['loopback_under_default_policy'] = exchange(socks(local, '127.0.0.1', echo), b'x') == b''
            associate = Associate(local)
            negatives['udp_loopback_under_default_policy'] = associate.exchange('127.0.0.1', udp_echo, b'x') is None
            associate.close()
            wrong = base64.b64encode(bytes(32)).decode()
            local = client(ports[METHODS[1]], METHODS[1], wrong)
            negatives['wrong_key'] = exchange(socks(local, '127.0.0.1', echo), b'x') == b''
            associate = Associate(local)
            negatives['udp_wrong_key'] = associate.exchange('127.0.0.1', udp_echo, b'x') is None
            associate.close()

            # Capture three datagrams of one 2022 session, then send them
            # ourselves: a repeat is dropped, and replies follow the client
            # to a new address.
            grab = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            grab.bind(('127.0.0.1', 0))
            grab.settimeout(5)
            local = client(grab.getsockname()[1], METHODS[1], key(METHODS[1]))
            associate = Associate(local)
            captured = []
            for payload in [b'first', b'second', b'third', b'fourth']:
                associate.send('127.0.0.1', udp_echo, payload)
                captured.append(grab.recvfrom(65535)[0])
            associate.close()
            first, moved = socket.socket(socket.AF_INET, socket.SOCK_DGRAM), socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            def reply(sock):
                sock.settimeout(2)
                try:
                    return len(sock.recv(65535))
                except socket.timeout:
                    return 0
            server = ('127.0.0.1', ports[METHODS[1]])
            first.sendto(captured[0], server)
            got_first = reply(first)
            first.sendto(captured[0], server)
            negatives['udp_replay'] = got_first > 0 and reply(first) == 0
            moved.sendto(captured[2], server)
            negatives['udp_client_moves'] = reply(moved) > 0
            # Arriving after a newer one, the second datagram is still new once.
            moved.sendto(captured[1], server)
            negatives['udp_reordered_once'] = reply(moved) > 0
            moved.sendto(captured[1], server)
            negatives['udp_reordered_replay'] = reply(moved) == 0
            # A rule change ends the association; its packet IDs outlive it.
            config.write_text(json.dumps({'api_version': 1, 'node_id': 'interop', 'revision': 2, 'rules': [
                {**rule, 'rate_bytes_per_sec': 10**9} if rule['id'] == 'ss1' else rule for rule in rules]}))
            time.sleep(4)
            moved.sendto(captured[2], server)
            negatives['udp_replay_after_rule_change'] = reply(moved) == 0
            moved.sendto(captured[3], server)
            negatives['udp_next_datagram_after_rule_change'] = reply(moved) > 0
            # The four delivered datagrams reached the echo and came back.
            expected += 2 * len(b'first' + b'second' + b'third' + b'fourth')

            # Capture one request from sslocal, then send it twice.
            grab = socket.socket()
            grab.bind(('127.0.0.1', 0))
            grab.listen()
            local = client(grab.getsockname()[1], METHODS[1], key(METHODS[1]))
            requester = socks(local, '127.0.0.1', echo)
            requester.sendall(b'replayed')
            captured, _ = grab.accept()
            captured.settimeout(1)
            request = b''
            try:
                while data := captured.recv(65536):
                    request += data
            except socket.timeout:
                pass
            requester.close()
            replies = []
            for _ in range(2):
                s = socket.create_connection(('127.0.0.1', ports[METHODS[1]]), timeout=5)
                s.sendall(request)
                s.settimeout(3)
                try:
                    replies.append(len(s.recv(4096)))
                except socket.timeout:
                    replies.append(-1)
                s.close()
            negatives['replay'] = replies[0] > 0 and replies[1] == 0
            if not all(negatives.values()):
                raise RuntimeError(f'a rejection failed: {negatives}, replies {replies}')
            time.sleep(1.5)
        finally:
            for process in reversed(processes):
                process.terminate()
                process.wait(10)
            log.close()
        rows = json.loads(subprocess.run([binary, 'usage', '--database', database], check=True,
                                         capture_output=True).stdout)
        recorded = sum(row['upload_bytes'] + row['download_bytes'] for row in rows)
        # The first replay copy reaches the echo; its 8 bytes go both ways.
        if recorded != expected + 16:
            raise RuntimeError(f'ledger recorded {recorded} bytes, expected {expected + 16}')
    version = subprocess.run([sslocal, '--version'], capture_output=True, text=True).stdout.strip()
    return {'at_utc': datetime.now(timezone.utc).isoformat(), 'platform': platform.platform(),
            'relay_binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
            'client': version, 'client_sha256': hashlib.sha256(sslocal.read_bytes()).hexdigest(),
            'topology': 'TCP / UDP -> SOCKS5 -> sslocal -> relay standalone -> echo', 'cases': cases,
            'udp_cases': udp_cases,
            'rejections': negatives, 'ledger': {'expected_payload_bytes': expected + 16,
                                                 'recorded_bytes': recorded, 'framing_excluded': True},
            'limits': ['loopback only', 'replay of older-method datagrams is not detected (no timestamp)',
                       'timings include Python client and echo, not a benchmark']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=Path('target/release/relay'))
    parser.add_argument('--sslocal', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = run(args)
    args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + '\n')
    print(json.dumps(result['cases']), json.dumps(result['udp_cases']), json.dumps(result['rejections']),
          json.dumps(result['ledger']))


if __name__ == '__main__':
    main()
