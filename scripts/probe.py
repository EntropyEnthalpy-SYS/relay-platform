#!/usr/bin/env python3
"""Verify an authorized TCP/UDP echo relay, failing loudly on any mismatch."""
import argparse
import json
import secrets
import socket


def probe(host, port):
    payload = b'relay-probe:' + secrets.token_bytes(32)
    with socket.create_connection((host, port), timeout=5) as tcp:
        tcp.sendall(payload)
        tcp.shutdown(socket.SHUT_WR)
        result = b''
        while data := tcp.recv(1024):
            result += data
            if len(result) > len(payload):
                raise RuntimeError('TCP returned extra bytes')
        if result != payload:
            raise RuntimeError('TCP payload mismatch')
    address = socket.getaddrinfo(host, port, type=socket.SOCK_DGRAM)[0]
    with socket.socket(address[0], address[1], address[2]) as udp:
        udp.settimeout(5)
        udp.connect(address[4])
        udp.send(payload)
        if udp.recv(65536) != payload:
            raise RuntimeError('UDP payload mismatch')
    return {'tcp': 'verified', 'udp': 'verified', 'bytes_each_direction_per_protocol': len(payload)}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=19001)
    args = parser.parse_args()
    print(json.dumps(probe(args.host, args.port)))
