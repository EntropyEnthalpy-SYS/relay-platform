#!/usr/bin/env python3
"""Diagnose IPv4 UDP delivery with bounded probes and NAT-aware Linux captures.

Capture retains headers and hashes only. It must observe a successful round trip
at both endpoints, without capture drops, before locating a failed datagram.
No application datagram is retried and no production firewall is changed.
"""
import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import signal
import socket
import struct
import sys
import time


def packet(frame, direction, peer, ports, at):
    """Decode Ethernet/IPv4; allow the local address to differ from its public IP."""
    if len(frame) < 42 or frame[12:14] != b'\x08\x00':
        return None
    ip = frame[14:]
    header = (ip[0] & 15) * 4
    total = int.from_bytes(ip[2:4], 'big')
    if ip[0] >> 4 != 4 or header < 20 or total < header + 8 or len(ip) < total or ip[9] != 17:
        return None
    source, target = socket.inet_ntoa(ip[12:16]), socket.inet_ntoa(ip[16:20])
    if peer not in (source, target):
        return None
    flags = int.from_bytes(ip[6:8], 'big')
    if flags & 8191:  # A later fragment has no UDP header.
        return None
    sport, dport, length = struct.unpack_from('!HHH', ip, header)
    if length < 8 or not ports.intersection((sport, dport)):
        return None
    body = ip[header + 8:min(header + length, total)]
    return {'time': at, 'direction': direction, 'src': source, 'dst': target,
            'sport': sport, 'dport': dport, 'ip_id': int.from_bytes(ip[4:6], 'big'),
            'bytes': length - 8, 'more_fragments': bool(flags & 8192),
            'captured_payload_bytes': len(body), 'payload_sha256': hashlib.sha256(body).hexdigest(),
            'hash_covers_full_payload': not bool(flags & 8192) and len(body) == length - 8}


def analyze(samples, sender, receiver, sender_stats, receiver_stats, receiver_offset=0., uncertainty=.5):
    """Only name the missing segment when positive controls validate both captures.

receiver_offset is receiver clock minus sender clock, in seconds. Ports must not
be translated by NAT; address translation is supported. Sample windows must not
overlap. Absence after the deadline means not observed in that bounded window.
"""
    def events(rows, sample, direction, offset):
        field = 'dport' if direction == 'request' else 'sport'
        return [r for r in rows if r[field] == sample['port']
                and r['payload_sha256'] == sample['payload_sha256']
                and r['hash_covers_full_payload']
                and sample['sent_at'] - uncertainty <= r['time'] - offset
                <= sample['sent_at'] + sample['elapsed_ms'] / 1000 + uncertainty]

    def stages(sample):
        return [
            [r for r in events(sender, sample, 'request', 0) if r['direction'] == 'out' and r['sport'] == sample['source_port']],
            [r for r in events(receiver, sample, 'request', receiver_offset) if r['direction'] == 'in'],
            [r for r in events(receiver, sample, 'reply', receiver_offset) if r['direction'] == 'out'],
            [r for r in events(sender, sample, 'reply', 0) if r['direction'] == 'in' and r['dport'] == sample['source_port']],
        ]

    positives = [s for s in samples if s['passed'] and all(stages(s))]
    stats_valid = all(s.get('kernel_drops') == 0 and not s.get('truncated', True)
                      for s in (sender_stats, receiver_stats))
    coverage = bool(samples) and all(
        stats.get('started_at', float('inf')) - offset <= min(s['sent_at'] for s in samples) - uncertainty
        and stats.get('ended_at', float('-inf')) - offset >= max(s['sent_at'] + s['elapsed_ms'] / 1000 for s in samples) + uncertainty
        for stats, offset in ((sender_stats, 0), (receiver_stats, receiver_offset)))
    valid = bool(positives) and stats_valid and coverage
    failures = []
    for s in samples:
        if s['passed']:
            continue
        observed = stages(s)
        # A router may fragment a packet that left the sender unfragmented.
        # Its receiver-side prefix hash cannot be compared with the full hash.
        # Any such candidate makes this bounded observation inconclusive.
        fragments = any(not r['hash_covers_full_payload']
            and (r['dport'] == s['port'] or r['sport'] == s['port'])
            and s['sent_at'] - uncertainty <= r['time'] - offset
            <= s['sent_at'] + s['elapsed_ms'] / 1000 + uncertainty
            for rows, offset in ((sender, 0), (receiver, receiver_offset)) for r in rows)
        status = 'unlocalized'
        # Missing/truncated capture evidence must never become a network verdict.
        if fragments:
            status = 'fragmented_datagram_unlocalized'
        if valid and observed[0] and not fragments:
            if not observed[1]:
                status = 'not_observed_at_receiver_interface'
            elif not observed[2]:
                status = 'no_reply_observed_at_receiver_interface'
            elif not observed[3]:
                status = 'reply_not_observed_at_sender_interface'
            else:
                status = 'packet_round_trip_observed_check_client'
        failures.append({'sample': s, 'observation': status, 'stage_packet_counts': list(map(len, observed))})
    return {'passed': bool(samples) and all(s['passed'] for s in samples), 'capture_validated': valid,
            'positive_control_count': len(positives), 'capture_statistics_valid': stats_valid, 'capture_covers_samples': coverage,
            'delivered': sum(s['passed'] for s in samples), 'total': len(samples),
            'failures': failures,
            'limit': 'Interface observations cannot identify a provider, device or policy. '
                     'No retries or warm-up are hidden. Corrected captures do not reclassify older failures.'}


def capture(args):
    stop = False
    def finish(*_):
        nonlocal stop
        stop = True
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, finish)
    count = 0
    started = time.time()
    deadline = time.monotonic() + args.duration
    truncated = False
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
        s.bind((args.interface, 0))
        s.settimeout(.25)
        args.ready.write_text(json.dumps({'started_at': started, 'interface': args.interface}))
        with args.output.open('w') as out:
            while not stop and time.monotonic() < deadline:
                try:
                    frame, link = s.recvfrom(65535)
                except socket.timeout:
                    continue
                row = packet(frame, 'out' if link[2] == 4 else 'in', args.peer, args.ports, time.time())
                if row is None:
                    continue
                out.write(json.dumps(row) + '\n')
                out.flush()
                count += 1
                if count >= args.max_packets:
                    truncated = True
                    break
        received, dropped = struct.unpack('II', s.getsockopt(263, 6, 8))
    args.stats.write_text(json.dumps({'started_at': started, 'ended_at': time.time(),
        'kernel_packets': received, 'kernel_drops': dropped, 'matching_packets': count,
        'truncated': truncated, 'payloads_retained': False, 'interface': args.interface,
        'peer': args.peer, 'ports': sorted(args.ports)}, indent=2) + '\n')


def probe(args):
    samples = []
    for port in sorted(args.ports):
        for index, size in enumerate(args.sizes):
            # Different sockets also distinguish empty datagrams, whose hashes cannot differ.
            data = (bytes([(index + port) % 251]) + bytes(range(251))) * (size // 252 + 1)
            data = data[:size]
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                started = time.time()
                deadline = time.monotonic() + args.timeout
                ok = False
                error = None
                try:
                    s.connect((args.peer, port))
                    if sys.platform == 'linux':
                        s.setsockopt(socket.IPPROTO_IP, getattr(socket, 'IP_MTU_DISCOVER', 10), 0)
                    s.send(data)
                    while time.monotonic() < deadline:
                        s.settimeout(max(.001, deadline - time.monotonic()))
                        reply = s.recv(65535)
                        if reply == data:
                            ok = True
                            break
                except OSError as exc:
                    error = type(exc).__name__
                samples.append({'port': port, 'bytes': size, 'source_port': s.getsockname()[1],
                    'sent_at': started, 'elapsed_ms': (time.time() - started) * 1000,
                    'payload_sha256': hashlib.sha256(data).hexdigest(), 'passed': ok, 'error': error})
    args.output.write_text(json.dumps({'no_datagram_retries': True, 'samples': samples}, indent=2) + '\n')
    return 0 if all(s['passed'] for s in samples) else 1


def ports(text):
    value = {int(x) for x in text.split(',')}
    if not value or len(value) > 32 or any(x < 1 or x > 65535 for x in value):
        raise argparse.ArgumentTypeError('supply 1..32 distinct ports in 1..65535')
    return value


def ipv4(text):
    return str(ipaddress.IPv4Address(text))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    commands = p.add_subparsers(dest='command', required=True)
    c = commands.add_parser('capture', help='Linux root; Ethernet IPv4 UDP metadata only')
    c.add_argument('--interface', required=True)
    c.add_argument('--peer', type=ipv4, required=True)
    c.add_argument('--ports', type=ports, required=True)
    c.add_argument('--output', type=Path, required=True)
    c.add_argument('--stats', type=Path, required=True)
    c.add_argument('--ready', type=Path, required=True)
    c.add_argument('--duration', type=int, default=300)
    c.add_argument('--max-packets', type=int, default=100000)
    c = commands.add_parser('probe', help='send each sample once to a controlled UDP echo')
    c.add_argument('--peer', type=ipv4, required=True)
    c.add_argument('--ports', type=ports, required=True)
    c.add_argument('--sizes', type=lambda s: [int(x) for x in s.split(',')], default=[0, 1, 64, 1200])
    c.add_argument('--timeout', type=float, default=5)
    c.add_argument('--output', type=Path, required=True)
    c = commands.add_parser('analyze', help='offline; requires successful controls at both interfaces')
    for name in ('samples', 'sender', 'receiver', 'sender-stats', 'receiver-stats', 'output'):
        c.add_argument('--' + name, type=Path, required=True)
    c.add_argument('--receiver-offset', type=float, default=0.)
    c.add_argument('--clock-uncertainty', type=float, default=.5)
    a = p.parse_args()
    if a.command == 'capture':
        if not 1 <= a.duration <= 1800 or not 1 <= a.max_packets <= 1000000:
            p.error('capture duration must be 1..1800s; max-packets 1..1000000')
        capture(a)
        return 0
    if a.command == 'probe':
        if not 0 < a.timeout <= 30 or not 1 <= len(a.sizes) <= 32 or any(x < 0 or x > 65507 for x in a.sizes):
            p.error('timeout must be (0,30]; supply 1..32 payload sizes in 0..65507')
        return probe(a)
    if not 0 <= a.clock_uncertainty <= 5:
        p.error('clock uncertainty must be 0..5 seconds')
    result = analyze(json.loads(a.samples.read_text())['samples'],
        [json.loads(x) for x in a.sender.read_text().splitlines()],
        [json.loads(x) for x in a.receiver.read_text().splitlines()],
        json.loads(a.sender_stats.read_text()), json.loads(a.receiver_stats.read_text()),
        a.receiver_offset, a.clock_uncertainty)
    a.output.write_text(json.dumps(result, indent=2) + '\n')
    return 0 if result['passed'] and result['capture_validated'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
