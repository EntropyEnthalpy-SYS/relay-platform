"""Prevent false network verdicts from NAT, empty packets or incomplete captures."""
import copy
import hashlib
import json
import tempfile
import threading
from types import SimpleNamespace
from pathlib import Path
import socket
import struct
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from check_udp_path import analyze, packet, probe


def frame(source='194.0.2.1', target='100.64.1.2', sport=40001, dport=29000, body=b'', fragment=0):
    udp = struct.pack('!HHHH', sport, dport, len(body) + 8, 0) + body
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, len(udp) + 20, 42, fragment, 64, 17, 0,
                     socket.inet_aton(source), socket.inet_aton(target))
    return bytes(12) + b'\x08\x00' + ip + udp


class UdpDiagnostics(unittest.TestCase):
    def test_nat_address_and_zero_payload_are_kept(self):
        row = packet(frame(), 'in', '194.0.2.1', {29000}, 10)
        self.assertEqual(row['dst'], '100.64.1.2')
        self.assertEqual(row['bytes'], 0)
        self.assertEqual(row['payload_sha256'], hashlib.sha256(b'').hexdigest())
        self.assertTrue(row['hash_covers_full_payload'])

    def test_unrelated_ports_peers_and_malformed_frames_are_excluded(self):
        self.assertIsNone(packet(frame(), 'in', '192.0.2.7', {29000}, 10))
        self.assertIsNone(packet(frame(), 'in', '194.0.2.1', {29001}, 10))
        for data in (b'', frame()[:30], frame()[:-1]):
            self.assertIsNone(packet(data, 'in', '194.0.2.1', {29000}, 10))

    def test_fragments_cannot_claim_a_full_hash(self):
        self.assertFalse(packet(frame(fragment=8192), 'in', '194.0.2.1', {29000}, 10)['hash_covers_full_payload'])
        self.assertIsNone(packet(frame(fragment=1), 'in', '194.0.2.1', {29000}, 10))

    def test_probe_preserves_empty_and_binary_payloads(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as echo, tempfile.TemporaryDirectory() as folder:
            echo.bind(('127.0.0.1', 0));echo.settimeout(2)
            received=[]
            def serve():
                for _ in range(3):
                    data, peer=echo.recvfrom(65535);received.append(data);echo.sendto(data,peer)
            worker=threading.Thread(target=serve);worker.start()
            out=Path(folder)/'samples.json'
            args=SimpleNamespace(peer='127.0.0.1',ports={echo.getsockname()[1]},sizes=[0,1,1200],timeout=1,output=out)
            try:self.assertEqual(probe(args),0)
            finally:worker.join(3)
            self.assertEqual([len(x) for x in received],[0,1,1200])
            self.assertTrue(all(s['passed'] for s in json.loads(out.read_text())['samples']))

    def test_probe_keeps_failed_sample_and_does_not_resend(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sink, tempfile.TemporaryDirectory() as folder:
            sink.bind(('127.0.0.1',0));sink.settimeout(.03)
            out=Path(folder)/'samples.json'
            args=SimpleNamespace(peer='127.0.0.1',ports={sink.getsockname()[1]},sizes=[0],timeout=.03,output=out)
            self.assertEqual(probe(args),1)
            self.assertEqual(sink.recvfrom(100)[0],b'')
            with self.assertRaises(socket.timeout):sink.recvfrom(100)
            result=json.loads(out.read_text())
            self.assertEqual(len(result['samples']),1)
            self.assertFalse(result['samples'][0]['passed'])

    def evidence(self):
        samples = [{'port':29000, 'source_port':40001, 'sent_at':10., 'elapsed_ms':1000,
                    'payload_sha256':hashlib.sha256(b'x').hexdigest(), 'passed':True},
                   {'port':29000, 'source_port':40002, 'sent_at':15., 'elapsed_ms':1000,
                    'payload_sha256':hashlib.sha256(b'').hexdigest(), 'passed':False}]
        request=packet(frame(body=b'x'), 'out', '194.0.2.1', {29000}, 10.1)
        reply=packet(frame(source='100.64.1.2', target='194.0.2.1', sport=29000, dport=40001, body=b'x'), 'in', '194.0.2.1', {29000}, 10.9)
        sender=[request, reply, packet(frame(sport=40002), 'out', '194.0.2.1', {29000}, 15.1)]
        receiver=[{**request,'direction':'in','time':10.3},{**reply,'direction':'out','time':10.7}]
        stats={'kernel_drops':0,'truncated':False,'started_at':9.,'ended_at':17.}
        return samples,sender,receiver,stats,copy.deepcopy(stats)

    def test_valid_controls_locate_missing_ingress_without_claiming_provider(self):
        result=analyze(*self.evidence())
        self.assertTrue(result['capture_validated'])
        self.assertFalse(result['passed'])
        self.assertEqual(result['failures'][0]['observation'],'not_observed_at_receiver_interface')

    def test_router_fragmentation_cannot_be_mistaken_for_missing_ingress(self):
        a=list(self.evidence())
        a[2].append({**a[1][-1], 'direction':'in', 'time':15.2, 'hash_covers_full_payload':False})
        result=analyze(*a)
        self.assertTrue(result['capture_validated'])
        self.assertEqual(result['failures'][0]['observation'],'fragmented_datagram_unlocalized')

    def test_original_public_ip_filter_cannot_locate_loss(self):
        a=list(self.evidence());a[2]=[]
        result=analyze(*a)
        self.assertFalse(result['capture_validated'])
        self.assertEqual(result['failures'][0]['observation'],'unlocalized')

    def test_capture_drops_limits_and_missing_stats_fail_closed(self):
        for change in ({'kernel_drops':1}, {'truncated':True}, {}):
            a=list(self.evidence());a[4]=change
            result=analyze(*a)
            self.assertFalse(result['capture_validated'])
            self.assertEqual(result['failures'][0]['observation'],'unlocalized')

    def test_capture_ending_before_failed_sample_is_not_valid(self):
        a=list(self.evidence());a[4]['ended_at']=14.
        result=analyze(*a)
        self.assertFalse(result['capture_covers_samples'])
        self.assertEqual(result['failures'][0]['observation'],'unlocalized')

    def test_clock_offset_and_source_port_are_respected(self):
        a=list(self.evidence())
        for r in a[2]:r['time']+=2
        a[4]['started_at']+=2;a[4]['ended_at']+=2
        self.assertTrue(analyze(*a,receiver_offset=2)['capture_validated'])
        a[1][-1]['sport']=44444
        self.assertEqual(analyze(*a,receiver_offset=2)['failures'][0]['observation'],'unlocalized')


if __name__=='__main__':unittest.main()
