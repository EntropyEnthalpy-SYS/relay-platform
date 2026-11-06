#!/usr/bin/env python3
"""Opt-in root-only WireGuard networking test in disposable network namespaces.

A controller on the host's loopback and three agents, each in its own
namespace: one public node and two nodes that can reach only the public node.
A fourth namespace plays a user device. Checks direct and relayed pairs, a
device behind its hub, TCP and UDP separately, a refused overlapping range,
links the agent does not own, links surviving an agent stop, and cleanup.
Agents reach the controller through a Unix socket bridge, so the host's own
routes, links and settings are not changed.
"""
import argparse
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import time
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request, build_opener


def run(*args, **kwargs):
    return subprocess.run(list(map(str, args)), check=True, capture_output=True, text=True, timeout=30, **kwargs).stdout


# Unix socket <-> loopback TCP, so an agent in a namespace reaches the host's controller.
BRIDGE = r'''
import asyncio,sys
mode,path,port=sys.argv[1],sys.argv[2],int(sys.argv[3])
async def pipe(r,w):
 try:
  while True:
   data=await r.read(65536)
   if not data:break
   w.write(data);await w.drain()
  if w.can_write_eof():w.write_eof()
 except Exception:w.close()
async def handle(r,w):
 try:
  r2,w2=await (asyncio.open_connection('127.0.0.1',port) if mode=='unix' else asyncio.open_unix_connection(path))
 except OSError:
  w.close();return
 await asyncio.gather(pipe(r,w2),pipe(r2,w));w.close();w2.close()
async def main():
 server=await (asyncio.start_unix_server(handle,path) if mode=='unix' else asyncio.start_server(handle,'127.0.0.1',port))
 async with server:await server.serve_forever()
asyncio.run(main())
'''
ECHO = r'''
import socket,sys,threading
port=int(sys.argv[1])
def tcp():
 s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('0.0.0.0',port));s.listen(8)
 while True:
  c,_=s.accept()
  while True:
   data=c.recv(65536)
   if not data:break
   c.sendall(data)
  c.close()
threading.Thread(target=tcp,daemon=True).start()
u=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);u.bind(('0.0.0.0',port))
while True:
 data,peer=u.recvfrom(65536);u.sendto(data,peer)
'''
CLIENT = r'''
import hashlib,json,socket,sys
host,port=sys.argv[1],int(sys.argv[2])
payload=bytes(range(256))*512
s=socket.create_connection((host,port),timeout=10);s.sendall(payload);s.shutdown(socket.SHUT_WR)
data=bytearray()
while True:
 block=s.recv(65536)
 if not block:break
 data.extend(block)
assert data==payload,len(data)
u=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);u.settimeout(2)
datagrams=0
for i in range(20):
 message=b'udp-%d-'%i+bytes(1000)
 for _ in range(3):
  u.sendto(message,(host,port))
  try:
   if u.recv(65536)==message:datagrams+=1;break
  except socket.timeout:pass
assert datagrams==20,datagrams
print(json.dumps({'tcp_bytes_each_way':len(payload),'tcp_sha256':hashlib.sha256(data).hexdigest(),'udp_datagrams':datagrams}))
'''


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', type=Path, required=True)
    p.add_argument('--workdir', type=Path, required=True)
    args = p.parse_args()
    if sys.platform != 'linux' or os.geteuid() != 0:
        p.error('Linux root is required for isolated network namespaces')
    os.umask(0o077)
    root = args.workdir.resolve()
    root.mkdir(parents=True, exist_ok=False)
    binary = args.binary.resolve()
    suffix = secrets.token_hex(3)
    names = {role: f'relaywg{role}-{suffix}' for role in ['p', 'a', 'b', 'd']}
    namespaces, processes, handles = [], [], []
    result = {'method': 'Disposable network namespaces with kernel WireGuard; not a WAN or real-NAT test'}

    def ns(role, *command):
        return run('ip', 'netns', 'exec', names[role], *command)

    def start(filename, command, env=None):
        handle = (root / filename).open('w')
        handles.append(handle)
        child = subprocess.Popen(list(map(str, command)), stdout=handle, stderr=subprocess.STDOUT, env=env)
        processes.append(child)
        return child

    def wg_links(role):
        return sorted(link['ifname'] for link in json.loads(ns(role, 'ip', '-j', 'link', 'show', 'type', 'wireguard') or '[]'))

    def all_links(role):
        return sorted(link['ifname'] for link in json.loads(ns(role, 'ip', '-j', 'link', 'show') or '[]'))

    def routes(role):
        return sorted(json.dumps(r, sort_keys=True) for r in json.loads(ns(role, 'ip', '-j', '-4', 'route', 'show', 'table', 'all') or '[]')
                      if not r.get('dev', '').startswith('rwg-'))

    def until(what, check, seconds=30):
        deadline = time.monotonic() + seconds
        last = None
        while time.monotonic() < deadline:
            last = check()
            if last:
                return last
            time.sleep(0.25)
        raise RuntimeError(f'timed out waiting for {what}; last {last!r}')

    try:
        for role in names:
            run('ip', 'netns', 'add', names[role])
            namespaces.append(names[role])
            ns(role, 'ip', 'link', 'set', 'lo', 'up')
        # The public node answers on 10.230.0.1; each other namespace has one
        # link to it and no route to the others.
        ns('p', 'ip', 'address', 'add', '10.230.0.1/32', 'dev', 'lo')
        for index, role in enumerate(['a', 'b', 'd'], start=1):
            left, right = f'wgp{role}{suffix}', f'wg{role}p{suffix}'
            run('ip', 'link', 'add', left, 'netns', names['p'], 'type', 'veth', 'peer', 'name', right, 'netns', names[role])
            ns('p', 'ip', 'address', 'add', f'10.230.{index}.1/24', 'dev', left)
            ns('p', 'ip', 'link', 'set', left, 'up')
            ns(role, 'ip', 'address', 'add', f'10.230.{index}.2/24', 'dev', right)
            ns(role, 'ip', 'link', 'set', right, 'up')
            ns(role, 'ip', 'route', 'add', '10.230.0.1/32', 'via', f'10.230.{index}.1')
        # Links an operator made: a WireGuard link with another name and a
        # non-WireGuard link with the agent's prefix. Both must survive.
        ns('a', 'ip', 'link', 'add', 'wg0', 'type', 'wireguard')
        ns('a', 'ip', 'link', 'add', 'rwg-decoy', 'type', 'dummy')
        before = {role: routes(role) for role in ['p', 'a', 'b']}

        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0))
            port = probe.getsockname()[1]
        state = root / 'controller'
        start('controller.log', [binary, 'server', '--listen', f'127.0.0.1:{port}', '--state', state])
        sock = root / 'controller.sock'
        start('bridge-host.log', [sys.executable, '-c', BRIDGE, 'unix', sock, port])
        origin = f'http://127.0.0.1:{port}'
        token = None
        until('host bridge', sock.exists)

        def api(method, path, body=None, status=None):
            headers = {'Content-Type': 'application/json'}
            if token:
                headers['Authorization'] = f'Bearer {token}'
            data = None if body is None else json.dumps(body).encode()
            request = Request(origin + '/api/v1' + path, data=data, headers=headers, method=method)
            try:
                with build_opener(ProxyHandler({})).open(request, timeout=10) as response:
                    if status is not None:
                        raise RuntimeError(f'{method} {path} gave {response.status}, expected {status}')
                    return json.load(response)
            except HTTPError as error:
                if error.code == status:
                    return json.loads(error.read() or b'{}')
                raise RuntimeError(f'{method} {path}: HTTP {error.code} {error.read().decode()}') from None

        until('controller', lambda: (state / 'admin-password.secret').exists())
        def login():
            try:
                return api('POST', '/auth/login', {'username': 'admin', 'password': (state / 'admin-password.secret').read_text().strip()})
            except (OSError, RuntimeError):
                return None
        token = until('login', login)['token']
        nodes, agents = {}, {}
        env = {**os.environ, 'RELAY_WIREGUARD': '1', 'RUST_LOG': 'info'}

        def start_agent(role, enrollment=True):
            command = ['ip', 'netns', 'exec', names[role], binary, 'agent', '--controller', origin, '--node-id', nodes[role],
                       '--state', root / f'agent-{role}', '--poll-seconds', '1']
            if enrollment:
                command += ['--enrollment-token-file', root / f'enroll-{role}.secret']
            agents[role] = start(f'agent-{role}{"" if enrollment else "-restarted"}.log', command, env)

        for role in ['p', 'a', 'b']:
            created = api('POST', '/nodes', {'name': f'wg-{role}'})
            nodes[role] = created['node']['id']
            secret = root / f'enroll-{role}.secret'
            secret.write_text(created['enrollment_token'])
            start(f'bridge-{role}.log', ['ip', 'netns', 'exec', names[role], sys.executable, '-c', BRIDGE, 'tcp', sock, port])
            until(f'bridge in {role}', lambda: f'127.0.0.1:{port} ' in ns(role, 'ss', '-Hlnt'))
            start_agent(role)
        def view():
            return api('GET', '/wireguard')
        until('agents online', lambda: all(n['last_seen_ms'] for n in api('GET', '/nodes')))

        # Off: writes refused, no keys made, no links.
        api('POST', '/wireguard/networks', {'name': 'lab', 'cidr': '10.88.0.0/24'}, status=409)
        time.sleep(3)
        assert not any(n['key_reported'] for n in view()['nodes']), 'keys made while off'
        assert all(not any(l.startswith('rwg-') and l != 'rwg-decoy' for l in all_links(r)) for r in ['p', 'a', 'b'])
        api('PUT', '/features/wireguard', {'enabled': True})
        until('node keys', lambda: all(n['key_reported'] for n in view()['nodes']))

        network = api('POST', '/wireguard/networks', {'name': 'lab', 'cidr': '10.88.0.0/24'})
        members = {}
        members['p'] = api('POST', f'/wireguard/networks/{network["id"]}/members', {'kind': 'node', 'node_id': nodes['p'], 'endpoint': '10.230.0.1'})
        members['a'] = api('POST', f'/wireguard/networks/{network["id"]}/members', {'kind': 'node', 'node_id': nodes['a']})
        members['b'] = api('POST', f'/wireguard/networks/{network["id"]}/members', {'kind': 'node', 'node_id': nodes['b']})
        device = api('POST', f'/wireguard/networks/{network["id"]}/members', {'kind': 'device', 'name': 'laptop'})
        assert device['via'] == members['p']['id'] and 'PrivateKey = ' in device['config'] and device['qr_svg'].startswith('<?xml')
        address = {role: m['address'] for role, m in members.items()}
        address['d'] = device['address']
        result['addresses'] = address
        interface = 'rwg-' + network['id'].replace('-', '')[:8]

        def states():
            return {m['label']: m['state'] for m in view()['networks'][0]['members']}
        until('members up', lambda: all(s == 'up' for label, s in states().items() if label != 'laptop'))
        for role in ['p', 'a', 'b']:
            assert interface in wg_links(role), (role, wg_links(role))

        # The device applies its wg-quick file by hand.
        config = device['config']
        wanted = [line for line in config.splitlines() if not line.startswith(('Address', 'MTU'))]
        (root / 'device.conf').write_text('\n'.join(wanted) + '\n')
        ns('d', 'ip', 'link', 'add', 'wgdev', 'type', 'wireguard')
        ns('d', 'wg', 'setconf', 'wgdev', root / 'device.conf')
        ns('d', 'ip', 'address', 'add', f'{address["d"]}/24', 'dev', 'wgdev')
        ns('d', 'ip', 'link', 'set', 'wgdev', 'up')

        start('echo-b.log', ['ip', 'netns', 'exec', names['b'], sys.executable, '-c', ECHO, 7000])
        start('echo-p.log', ['ip', 'netns', 'exec', names['p'], sys.executable, '-c', ECHO, 7000])
        pings = {}
        for source, target in [('a', 'p'), ('b', 'p'), ('a', 'b'), ('b', 'a'), ('d', 'b'), ('b', 'd'), ('d', 'p')]:
            output = until(f'ping {source}->{target}', lambda: _ping(ns, source, address[target]), 20)
            pings[f'{source}->{target}'] = output
        result['ping_rtt_ms'] = pings
        result['tcp_udp_a_to_b_relayed'] = json.loads(ns('a', sys.executable, '-c', CLIENT, address['b'], 7000))
        result['tcp_udp_d_to_b_via_hub'] = json.loads(ns('d', sys.executable, '-c', CLIENT, address['b'], 7000))
        result['tcp_udp_a_to_p_direct'] = json.loads(ns('a', sys.executable, '-c', CLIENT, address['p'], 7000))

        # A has no entry for B: their traffic goes through P.
        dump = {role: ns(role, 'wg', 'show', interface, 'dump').splitlines()[1:] for role in ['p', 'a', 'b']}
        a_peers = [line.split('\t') for line in dump['a']]
        assert len(a_peers) == 1 and address['b'] + '/32' in a_peers[0][3], a_peers
        assert len(dump['p']) == 3, dump['p']
        assert ns('p', 'cat', f'/proc/sys/net/ipv4/conf/{interface}/forwarding').strip() == '1'
        assert ns('a', 'cat', f'/proc/sys/net/ipv4/conf/{interface}/forwarding').strip() == '0'
        assert ns('p', 'cat', '/proc/sys/net/ipv4/ip_forward').strip() == '0', 'server-wide forwarding changed'
        for role in ['p', 'a', 'b']:
            assert routes(role) == before[role], f'{role}: routes outside the WireGuard link changed'
        assert 'wg0' in wg_links('a') and 'rwg-decoy' in all_links('a') and 'rwg-decoy' not in wg_links('a')

        def pairs():
            current = view()['networks'][0]
            table = {(x['a'], x['b']): x for x in current['pairs']}
            ab = table.get(('wg-a', 'wg-b'))
            return table if ab and ab['path'] == 'relayed' and ab.get('handshake_age_s') is not None and \
                all(x.get('handshake_age_s') is not None for x in current['pairs']) else None
        table = until('pair handshakes reported', pairs, 40)
        result['pairs'] = {f'{a}<->{b}': {k: v for k, v in x.items() if k in ('path', 'via', 'handshake_age_s')} for (a, b), x in table.items()}
        assert table[('wg-a', 'wg-b')]['via'] == 'wg-p'
        assert table[('wg-p', 'wg-a')]['path'] == 'direct'
        assert table[('wg-p', 'laptop')]['path'] == 'direct'
        assert {m['label']: m['state'] for m in view()['networks'][0]['members']}['laptop'] == 'connected'

        # Device settings on the kernel: the laptop makes way for a phone with
        # network DNS, a preshared key, its own allowed IPs and keepalive.
        ns('d', 'ip', 'link', 'del', 'wgdev')
        api('PUT', f'/wireguard/networks/{network["id"]}', {'name': 'lab', 'dns': ['10.88.0.53']})
        phone = api('POST', f'/wireguard/networks/{network["id"]}/members', {'kind': 'device', 'name': 'phone',
            'allowed_ips': [address['p'] + '/32'], 'keepalive': 7, 'preshared_key': True})
        config = phone['config']
        for line in ['DNS = 10.88.0.53', f'AllowedIPs = {address["p"]}/32', 'PersistentKeepalive = 7']:
            assert line in config.splitlines(), (line, config)
        wanted = [line for line in config.splitlines() if not line.startswith(('Address', 'MTU', 'DNS'))]
        (root / 'phone.conf').write_text('\n'.join(wanted) + '\n')
        ns('d', 'ip', 'link', 'add', 'wgdev', 'type', 'wireguard')
        ns('d', 'wg', 'setconf', 'wgdev', root / 'phone.conf')
        ns('d', 'ip', 'address', 'add', f'{phone["address"]}/24', 'dev', 'wgdev')
        ns('d', 'ip', 'link', 'set', 'wgdev', 'up')
        phone_key = ns('d', 'wg', 'show', 'wgdev', 'public-key').strip()
        hub_psk = lambda: dict(line.split('\t') for line in ns('p', 'wg', 'show', interface, 'preshared-keys').splitlines())
        until('phone peer on the hub', lambda: phone_key in hub_psk())
        assert [k for k, v in hub_psk().items() if v != '(none)'] == [phone_key], 'preshared key on the wrong peers'
        result['phone_ping_p_with_psk'] = until('phone ping with preshared key', lambda: _ping(ns, 'd', address['p']), 20)
        assert _ping(ns, 'd', address['b']) is None, 'phone reached an address outside its allowed IPs'
        assert ns('d', 'wg', 'show', 'wgdev', 'persistent-keepalive').split()[-1] == '7'
        # Switched off, the hub drops the phone's peer; switched on, the same configuration works again.
        api('PUT', f'/wireguard/members/{phone["id"]}', {'kind': 'device', 'name': 'phone', 'enabled': False})
        until('phone peer removed', lambda: phone_key not in hub_psk())
        assert _ping(ns, 'd', address['p']) is None, 'switched-off phone still reaches the hub'
        assert {m['label']: m['state'] for m in view()['networks'][0]['members']}['phone'] == 'disabled'
        api('PUT', f'/wireguard/members/{phone["id"]}', {'kind': 'device', 'name': 'phone', 'enabled': True})
        result['phone_ping_after_switch_on'] = until('phone ping after switch on', lambda: _ping(ns, 'd', address['p']), 20)

        # A range that overlaps A's own link is refused on A, and nothing is made.
        clash = api('POST', '/wireguard/networks', {'name': 'clash', 'cidr': '10.230.1.0/24', 'listen_port': 51821})
        api('POST', f'/wireguard/networks/{clash["id"]}/members', {'kind': 'node', 'node_id': nodes['a']})
        def refused():
            for n in view()['networks']:
                if n['id'] == clash['id'] and n['members'][0]['state'] == 'error':
                    return n['members'][0]['error']
        result['overlap_refusal'] = until('overlap refusal', refused)
        assert 'overlaps the address 10.230.1.2/24' in result['overlap_refusal']
        # The refusal stays with its own network: A's other network is still up.
        until('other network still up', lambda: {m['label']: m['state'] for n in view()['networks'] if n['id'] == network['id'] for m in n['members']}['wg-a'] == 'up')
        assert wg_links('a') == sorted(['wg0', interface]), wg_links('a')
        api('DELETE', f'/wireguard/networks/{clash["id"]}')

        # Stopping an agent leaves its link and traffic running.
        agents['a'].terminate()
        agents['a'].wait(timeout=15)
        assert interface in wg_links('a')
        result['ping_while_agent_a_stopped'] = until('ping with agent stopped', lambda: _ping(ns, 'a', address['b']), 20)
        start_agent('a', enrollment=False)

        # Removing a member, then the network, removes exactly the owned links.
        api('DELETE', f'/wireguard/members/{device["id"]}')
        api('DELETE', f'/wireguard/members/{members["b"]["id"]}')
        until('b link removed', lambda: interface not in wg_links('b'))
        # A revoked node removes its own links and nothing else.
        credential = api('GET', f'/nodes/{nodes["a"]}/credential')
        api('POST', f'/nodes/{nodes["a"]}/credential/revoke', {'operation_id': 'wireguard-check-revoke',
            'expected_revision': credential['revision'], 'reason': 'WireGuard check'})
        until('revoked node removed its link', lambda: interface not in wg_links('a'))
        assert 'wg0' in wg_links('a') and 'rwg-decoy' in all_links('a'), all_links('a')
        api('PUT', '/features/wireguard', {'enabled': False}, status=409)
        api('DELETE', f'/wireguard/networks/{network["id"]}')
        until('all links removed', lambda: interface not in wg_links('p'))
        api('PUT', '/features/wireguard', {'enabled': False})
        time.sleep(3)
        assert wg_links('a') == ['wg0'] and 'rwg-decoy' in all_links('a'), all_links('a')
        for role in ['p', 'a', 'b']:
            assert routes(role) == before[role], f'{role}: routes changed after cleanup'
        result['passed'] = True
        result['build'] = json.loads(run(binary, 'build-info'))
        (root / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps(result, indent=2))
    finally:
        for child in reversed(processes):
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()
        for handle in handles:
            handle.close()
        for name in reversed(namespaces):
            run('ip', 'netns', 'delete', name)
        (root / 'cleanup.json').write_text(json.dumps({'removed_namespaces': namespaces,
            'children_stopped': all(p.poll() is not None for p in processes)}, indent=2) + '\n')


def _ping(ns, role, target):
    try:
        output = ns(role, 'ping', '-c', '3', '-i', '0.2', '-W', '1', target)
    except subprocess.CalledProcessError:
        return None
    for line in output.splitlines():
        if 'min/avg/max' in line:
            return float(line.split('=')[1].split('/')[1])
    return None


if __name__ == '__main__':
    main()
