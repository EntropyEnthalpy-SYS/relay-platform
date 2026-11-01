#!/usr/bin/env python3
"""Opt-in root-only NAT traversal test in disposable network namespaces.

A small internet (one switch) joins a public relay node and three home
routers. Each router hides one node behind nftables masquerade on the same
private range and drops unsolicited packets from the internet, like a home
router. Routers A and B keep a node's source port; router C picks a new
random port for every destination, so hole punching through it cannot work.

Checks: with the feature off every pair of NAT'd nodes goes through the
relay; switched on, A and B connect directly while C's pairs fall back to
the relay with a reason; packets lost while A and B switch; the relay no
longer carrying their traffic; TCP and UDP on both kinds of path; a
controller restart leaving the direct path alone; a direct path that stops
working falling back; and cleanup. The controller runs on the host's
loopback and agents reach it through a Unix socket bridge, so the host's own
routes, links and settings are not changed.
"""
import argparse
import json
import os
from pathlib import Path
import re
import secrets
import signal
import socket
import subprocess
import sys
import time
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request, build_opener

from check_linux_wireguard import BRIDGE, CLIENT, ECHO, _ping, run

PUBLIC = {'p': '203.0.113.1', 'ra': '203.0.113.2', 'rb': '203.0.113.3', 'rc': '203.0.113.4'}
HOMES = [('ra', 'a', 'masquerade'), ('rb', 'b', 'masquerade'), ('rc', 'c', 'masquerade fully-random')]
ROUTER = '''table inet relaynat {{
  chain input {{ type filter hook input priority 0; policy accept; iifname "{wan}" ct state established,related accept; iifname "{wan}" drop; }}
  chain forward {{ type filter hook forward priority 0; policy drop; iifname "{lan}" accept; iifname "{wan}" ct state established,related accept; }}
  chain postrouting {{ type nat hook postrouting priority 100; oifname "{wan}" {nat}; }}
}}
'''
PING_INTERVAL = 0.05


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
    names = {role: f'relaynt{role}-{suffix}' for role in ['w', 'p', 'ra', 'a', 'rb', 'b', 'rc', 'c']}
    namespaces, processes, handles = [], [], []
    result = {'method': 'Disposable network namespaces with kernel WireGuard and nftables NAT; not a WAN or real-NAT test'}

    def ns(role, *command, **kwargs):
        return run('ip', 'netns', 'exec', names[role], *command, **kwargs)

    def start(filename, command, env=None):
        handle = (root / filename).open('w')
        handles.append(handle)
        child = subprocess.Popen(list(map(str, command)), stdout=handle, stderr=subprocess.STDOUT, env=env)
        processes.append(child)
        return child

    def links(role):
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
        ns('w', 'ip', 'link', 'add', 'br0', 'type', 'bridge')
        ns('w', 'ip', 'link', 'set', 'br0', 'up')
        wan = {}
        for role, address in PUBLIC.items():
            switch_side, wan[role] = f'nt{role}w{suffix}', f'nt{role}x{suffix}'
            run('ip', 'link', 'add', switch_side, 'netns', names['w'], 'type', 'veth', 'peer', 'name', wan[role], 'netns', names[role])
            ns('w', 'ip', 'link', 'set', switch_side, 'master', 'br0')
            ns('w', 'ip', 'link', 'set', switch_side, 'up')
            ns(role, 'ip', 'address', 'add', f'{address}/24', 'dev', wan[role])
            ns(role, 'ip', 'link', 'set', wan[role], 'up')
        for router, node, nat in HOMES:
            lan, inside = f'nt{node}l{suffix}', f'nt{node}n{suffix}'
            run('ip', 'link', 'add', lan, 'netns', names[router], 'type', 'veth', 'peer', 'name', inside, 'netns', names[node])
            ns(router, 'ip', 'address', 'add', '192.168.1.1/24', 'dev', lan)
            ns(router, 'ip', 'link', 'set', lan, 'up')
            ns(node, 'ip', 'address', 'add', '192.168.1.2/24', 'dev', inside)
            ns(node, 'ip', 'link', 'set', inside, 'up')
            ns(node, 'ip', 'route', 'add', 'default', 'via', '192.168.1.1')
            ns(router, 'sysctl', '-qw', 'net.ipv4.ip_forward=1')
            ns(router, 'nft', '-f', '-', input=ROUTER.format(wan=wan[router], lan=lan, nat=nat))
        before = {role: routes(role) for role in ['p', 'a', 'b', 'c']}

        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0))
            port = probe.getsockname()[1]
        state = root / 'controller'
        controller_command = [binary, 'server', '--listen', f'127.0.0.1:{port}', '--state', state]
        controller = start('controller.log', controller_command)
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
        nodes = {}
        # The production poll interval: path switches rely on the watch waking agents.
        env = {**os.environ, 'RELAY_WIREGUARD': '1', 'RUST_LOG': 'info'}
        for role in ['p', 'a', 'b', 'c']:
            created = api('POST', '/nodes', {'name': f'nt-{role}'})
            nodes[role] = created['node']['id']
            secret = root / f'enroll-{role}.secret'
            secret.write_text(created['enrollment_token'])
            start(f'bridge-{role}.log', ['ip', 'netns', 'exec', names[role], sys.executable, '-c', BRIDGE, 'tcp', sock, port])
            until(f'bridge in {role}', lambda: f'127.0.0.1:{port} ' in ns(role, 'ss', '-Hlnt'))
            start(f'agent-{role}.log', ['ip', 'netns', 'exec', names[role], binary, 'agent', '--controller', origin, '--node-id', nodes[role],
                                        '--state', root / f'agent-{role}', '--enrollment-token-file', secret], env)

        def view():
            return api('GET', '/wireguard')
        until('agents online', lambda: all(n['last_seen_ms'] for n in api('GET', '/nodes')))
        api('PUT', '/features/nat-traversal', {'enabled': True}, status=409)
        api('PUT', '/features/wireguard', {'enabled': True})
        until('node keys', lambda: all(n['key_reported'] for n in view()['nodes']), 60)
        network = api('POST', '/wireguard/networks', {'name': 'lab', 'cidr': '10.88.0.0/24'})
        address, keys = {}, {}
        for role in ['p', 'a', 'b', 'c']:
            body = {'kind': 'node', 'node_id': nodes[role]}
            if role == 'p':
                body['endpoint'] = PUBLIC['p']
            address[role] = api('POST', f'/wireguard/networks/{network["id"]}/members', body)['address']
        interface = 'rwg-' + network['id'].replace('-', '')[:8]
        result['addresses'] = address

        def members_up():
            return all(m['state'] == 'up' for m in view()['networks'][0]['members'])
        until('members up', members_up, 60)

        def dump(role):
            """Peer public key -> (endpoint, allowed IPs, rx, tx)."""
            peers = {}
            for line in ns(role, 'wg', 'show', interface, 'dump').splitlines()[1:]:
                fields = line.split('\t')
                peers[fields[0]] = (fields[2], fields[3], int(fields[5]), int(fields[6]))
            return peers
        for role in ['p', 'a', 'b', 'c']:
            keys[role] = ns(role, 'wg', 'show', interface, 'public-key').strip()

        def carrier(role, target):
            """The peer of `role` whose allowed IPs hold `target`'s address."""
            for key, (_, allowed, _, _) in dump(role).items():
                if f'{address[target]}/32' in allowed.split(','):
                    return next(r for r, k in keys.items() if k == key)

        def pairs():
            return {(x['a'], x['b']): x for x in view()['networks'][0]['pairs']}
        for role in ['b', 'c']:
            start(f'echo-{role}.log', ['ip', 'netns', 'exec', names[role], sys.executable, '-c', ECHO, 7000])
        for source, target in [('a', 'b'), ('a', 'c'), ('b', 'c')]:
            until(f'relayed ping {source}->{target}', lambda: _ping(ns, source, address[target]), 30)

        # Off: every pair of NAT'd nodes goes through the relay, and no node
        # has an entry for another NAT'd node.
        time.sleep(6)
        for role in ['a', 'b', 'c']:
            assert list(dump(role)) == [keys['p']], (role, dump(role))
        assert all(pairs()[pair]['path'] == 'relayed' for pair in [('nt-a', 'nt-b'), ('nt-a', 'nt-c'), ('nt-b', 'nt-c')])

        # On: A and B punch through; C's NAT defeats it and its pairs stay
        # relayed with a reason. A ping every 50 ms measures the switch.
        ping = start('ping-a-b.log', ['ip', 'netns', 'exec', names['a'], 'ping', '-n', '-O', '-W', '1', '-i', PING_INTERVAL, address['b']])
        switched_on = time.monotonic()
        api('PUT', '/features/nat-traversal', {'enabled': True})

        def punched():
            ab = pairs()[('nt-a', 'nt-b')]
            return ab if ab['path'] == 'direct' and ab.get('punched') else None
        until('A and B direct', punched, 120)
        result['seconds_to_direct'] = round(time.monotonic() - switched_on, 1)

        def refused():
            table = pairs()
            ac, bc = table[('nt-a', 'nt-c')], table[('nt-b', 'nt-c')]
            return [ac, bc] if all(x['path'] == 'relayed' and 'hole punching failed' in (x.get('reason') or '') for x in [ac, bc]) else None
        failed = until("C's pairs back on the relay", refused, 120)
        result['seconds_to_c_fallback'] = round(time.monotonic() - switched_on, 1)
        result['c_pairs'] = [{k: x.get(k) for k in ('path', 'via', 'reason', 'retry_in_s')} for x in failed]
        assert all(250 <= x['retry_in_s'] <= 300 for x in failed), failed
        time.sleep(3)
        ping.send_signal(signal.SIGINT)
        ping.wait(timeout=10)
        log = (root / 'ping-a-b.log').read_text()
        answered = {int(n) for n in re.findall(r'icmp_seq=(\d+) ttl=', log)}
        sent = max(int(n) for n in re.findall(r'icmp_seq=(\d+)', log))
        streak = longest = 0
        for seq in range(1, sent + 1):
            streak = 0 if seq in answered else streak + 1
            longest = max(longest, streak)
        result['ping_during_switch'] = {'sent': sent, 'lost': sent - len(answered), 'longest_gap_ms': round(longest * PING_INTERVAL * 1000)}
        assert longest * PING_INTERVAL < 2, result['ping_during_switch']

        a_peers, b_peers = dump('a'), dump('b')
        assert a_peers[keys['b']][:2] == (f'{PUBLIC["rb"]}:51820', f'{address["b"]}/32'), a_peers
        assert b_peers[keys['a']][:2] == (f'{PUBLIC["ra"]}:51820', f'{address["a"]}/32'), b_peers
        assert sorted(a_peers) == sorted([keys['p'], keys['b']]), 'the failed probe towards C left an entry'
        assert carrier('a', 'c') == 'p' and carrier('c', 'a') == 'p' and carrier('a', 'b') == 'b'

        # The relay no longer carries A and B's traffic.
        relay_before = dump('p')
        result['tcp_udp_a_to_b_direct'] = json.loads(ns('a', sys.executable, '-c', CLIENT, address['b'], 7000))
        relay_after = dump('p')
        carried = sum(relay_after[keys[r]][2] + relay_after[keys[r]][3] - relay_before[keys[r]][2] - relay_before[keys[r]][3] for r in ['a', 'b'])
        result['relay_bytes_during_a_to_b_transfer'] = carried
        assert carried < 16384, carried
        result['tcp_udp_a_to_c_relayed'] = json.loads(ns('a', sys.executable, '-c', CLIENT, address['c'], 7000))
        result['ping_rtt_ms'] = {'a->b direct': _ping(ns, 'a', address['b']), 'a->c relayed': _ping(ns, 'a', address['c'])}

        # A controller restart rebuilds the state from reports without
        # sending A and B back to the relay.
        controller.terminate()
        controller.wait(timeout=15)
        restarted_at = time.monotonic()
        start('controller-restarted.log', controller_command)
        token = until('login after restart', login)['token']
        samples = 0
        while time.monotonic() - restarted_at < 25:
            assert carrier('a', 'b') == 'b' and carrier('b', 'a') == 'a', 'a restart moved A and B back to the relay'
            samples += 1
            time.sleep(0.5)
        until('direct after restart', punched, 30)
        result['restart_samples_still_direct'] = samples

        # A direct path that stops working falls back: B stops hearing A.
        ns('rb', 'nft', '-f', '-', input=f'table inet relayblock {{\n  chain pre {{ type filter hook prerouting priority -300; ip saddr {PUBLIC["ra"]} udp dport 51820 drop; }}\n}}\n')
        blocked_at = time.monotonic()

        def fell_back():
            ab = pairs()[('nt-a', 'nt-b')]
            return ab if ab['path'] == 'relayed' and 'received nothing' in (ab.get('reason') or '') else None
        result['silent_fallback'] = {k: v for k, v in until('silent direct path back on the relay', fell_back, 150).items() if k in ('path', 'via', 'reason', 'retry_in_s')}
        result['seconds_to_silent_fallback'] = round(time.monotonic() - blocked_at, 1)
        until('relay carries A and B again', lambda: carrier('a', 'b') == 'p' and carrier('b', 'a') == 'p', 15)
        result['ping_after_fallback_ms'] = until('ping after fallback', lambda: _ping(ns, 'a', address['b']), 20)
        ns('rb', 'nft', 'delete', 'table', 'inet', 'relayblock')

        # Cleanup: nothing outside the agent's own links changed.
        api('PUT', '/features/wireguard', {'enabled': False}, status=409)
        api('DELETE', f'/wireguard/networks/{network["id"]}')
        api('PUT', '/features/nat-traversal', {'enabled': False})
        api('PUT', '/features/wireguard', {'enabled': False})
        until('links removed', lambda: not any(link.startswith('rwg-') for r in ['p', 'a', 'b', 'c'] for link in links(r)), 30)
        for role in ['p', 'a', 'b', 'c']:
            assert routes(role) == before[role], f'{role}: routes outside the WireGuard link changed'
            assert ns(role, 'cat', '/proc/sys/net/ipv4/ip_forward').strip() == '0', f'{role}: server-wide forwarding changed'
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


if __name__ == '__main__':
    main()
