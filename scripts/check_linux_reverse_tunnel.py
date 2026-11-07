#!/usr/bin/env python3
"""Opt-in root-only reverse tunnel test in disposable network namespaces.

A small internet (one switch) joins a public node, a client and a home
router. The router hides a private node and a LAN host behind nftables
masquerade and drops every unsolicited packet from the internet, so nothing
can connect in to the private node. Both nodes run real agents; the
controller runs on the host's loopback and agents reach it through a Unix
socket bridge, so the host's own routes, links and settings are not changed.

Checks: the router really drops inbound connections; a panel-managed
reverse tunnel delivers the client's TCP and UDP to an echo service on the
LAN host (192.168.10.20) and a second tunnel to one on the private node
itself (127.0.0.1), both over one outbound tunnel connection on the shared
tunnel port; the tunnel token never crosses the router's WAN link in clear;
the public end is metered; the private node connects again after the public
node's agent restarts; disabling closes the public port and the outbound
connection; and cleanup.
"""
import argparse
import json
import os
from pathlib import Path
import secrets
import socket
import sqlite3
import subprocess
import sys
import time
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request, build_opener

from check_linux_wireguard import BRIDGE, CLIENT, ECHO, run
from check_linux_nat_traversal import ROUTER

INTERNET = {'p': '203.0.113.1', 'r': '203.0.113.2', 'c': '203.0.113.3'}
LAN = {'h': '192.168.10.2', 'l': '192.168.10.20'}
# Every frame on the router's WAN link, for the token check.
SNIFF = r'''
import socket,sys,time
s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3));s.bind((sys.argv[1],0));s.settimeout(0.5)
with open(sys.argv[2],'ab',buffering=0) as out:
 while True:
  try:out.write(s.recv(65536))
  except socket.timeout:pass
'''
# One TCP connection attempt: "open", "refused" or "silent" (dropped).
PROBE = r'''
import socket,sys
s=socket.socket();s.settimeout(2)
try:s.connect((sys.argv[1],int(sys.argv[2])));print('open')
except ConnectionRefusedError:print('refused')
except OSError:print('silent')
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
    names = {role: f'relayrt{role}-{suffix}' for role in ['w', 'p', 'c', 'r', 'h', 'l']}
    namespaces, processes, handles = [], [], []
    result = {'method': 'Disposable network namespaces with nftables NAT; not a WAN or real-NAT test'}

    def ns(role, *command, **kwargs):
        return run('ip', 'netns', 'exec', names[role], *command, **kwargs)

    def start(filename, command, env=None):
        handle = (root / filename).open('w')
        handles.append(handle)
        child = subprocess.Popen(list(map(str, command)), stdout=handle, stderr=subprocess.STDOUT, env=env)
        processes.append(child)
        return child

    def until(what, check, seconds=30):
        deadline = time.monotonic() + seconds
        last = None
        while time.monotonic() < deadline:
            last = check()
            if last:
                return last
            time.sleep(0.25)
        raise RuntimeError(f'timed out waiting for {what}; last {last!r}')

    def probe(role, host, port):
        return ns(role, sys.executable, '-c', PROBE, host, port).strip()

    def tunnel_connections():
        """Established connections from the private node to the tunnel port."""
        return len(ns('h', 'ss', '-Htn', 'state', 'established', 'dst', f'{INTERNET["p"]}:29123').splitlines())

    try:
        for role in names:
            run('ip', 'netns', 'add', names[role])
            namespaces.append(names[role])
            ns(role, 'ip', 'link', 'set', 'lo', 'up')
        ns('w', 'ip', 'link', 'add', 'br0', 'type', 'bridge')
        ns('w', 'ip', 'link', 'set', 'br0', 'up')
        wan = {}
        for role, address in INTERNET.items():
            switch_side, wan[role] = f'rt{role}w{suffix}', f'rt{role}x{suffix}'
            run('ip', 'link', 'add', switch_side, 'netns', names['w'], 'type', 'veth', 'peer', 'name', wan[role], 'netns', names[role])
            ns('w', 'ip', 'link', 'set', switch_side, 'master', 'br0')
            ns('w', 'ip', 'link', 'set', switch_side, 'up')
            ns(role, 'ip', 'address', 'add', f'{address}/24', 'dev', wan[role])
            ns(role, 'ip', 'link', 'set', wan[role], 'up')
        # The home LAN: a bridge in the router joins the private node and the LAN host.
        ns('r', 'ip', 'link', 'add', 'lan0', 'type', 'bridge')
        ns('r', 'ip', 'address', 'add', '192.168.10.1/24', 'dev', 'lan0')
        ns('r', 'ip', 'link', 'set', 'lan0', 'up')
        for role, address in LAN.items():
            router_side, inside = f'rt{role}l{suffix}', f'rt{role}n{suffix}'
            run('ip', 'link', 'add', router_side, 'netns', names['r'], 'type', 'veth', 'peer', 'name', inside, 'netns', names[role])
            ns('r', 'ip', 'link', 'set', router_side, 'master', 'lan0')
            ns('r', 'ip', 'link', 'set', router_side, 'up')
            ns(role, 'ip', 'address', 'add', f'{address}/24', 'dev', inside)
            ns(role, 'ip', 'link', 'set', inside, 'up')
            ns(role, 'ip', 'route', 'add', 'default', 'via', '192.168.10.1')
        ns('r', 'sysctl', '-qw', 'net.ipv4.ip_forward=1')
        ns('r', 'nft', '-f', '-', input=ROUTER.format(wan=wan['r'], lan='lan0', nat='masquerade'))
        router_rules = ns('r', 'nft', 'list', 'ruleset')

        # Echo services: on the LAN host, and on the private node's loopback only.
        start('echo-lan.log', ['ip', 'netns', 'exec', names['l'], sys.executable, '-c', ECHO, 7000])
        start('echo-private.log', ['ip', 'netns', 'exec', names['h'], sys.executable, '-c', ECHO.replace("'0.0.0.0'", "'127.0.0.1'"), 7001])
        until('LAN echo', lambda: ':7000 ' in ns('l', 'ss', '-Hlnt'))
        until('private echo', lambda: '127.0.0.1:7001 ' in ns('h', 'ss', '-Hlnt'))
        # Nothing on the internet can connect in: the router drops it, and the LAN is not routed.
        start('listen-router.log', ['ip', 'netns', 'exec', names['h'], sys.executable, '-c', ECHO, 7002])
        until('private listener', lambda: ':7002 ' in ns('h', 'ss', '-Hlnt'))
        result['inbound_before'] = {'router_wan_from_client': probe('c', INTERNET['r'], 7002), 'router_wan_from_public': probe('p', INTERNET['r'], 7002),
                                    'lan_host_from_client': probe('c', LAN['l'], 7000)}
        assert result['inbound_before'] == {'router_wan_from_client': 'silent', 'router_wan_from_public': 'silent', 'lan_host_from_client': 'silent'}, result['inbound_before']
        assert probe('h', INTERNET['p'], 22) == 'refused', 'the private node reaches the internet'

        with socket.socket() as reserve:
            reserve.bind(('127.0.0.1', 0))
            port = reserve.getsockname()[1]
        state = root / 'controller'
        start('controller.log', [binary, 'server', '--listen', f'127.0.0.1:{port}', '--state', state])
        sock = root / 'controller.sock'
        start('bridge-host.log', [sys.executable, '-c', BRIDGE, 'unix', sock, port])
        origin = f'http://127.0.0.1:{port}'
        token = None
        until('host bridge', sock.exists)

        def api(method, path, body=None):
            headers = {'Content-Type': 'application/json'}
            if token:
                headers['Authorization'] = f'Bearer {token}'
            data = None if body is None else json.dumps(body).encode()
            request = Request(origin + '/api/v1' + path, data=data, headers=headers, method=method)
            try:
                with build_opener(ProxyHandler({})).open(request, timeout=10) as response:
                    return json.load(response)
            except HTTPError as error:
                raise RuntimeError(f'{method} {path}: HTTP {error.code} {error.read().decode()}') from None

        until('controller', lambda: (state / 'admin-password.secret').exists())

        def login():
            try:
                return api('POST', '/auth/login', {'username': 'admin', 'password': (state / 'admin-password.secret').read_text().strip()})
            except (OSError, RuntimeError):
                return None
        token = until('login', login)['token']
        nodes, agents = {}, {}
        env = {**os.environ, 'RUST_LOG': 'info'}

        def agent(role, log):
            command = ['ip', 'netns', 'exec', names[role], binary, 'agent', '--controller', origin, '--node-id', nodes[role],
                       '--state', root / f'agent-{role}', '--enrollment-token-file', root / f'enroll-{role}.secret']
            agents[role] = start(log, command, env)
        for role in ['p', 'h']:
            created = api('POST', '/nodes', {'name': f'rt-{role}'})
            nodes[role] = created['node']['id']
            (root / f'enroll-{role}.secret').write_text(created['enrollment_token'])
            start(f'bridge-{role}.log', ['ip', 'netns', 'exec', names[role], sys.executable, '-c', BRIDGE, 'tcp', sock, port])
            until(f'bridge in {role}', lambda: f'127.0.0.1:{port} ' in ns(role, 'ss', '-Hlnt'))
            agent(role, f'agent-{role}.log')
        public = next(n for n in api('GET', '/nodes') if n['id'] == nodes['p'])
        settings = {**public['profile']['settings'], 'forwarding': {'host': INTERNET['p'], 'listen_ip': None, 'port_start': 20000, 'port_end': 20100, 'public_port_start': None}}
        api('PUT', f'/nodes/{nodes["p"]}/profile', {'expected_revision': public['profile']['revision'], 'name': public['name'], 'settings': settings})
        until('agents online', lambda: all(n['last_seen_ms'] for n in api('GET', '/nodes')))

        # Watch the router's WAN link from before the tunnel exists.
        capture = root / 'wan.bin'
        start('sniff.log', ['ip', 'netns', 'exec', names['r'], sys.executable, '-c', SNIFF, wan['r'], capture])
        until('capture', capture.exists)
        lan = api('POST', '/reverse-tunnels', {'name': 'LAN echo', 'public_node_id': nodes['p'], 'private_node_id': nodes['h'], 'public_port': 20000,
                                               'protocol': 'tcp_udp', 'target': f'{LAN["l"]}:7000'})
        local = api('POST', '/reverse-tunnels', {'name': 'Private echo', 'public_node_id': nodes['p'], 'private_node_id': nodes['h'], 'public_port': 20001,
                                                 'protocol': 'tcp', 'target': '127.0.0.1:7001'})
        result['entries'] = [lan['entry'], local['entry']]
        assert result['entries'] == [f'{INTERNET["p"]}:20000', f'{INTERNET["p"]}:20001'], result['entries']

        def views():
            return {v['id']: v for v in api('GET', '/reverse-tunnels')}

        def connected():
            current = views()
            return current if all(current[t['id']]['state'] == 'connected' for t in [lan, local]) else None
        started = time.monotonic()
        until('both tunnels connected', connected, 60)
        result['seconds_to_connected'] = round(time.monotonic() - started, 1)
        result['client_to_lan_host'] = json.loads(ns('c', sys.executable, '-c', CLIENT, INTERNET['p'], 20000))
        echoed = ns('c', sys.executable, '-c', 'import socket;s=socket.create_connection(("%s",20001),timeout=10);s.sendall(b"private node itself");s.shutdown(1);print(s.recv(100).decode())' % INTERNET['p']).strip()
        assert echoed == 'private node itself', echoed
        result['client_to_private_loopback'] = 'tcp echo ok'
        result['outbound_tunnel_connections'] = tunnel_connections()
        assert result['outbound_tunnel_connections'] == 1, 'both tunnels share one connection'
        # The public end is metered like any rule: 128 KiB each way plus 20 datagrams.
        metered = until('usage reported', lambda: (lambda v: v if v['upload_bytes'] >= 131072 + 20 * 1006 else None)(views()[lan['id']]), 30)
        result['metered'] = {'upload_bytes': metered['upload_bytes'], 'download_bytes': metered['download_bytes']}
        assert metered['download_bytes'] >= 131072 + 20 * 1006, metered

        # The tokens went over the router's WAN link only inside TLS.
        time.sleep(1)
        with sqlite3.connect(f'file:{state / "controller.sqlite"}?mode=ro', uri=True) as db:
            tokens = [db.execute('SELECT value FROM metadata WHERE key=?', (f'reverse_tunnel_token:{t["id"]}',)).fetchone()[0] for t in [lan, local]]
        wire = capture.read_bytes()
        result['wan_bytes_captured'] = len(wire)
        assert len(wire) > 131072 and all(len(t) == 64 for t in tokens)
        assert not any(t.encode() in wire or bytes.fromhex(t) in wire for t in tokens), 'a tunnel token crossed the WAN link in clear'
        assert b'192.168.10.20:7000' not in wire, 'the target crossed the WAN link in clear'

        # The public node's agent restarts: the tunnel drops and the private node connects again.
        agents['p'].terminate()
        agents['p'].wait(timeout=15)
        until('tunnel down', lambda: tunnel_connections() == 0, 30)
        restarted = time.monotonic()
        agent('p', 'agent-p-restarted.log')
        until('tunnels connected again', connected, 60)
        result['seconds_to_reconnect_after_restart'] = round(time.monotonic() - restarted, 1)
        result['client_after_reconnect'] = json.loads(ns('c', sys.executable, '-c', CLIENT, INTERNET['p'], 20000))

        # Disabled: the public port closes; the other tunnel keeps the connection.
        body = {k: lan[k] for k in ['name', 'public_node_id', 'private_node_id', 'public_port', 'protocol', 'target', 'tunnel_port']}
        api('PUT', f'/reverse-tunnels/{lan["id"]}', {**body, 'enabled': False})
        until('public port closed', lambda: probe('c', INTERNET['p'], 20000) == 'refused', 30)
        assert views()[lan['id']]['state'] == 'disabled'
        assert probe('c', INTERNET['p'], 20001) == 'open'
        # Deleting the last tunnel closes the tunnel port and the outbound connection.
        api('DELETE', f'/reverse-tunnels/{local["id"]}')
        until('tunnel port closed', lambda: probe('c', INTERNET['p'], 29123) == 'refused' and tunnel_connections() == 0, 30)
        api('DELETE', f'/reverse-tunnels/{lan["id"]}')
        assert api('GET', '/reverse-tunnels') == []
        assert probe('c', INTERNET['p'], 20001) == 'refused'
        assert ns('r', 'nft', 'list', 'ruleset') == router_rules, 'the router changed'
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
