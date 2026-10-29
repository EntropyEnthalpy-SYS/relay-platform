#!/usr/bin/env python3
"""Independent-client SS forwarding, UoT and write-half-close acceptance.

Requires the optional compatibility client from build_ss_compat_client.py.
Every attempted sample is retained; a failed required check exits nonzero.
"""
import argparse
import base64
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time
from check_shadowsocks_interop import Associate, METHODS, key, free_port, wait_port, socks, exchange, echo_server, udp_echo_server


def delayed_echo():
    listener = socket.socket(); listener.bind(('127.0.0.1', 0)); listener.listen()
    def handle(stream):
        with stream:
            stream.settimeout(10); data = bytearray()
            while block := stream.recv(65536):
                data.extend(block)
                if len(data) > 8 * 1024 * 1024: return
            time.sleep(.1)
            stream.sendall(data)
    def accept():
        while True:
            stream, _ = listener.accept()
            threading.Thread(target=handle, args=(stream,), daemon=True).start()
    threading.Thread(target=accept, daemon=True).start()
    return listener.getsockname()[1]


def run(args):
    results = []; processes = []; logs = []; completed = False
    def record(case, passed, **details):
        results.append(dict(case=case, passed=bool(passed), **details))
        print(json.dumps(results[-1]), flush=True)
    with tempfile.TemporaryDirectory(prefix='relay-ss-uot-') as temp:
        temp = Path(temp); echo = echo_server(); delayed = delayed_echo(); udp = udp_echo_server(); rules = []; entries = {}
        for method in METHODS:
            ports = [free_port() for _ in range(3)]; entries[method] = ports[0]
            for hop, port in enumerate(ports):
                rule = {'id':f'{method}-{hop}', 'tenant_id':'default','owner_id':'admin','name':'SS UoT acceptance', 'protocol':'both','listen':f'127.0.0.1:{port}','targets':[], 'meter_epoch':'uot','connect_timeout_ms':2000,'idle_timeout_secs':10}
                if hop < 2: rule['targets'] = [{'address':f'127.0.0.1:{ports[hop+1]}'}]
                else: rule['inbound_shadowsocks'] = {'method':method,'password':key(method),'allow_private_destinations':True,'udp_over_tcp':True}
                rules.append(rule)
        variants = {}; base_rule = rules[-1]
        for name, changes in [('disabled',{'udp_over_tcp':False}),('private',{'allow_private_destinations':False}),('acl',{}),('quota',{}),('domain-allow',{})]:
            port = free_port(); variants[name] = port
            rule = {**base_rule, 'id':name, 'listen':f'127.0.0.1:{port}', 'inbound_shadowsocks':{**base_rule['inbound_shadowsocks'], **changes}}
            if name == 'acl': rule['deny_destinations'] = ['127.0.0.0/8']
            if name == 'quota': rule['quota_bytes'] = 64
            if name == 'domain-allow': rule['allow_destinations'] = ['localhost']
            rules.append(rule)
        config = temp/'relay.json'; config.write_text(json.dumps({'api_version':1,'node_id':'uot-acceptance','revision':1,'rules':rules}))
        log = (temp/'relay.log').open('wb'); logs.append(log)
        relay = subprocess.Popen([args.binary,'standalone','--config',config,'--database',temp/'state.db'],stdout=log,stderr=log); processes.append(relay)
        try:
            wait_port(entries[METHODS[0]],relay)
            def client(method, server, version=2, engine=None):
                local = free_port(); path = temp/f'client-{local}.json'
                outbound = {'type':'shadowsocks','tag':'test','server':'127.0.0.1','server_port':server,'method':method,'password':key(method)}
                if version: outbound['udp_over_tcp'] = {'enabled':True,'version':version}
                path.write_text(json.dumps({'log':{'level':'error'},'inbounds':[{'type':'socks','listen':'127.0.0.1','listen_port':local}], 'outbounds':[outbound],'route':{'final':'test'}})); path.chmod(0o600)
                log = (temp/f'client-{local}.log').open('wb'); logs.append(log)
                process = subprocess.Popen([engine or args.client,'run','-c',path],stdout=log,stderr=log); processes.append(process);wait_port(local,process)
                return local
            payload = bytes(range(251))*419
            if args.stock_client:
                port = client(METHODS[1],entries[METHODS[1]],engine=args.stock_client)
                received = exchange(socks(port,'127.0.0.1',delayed),payload)
                record('upstream-client-half-close-control',received != payload, expected_failure=True, received_bytes=len(received), expected_bytes=len(payload))
            for method in METHODS:
                port = client(method,entries[method])
                for kind, origin in [('echo',echo),('reply-after-request-FIN',delayed)]:
                    received = exchange(socks(port,'127.0.0.1',origin),payload)
                    record('TCP-half-close-'+kind,received==payload,method=method,received_bytes=len(received),expected_bytes=len(payload))
                for version in [2,1,0]:
                    proxy = port if version==2 else client(method,entries[method],version)
                    association=Associate(proxy); rows=[]
                    try:
                        for n in [0,1,64,512,1200,1400,4096,8192]:
                            data=(bytes(range(251))*max(1,n))[:n]
                            response=association.exchange('127.0.0.1',udp,data)
                            rows.append({'bytes':n,'passed':response is not None and response[0]==('127.0.0.1',udp) and response[1]==data})
                        response=association.exchange('localhost',udp,b'domain')
                        rows.append({'destination':'localhost','passed':response is not None and response[1]==b'domain'})
                    finally:association.close()
                    record('UDP-framing',all(row['passed'] for row in rows),method=method,version=version,samples=rows)
                    if version == 2:
                        association = Associate(proxy)
                        sent = [bytes([i]) + bytes(512 + i * 107) for i in range(16)]
                        received = []
                        try:
                            for data in sent: association.send('127.0.0.1', udp, data)
                            for _ in sent:
                                try: received.append(association.udp.recvfrom(65535)[0][10:])
                                except socket.timeout: break
                        finally: association.close()
                        record('UoT-interleaved-burst',len(received)==len(sent) and set(received)==set(sent),method=method,sent=len(sent),received=len(received))

            method=METHODS[-1]
            for name,server in variants.items():
                proxy=client(method,server);association=Associate(proxy)
                try: response=association.exchange('127.0.0.1',udp,b'X'*100)
                finally:association.close()
                record('UoT-reject-'+name,response is None)
            # Native UDP must apply the same explicit destination ACL.
            proxy=client(method,variants['acl'],version=0);association=Associate(proxy)
            try:response=association.exchange('127.0.0.1',udp,b'acl')
            finally:association.close()
            record('native-UDP-destination-ACL',response is None)
            for version in [0,2]:
                proxy=client(method,variants['domain-allow'],version=version);association=Associate(proxy)
                try:response=association.exchange('localhost',udp,b'allowed-domain')
                finally:association.close()
                record('UDP-domain-allowlist',response is not None and response[1]==b'allowed-domain',version=version)

            completed = True
        finally:
            for process in reversed(processes):
                process.terminate()
                try:process.wait(timeout=5)
                except subprocess.TimeoutExpired:process.kill();process.wait()
            for log in logs:log.close()
            if args.output:
                Path(args.output).write_text(json.dumps({'checks':results,'completed':completed,'passed':completed and bool(results) and all(r['passed'] for r in results)},indent=2)+'\n')
    return all(r['passed'] for r in results)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--binary',required=True);p.add_argument('--client',required=True);p.add_argument('--stock-client');p.add_argument('--output');a=p.parse_args()
    raise SystemExit(0 if run(a) else 1)
