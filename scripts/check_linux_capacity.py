#!/usr/bin/env python3
"""Opt-in Linux/systemd acceptance lab; all services use isolated state and unit names.
Resource caps apply only to relay processes. curl and the local HTTP origin run
outside those caps. Results are workload evidence, not a universal VPS minimum.
"""
import argparse
import concurrent.futures
import hashlib
import http.server
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import statistics
import subprocess
import tempfile
import threading
import time
import uuid
import urllib.request
import urllib.error


def run(*args, **kwargs):
    return subprocess.run(list(map(str, args)), check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, **kwargs).stdout


def save(path, obj):
    path.write_text(json.dumps(obj, indent=2) + '\n')


def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


class Origin(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_GET(self):
        if self.path == '/browser-proxy':
            data=b'relay-browser-proxy-accepted'; self.send_response(200); self.send_header('Content-Length',str(len(data))); self.end_headers(); self.wfile.write(data); return
        size = int(self.path.rsplit('/', 1)[-1]) if self.path.startswith('/bytes/') else 1024
        size = max(0, min(size, 16 * 1024 * 1024))
        self.send_response(200)
        self.send_header('Content-Length', str(size))
        self.send_header('Connection', 'close')
        self.end_headers()
        block = b'x' * 65536
        try:
            while size:
                data = block[:min(size, len(block))]
                self.wfile.write(data)
                size -= len(data)
        except (BrokenPipeError, ConnectionResetError):
            pass


class OriginServer(http.server.ThreadingHTTPServer):
    # The origin must accept the complete 64-client load without its default
    # five-connection listen backlog becoming the test's bottleneck.
    request_queue_size = 256
    daemon_threads = True


class Unit:
    def __init__(self, name, memory, command, root):
        self.name = name + '.service'
        self.memory = memory
        self.root = root
        run('systemd-run', '--quiet', '--unit', self.name, '--collect',
            '-p', 'CPUQuota=100%', '-p', 'AllowedCPUs=0', '-p', f'MemoryMax={memory}M', '-p', 'MemorySwapMax=0',
            '-p', 'TasksMax=128', '-p', 'NoNewPrivileges=yes', '-p', 'LimitNOFILE=8192',
            '--setenv=TOKIO_WORKER_THREADS=1', '--setenv=RUST_LOG=warn', *command)

    def snapshot(self):
        raw = run('systemctl', 'show', self.name, '-p', 'MainPID', '-p', 'ControlGroup', '-p', 'ActiveState', '-p', 'AllowedCPUs', '-p', 'MemoryMax')
        values = dict(line.split('=', 1) for line in raw.splitlines() if '=' in line)
        pid = int(values.get('MainPID', '0'))
        result = {'active': values.get('ActiveState'), 'pid': pid, 'memory_limit_mib': self.memory, 'effective_memory_max':values.get('MemoryMax'), 'allowed_cpus':values.get('AllowedCPUs')}
        if pid:
            try:
                status = Path(f'/proc/{pid}/status').read_text()
                for field in ('VmRSS', 'VmHWM', 'Threads'):
                    result[field] = int(next(line for line in status.splitlines() if line.startswith(field + ':')).split()[1])
                result['fds'] = len(list(Path(f'/proc/{pid}/fd').iterdir()))
                cgroup = Path('/sys/fs/cgroup') / values['ControlGroup'].lstrip('/')
                for name in ('memory.current', 'memory.peak'):
                    result[name] = int((cgroup / name).read_text())
                result['memory.events'] = dict((k, int(v)) for k,v in (line.split() for line in (cgroup / 'memory.events').read_text().splitlines()))
                result['cpu.stat'] = dict((k, int(v)) for k,v in (line.split() for line in (cgroup / 'cpu.stat').read_text().splitlines()))
            except (OSError, StopIteration):
                result['sampling_race'] = True
        return result

    def stop(self):
        subprocess.run(['systemctl', 'stop', self.name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        log = subprocess.run(['journalctl', '-u', self.name, '--no-pager', '-o', 'cat', '-n', '100'], capture_output=True, text=True)
        (self.root / (self.name + '.log')).write_text(log.stdout)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--workdir', type=Path, required=True)
    parser.add_argument('--public-host', required=True)
    parser.add_argument('--client-ip', required=True)
    parser.add_argument('--endurance-seconds', type=int, default=600)
    parser.add_argument('--socket-buffer-bytes', type=int, default=131072,
                        help='per-direction HTTP/2 socket buffer request; 0 keeps OS autotuning')
    parser.add_argument('--steady-rounds', type=int, default=3,
                        help='independent 64-reader rounds; every round must pass')
    parser.add_argument('--protocol-engine', type=Path, help='also run six managed gateways in the agent cgroup; profiles become 64/128/192/256 MiB')
    parser.add_argument('--start-soak-immediately', action='store_true', help='do not wait for an external coordination file')
    args = parser.parse_args()
    if args.endurance_seconds < 10 or args.endurance_seconds > 86400:
        parser.error('endurance-seconds must be 10..86400')
    if args.socket_buffer_bytes != 0 and not 16384 <= args.socket_buffer_bytes <= 4194304:
        parser.error('socket-buffer-bytes must be 0 or 16384..4194304')
    if not 1 <= args.steady_rounds <= 20:
        parser.error('steady-rounds must be 1..20')
    os.umask(0o077)
    root = args.workdir.resolve(); root.mkdir(parents=True, exist_ok=False)
    evidence = root / 'evidence'; evidence.mkdir()
    binary = args.binary.resolve()
    prefix = 'relay-lab-' + secrets.token_hex(3)
    results = {'build': json.loads(run(binary, 'build-info')), 'profiles': [], 'controller_profiles': [],
               'method': 'One CPU quota, no swap; local curl/origin outside relay cgroup. No network-emulation or bare-VPS claim.'}
    save(evidence / 'capacity.json', results)
    password = secrets.token_hex(24); password_path = root / 'admin.secret'; password_path.write_text(password)
    token = secrets.token_hex(32); user, proxy_password = 'lab', secrets.token_hex(24)
    tls = root / 'tls'; (tls / 'server').mkdir(parents=True); (tls / 'root').mkdir()
    run('openssl','req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-days','2',
        '-subj','/CN=Relay isolated acceptance CA','-addext','basicConstraints=critical,CA:TRUE',
        '-keyout',tls/'root/key.pem','-out',tls/'root/ca.pem')
    run('openssl','req','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-subj','/CN=relay.lab',
        '-keyout',tls/'server/key.pem','-out',tls/'server/request.pem')
    ext = tls/'server/ext.cnf'; ext.write_text(f'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1,IP:{args.public_host}\n')
    run('openssl','x509','-req','-in',tls/'server/request.pem','-CA',tls/'root/ca.pem','-CAkey',tls/'root/key.pem',
        '-CAcreateserial','-days','2','-extfile',ext,'-out',tls/'server/cert.pem')
    for key in tls.rglob('key.pem'): key.chmod(0o600)
    origin = OriginServer(('127.0.0.1',0), Origin)
    threading.Thread(target=origin.serve_forever, daemon=True).start()
    origin_port = origin.server_address[1]
    udp_origin = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_origin.bind(('127.0.0.1',0))
    udp_port = udp_origin.getsockname()[1]
    def echo_udp():
        while True:
            try:
                data, peer = udp_origin.recvfrom(65536)
                udp_origin.sendto(data, peer)
            except OSError: return
    threading.Thread(target=echo_udp,daemon=True).start()
    https_origin = OriginServer(('127.0.0.1',0), Origin)
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain(tls/'server/cert.pem',tls/'server/key.pem')
    https_origin.socket=context.wrap_socket(https_origin.socket,server_side=True)
    threading.Thread(target=https_origin.serve_forever,daemon=True).start()
    https_port=https_origin.server_address[1]
    controller_port, h2_port, tcp_port = free_port(), free_port(), free_port()
    controller_url = f'http://127.0.0.1:{controller_port}'
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    auth = None
    def api(path, body=None, method=None):
        headers={'Content-Type':'application/json'}
        if auth: headers['Authorization']='Bearer '+auth
        req=urllib.request.Request(controller_url+'/api/v1'+path, None if body is None else json.dumps(body).encode(), headers, method=method)
        with opener.open(req,timeout=8) as response: return json.load(response)
    def ready(port, unit):
        for _ in range(150):
            if unit.snapshot()['active'] not in ('active','activating'): raise RuntimeError('unit exited during startup')
            try:
                with socket.create_connection(('127.0.0.1',port), timeout=.1): return
            except OSError: time.sleep(.1)
        raise RuntimeError('listener not ready')
    units=[]
    controller=None; agent=None
    try:
        for memory in (64,128):
            unit=Unit(prefix+f'-controller-{memory}', memory, [binary,'server','--state',root/f'controller-{memory}',
                '--listen',f'127.0.0.1:{controller_port}','--admin-password-file',password_path],evidence); units.append(unit)
            entry={'memory_mib':memory}
            try:
                ready(controller_port,unit)
                login=api('/auth/login',{'username':'admin','password':password}); auth=login['token']; owner=login['user']['id']
                latencies=[]
                for _ in range(100):
                    start=time.perf_counter(); api('/nodes'); latencies.append((time.perf_counter()-start)*1000)
                entry.update(passed=True,latency_p50_ms=statistics.median(latencies),latency_p95_ms=sorted(latencies)[94],snapshot=unit.snapshot())
                controller=unit
            except Exception as error:
                entry.update(passed=False,error=type(error).__name__,snapshot=unit.snapshot());unit.stop()
            results['controller_profiles'].append(entry); save(evidence/'capacity.json',results)
            if controller: break
        if not controller: raise RuntimeError('controller did not start in tested profiles')
        created=api('/nodes',{'name':'Managed HTTP2 Linux acceptance','lease_policy':None,'settings':{}})
        node_id=created['node']['id']; enrollment=root/'enrollment.secret';enrollment.write_text(created['enrollment_token'])
        base={'tenant_id':'default','owner_id':owner,'protocol':'tcp','enabled':True,'quota_bytes':None,
              'expires_at_ms':None,'rate_bytes_per_sec':None,'meter_epoch':'linux-acceptance','connect_timeout_ms':10000,
              'idle_timeout_secs':60,'max_connections':256,'allow_sources':['127.0.0.0/8',args.client_ip+'/32']}
        h2={**base,'id':'h2-linux','name':'Managed HTTP2 TLS','listen':f'0.0.0.0:{h2_port}','targets':[],
            'inbound_tls':{'identity':'server','client_ca':None},
            'inbound_http2_connect':{'username':user,'password':proxy_password,'bearer_token_sha256':[hashlib.sha256(token.encode()).hexdigest()],
                                    'allow_private_destinations':True,'max_concurrent_streams':128,
                                    'socket_buffer_bytes':args.socket_buffer_bytes or None},
            'allow_destinations':['127.0.0.1/32'],'allow_destination_ports':[str(origin_port),str(https_port)]}
        tcp={**base,'id':'tcp-linux','name':'TCP Linux baseline','listen':f'127.0.0.1:{tcp_port}',
             'targets':[{'address':f'127.0.0.1:{origin_port}','weight':1}]}
        rules=[h2,tcp]
        gateways=[]
        if args.protocol_engine:
            for kind in ('vless','hysteria2','tuic','any_tls','trojan','vmess'):
                credential={'type':kind}
                if kind in ('vless','vmess','tuic'): credential['uuid']=str(uuid.uuid4())
                if kind in ('hysteria2','tuic','any_tls','trojan'): credential['password']=secrets.token_hex(24)
                port=free_port()
                rule={**base,'id':'gateway-'+kind,'name':kind,'protocol':'tcp' if kind=='any_tls' else 'both',
                      'listen':f'127.0.0.1:{free_port()}','targets':[],
                      'allow_destinations':['127.0.0.1/32'],'allow_destination_ports':[str(origin_port),str(https_port),str(udp_port)],
                      'protocol_gateway':{'listen':f'0.0.0.0:{port}','protocol':credential,
                          'security':{'type':'certificate','identity':'server','server_name':args.public_host},'allow_private_destinations':True}}
                rules.append(rule)
                outbound={'type':'anytls' if kind=='any_tls' else kind,'tag':kind,'server':args.public_host,'server_port':port,
                          **{k:v for k,v in credential.items() if k!='type'},
                          'tls':{'enabled':True,'server_name':args.public_host,'certificate':[ (tls/'root/ca.pem').read_text() ]}}
                if kind in ('hysteria2','tuic'):
                    outbound['tls']['alpn']=['h3']
                    outbound['initial_packet_size']=1200
                if kind=='vmess':outbound['security']='auto'
                gateways.append(outbound)
            save(root/'gateway-clients.private.json',{'outbounds':gateways,'origin_port':origin_port,'https_origin_port':https_port,'udp_port':udp_port})
            results['method'] += ' Optional shared sing-box child included in each agent memory/CPU cap.'
        api(f'/nodes/{node_id}/config',{'expected_revision':0,'rules':rules},'PUT')
        agent_state=root/'agent'
        def launch_agent(memory,label):
            command=[binary,'agent','--controller',controller_url,'--node-id',node_id,
                '--state',agent_state,'--enrollment-token-file',enrollment,'--poll-seconds','1','--tls-directory',tls]
            if args.protocol_engine: command=['/usr/bin/env','RELAY_PROTOCOL_ENGINE='+str(args.protocol_engine.resolve()),*command]
            unit=Unit(prefix+'-agent-'+label,memory,command,evidence)
            units.append(unit)
            try:
                ready(h2_port,unit)
                return unit
            except Exception:
                unit.stop()
                raise
        def curl(kind,size,auth_kind='bearer',public=False,slow=False):
            command=['curl','--silent','--show-error','--fail','--connect-timeout','5','--max-time','95' if slow else '25','--noproxy','','--output','/dev/null','--write-out','%{json}']
            if kind=='h2':
                command += ['--proxy-http2','--proxytunnel','--proxy',f'https://{args.public_host if public else "127.0.0.1"}:{h2_port}','--proxy-cacert',str(tls/'root/ca.pem')]
                if auth_kind=='basic':command+=['--proxy-user',user+':'+proxy_password]
                else:command+=['--proxy-header','Proxy-Authorization: Bearer '+(token if auth_kind=='bearer' else 'invalid')]
                port=origin_port
            else:port=tcp_port
            if slow:command += ['--limit-rate','256k']
            command += [f'http://127.0.0.1:{port}/bytes/{size}']
            completed=subprocess.run(command,capture_output=True,text=True)
            value=json.loads(completed.stdout or '{}')
            return {'ok':completed.returncode==0 and int(value.get('size_download',0))==size,
                'exit_code':completed.returncode,'bytes':int(value.get('size_download',0)),
                'connect_status':value.get('http_connect'),'seconds':value.get('time_total'),
                'time_connect':value.get('time_connect'),'time_appconnect':value.get('time_appconnect'),'time_starttransfer':value.get('time_starttransfer'),
                'error':completed.stderr[:200] if completed.returncode else None}
        def gateway_batch(unit):
            # Client and HTTP origin are load generators outside the measured
            # agent cgroup. The managed server engine remains inside it.
            ports={out['tag']:free_port() for out in gateways}
            outbounds=[{**out,'server':'127.0.0.1'} for out in gateways]
            document={'log':{'level':'error'},'inbounds':[{'type':'socks','tag':name,'listen':'127.0.0.1','listen_port':port} for name,port in ports.items()],
                'outbounds':outbounds,'route':{'rules':[{'inbound':[name],'action':'route','outbound':name} for name in ports]+[{'action':'reject'}]}}
            with tempfile.TemporaryDirectory(prefix='gateway-load-',dir=root) as directory:
                config=Path(directory)/'config.json';save(config,document)
                process=subprocess.Popen([str(args.protocol_engine),'run','-c',str(config)],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
                    env={**os.environ,'GOMAXPROCS':'1','GOMEMLIMIT':'96MiB'})
                try:
                    for port in ports.values():
                        for _ in range(100):
                            if process.poll() is not None: raise RuntimeError('gateway load client exited')
                            try:
                                with socket.create_connection(('127.0.0.1',port),timeout=.1):break
                            except OSError:time.sleep(.05)
                        else:raise RuntimeError('gateway load client startup timed out')
                    def transfer(name):
                        size=1024*1024
                        completed=subprocess.run(['curl','--silent','--show-error','--fail','--connect-timeout','5','--max-time','25','--noproxy','',
                            '--socks5-hostname',f'127.0.0.1:{ports[name]}',f'http://127.0.0.1:{origin_port}/bytes/{size}'],capture_output=True)
                        return {'protocol':name,'ok':completed.returncode==0 and completed.stdout==b'x'*size,
                            'bytes':len(completed.stdout),'exit_code':completed.returncode,'error':completed.stderr.decode(errors='replace')[:200]}
                    before=unit.snapshot();start=time.monotonic()
                    with concurrent.futures.ThreadPoolExecutor(max_workers=24) as pool:
                        transfers=list(pool.map(transfer,list(ports)*4))
                    elapsed=time.monotonic()-start
                    return {'method':'24 concurrent connections, four per gateway protocol, 1 MiB exact body each; client/origin outside agent cgroup',
                        'passed':all(p['ok'] for p in transfers),'seconds':elapsed,'mbps':sum(p['bytes'] for p in transfers)*8/elapsed/1e6,
                        'before':before,'after':unit.snapshot(),'transfers':transfers}
                finally:
                    process.terminate()
                    try:process.wait(timeout=5)
                    except subprocess.TimeoutExpired:process.kill();process.wait()
        for memory in ((64,128,192,256) if args.protocol_engine else (16,32,64,128)):
            profile={'memory_mib':memory,'cpu_quota_percent':100,'swap':False,'cases':[]}
            try:
                agent=launch_agent(memory,str(memory));time.sleep(2);profile['idle']=agent.snapshot()
                profile['basic']=curl('h2',1024,'basic');profile['bearer']=curl('h2',1024,'bearer');profile['invalid_bearer']=curl('h2',1024,'invalid')
                # curl's HTTP/2 proxy write-out can leave http_connect at zero.
                # Verify payload success/failure; Rust protocol tests assert 407.
                assert profile['basic']['ok'] and profile['bearer']['ok'] and not profile['invalid_bearer']['ok'] and profile['invalid_bearer']['bytes']==0, 'authentication probe failed'
                for kind in ('tcp','h2'):
                    for concurrency in (1,16,64):
                        before=agent.snapshot();start=time.perf_counter()
                        with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
                            cases=list(pool.map(lambda _:curl(kind,4*1024*1024),range(concurrency)))
                        elapsed=time.perf_counter()-start;after=agent.snapshot()
                        count=sum(c['bytes'] for c in cases);failures=sum(not c['ok'] for c in cases)
                        cpu=after.get('cpu.stat',{}).get('usage_usec',0)-before.get('cpu.stat',{}).get('usage_usec',0)
                        profile['cases'].append({'protocol':kind,'concurrency':concurrency,'bytes':count,'seconds':elapsed,
                            'mbps':count*8/elapsed/1e6,'failures':failures,'cpu_seconds':cpu/1e6,'snapshot':after})
                        save(evidence/'capacity.json',{**results,'in_progress':profile})
                        if failures: raise RuntimeError('transfer failure under cap')
                if args.protocol_engine:
                    profile['gateway_batch']=gateway_batch(agent)
                    if not profile['gateway_batch']['passed']:raise RuntimeError('gateway transfer failure under cap')
                profile['passed']=True;profile['final']=agent.snapshot()
            except Exception as error:
                profile['passed']=False;profile['error']=str(error)
            finally:
                if agent:agent.stop();agent=None
            results['profiles'].append(profile);save(evidence/'capacity.json',results)
        # A stable instance remains during the bounded soak and external WAN/browser probes.
        soak_memory=192 if args.protocol_engine else 64
        agent=launch_agent(soak_memory,'soak');time.sleep(2)
        ready_info={'controller_port':controller_port,'h2_port':h2_port,'tcp_port':tcp_port,'origin_port':origin_port,
                    'node_id':node_id,'https_origin_port':https_port,'ca_file':str(tls/'root/ca.pem'),'controller_unit':controller.name,'agent_unit':agent.name,
                    'soak_seconds':args.endurance_seconds,'udp_port':udp_port}
        save(evidence/'ready.json',ready_info)
        save(root/'private-access.json',{**ready_info,'admin_password':password,'session':auth,'proxy_bearer':token,'proxy_user':user,'proxy_password':proxy_password})
        for _ in range(1500):
            if args.start_soak_immediately or (root/'start-soak').exists(): break
            time.sleep(.2)
        if not args.start_soak_immediately and not (root/'start-soak').exists(): raise RuntimeError('external probe gate timed out; no soak started')
        steady_before=agent.snapshot(); start=time.monotonic()
        samples=[]; sampling=threading.Event()
        def sample_load():
            while not sampling.wait(.5):
                samples.append({'seconds':round(time.monotonic()-start,3),'agent':agent.snapshot(),'controller':controller.snapshot()})
        sampler=threading.Thread(target=sample_load,daemon=True);sampler.start()
        rounds=[]
        for round_number in range(args.steady_rounds):
            began=time.monotonic()
            with concurrent.futures.ThreadPoolExecutor(max_workers=64) as pool:
                transfers=list(pool.map(lambda _:curl('h2',16*1024*1024,slow=True),range(64)))
            rounds.append({'round':round_number+1,'seconds':time.monotonic()-began,
                           'passed':all(p['ok'] for p in transfers),'transfers':transfers,
                           'agent':agent.snapshot(),'controller':controller.snapshot()})
            save(evidence/'steady-rounds.json',rounds)
        steady=[transfer for round_result in rounds for transfer in round_result['transfers']]
        sampling.set();sampler.join(timeout=5)
        elapsed=time.monotonic()-start
        save(evidence/'steady-load.json',{'method':f'{args.steady_rounds} independent rounds of 64 concurrent slow readers; each 16MiB at 256KiB/s; controller and agent share CPU 0, separate 64/{soak_memory}MiB caps; socket buffer request {args.socket_buffer_bytes} bytes (0 means OS autotuning)',
            'socket_buffer_bytes':args.socket_buffer_bytes,'rounds':args.steady_rounds,
            'passed':all(p['ok'] for p in steady),'seconds':elapsed,'mbps':sum(p['bytes'] for p in steady)*8/elapsed/1e6,'before':steady_before,'after':agent.snapshot(),'controller':controller.snapshot(),'transfers':steady})
        save(evidence/'steady-samples.json',samples)
        samples=[];failures=[];start=time.monotonic()
        while time.monotonic()-start<args.endurance_seconds:
            probe=curl('h2',1024*1024)
            if not probe['ok']:failures.append(probe)
            if controller.snapshot()['active'] != 'active': failures.append({'controller_inactive': True})
            samples.append({'seconds':round(time.monotonic()-start,3),'agent':agent.snapshot(),'controller':controller.snapshot(),'transfer':probe})
            save(evidence/'endurance.json',{'requested_seconds':args.endurance_seconds,'elapsed_seconds':time.monotonic()-start,'complete':False,'failures':failures,'samples':samples})
            time.sleep(2)
        results['endurance']={'seconds':time.monotonic()-start,'transfers':len(samples),'failures':len(failures),
                              'first':samples[0],'last':samples[-1]}
        save(evidence/'endurance.json',{'requested_seconds':args.endurance_seconds,'elapsed_seconds':time.monotonic()-start,'complete':True,'failures':failures,'samples':samples})
        # Lower cap profiles may fail while establishing the sizing boundary.
        # The sustained workload must pass; a timeout must not yield exit 0.
        passed=any(p['passed'] for p in results['profiles']) and all(p['ok'] for p in steady) and not failures
        results['passed']=bool(passed)
        save(evidence/'capacity.json',results)
        print(json.dumps({'complete':True,'passed':bool(passed),'controller_profiles':len(results['controller_profiles']),'agent_profiles':len(results['profiles']),'soak_failures':len(failures)}),flush=True)
        if not passed:
            raise SystemExit(1)
    finally:
        for unit in reversed(units):unit.stop()
        origin.shutdown()
        https_origin.shutdown()
        udp_origin.close()
        save(evidence/'cleanup.json',{'test_units_stopped':[unit.name for unit in units]})


if __name__=='__main__':main()
