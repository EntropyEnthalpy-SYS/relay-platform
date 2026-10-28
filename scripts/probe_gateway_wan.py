#!/usr/bin/env python3
"""Probe owned protocol gateways from a second host using private client JSON.

Input is produced by check_linux_capacity.py --protocol-engine. Uses loopback
SOCKS listeners, verifies TLS, compares payload bytes, and kills its client.
Private input/configuration must not be included in public evidence packages.
"""
import argparse
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
import time
from check_linux_capacity import free_port


def exact(stream, size):
    out=b''
    while len(out)<size:
        part=stream.recv(size-len(out))
        if not part: raise OSError('unexpected EOF')
        out+=part
    return out


def udp(proxy, target):
    with socket.create_connection(('127.0.0.1',proxy),timeout=8) as control:
        control.sendall(b'\x05\x01\x00')
        if exact(control,2)!=b'\x05\x00': raise OSError('SOCKS greeting rejected')
        control.sendall(bytes([5,3,0,1,0,0,0,0,0,0]))
        response=exact(control,10)
        if response[:4]!=bytes([5,0,0,1]): raise OSError('UDP association rejected')
        address=(socket.inet_ntoa(response[4:8]),int.from_bytes(response[8:10],'big'))
        payload=b'relay-owned-wan-udp-' + os.urandom(64)
        destination=bytes([0,0,0,1,127,0,0,1])+struct.pack('!H',target)
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as datagram:
            datagram.settimeout(8); datagram.sendto(destination+payload,address)
            response,_=datagram.recvfrom(65536)
        return {'passed':response==destination+payload,'bytes':len(payload)}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--engine',type=Path,required=True)
    parser.add_argument('--private-config',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args(); os.umask(0o077)
    source=json.loads(args.private_config.read_text())
    ports={out['tag']:free_port() for out in source['outbounds']}
    config={'log':{'level':'error'},'inbounds':[{'type':'socks','tag':name,'listen':'127.0.0.1','listen_port':port} for name,port in ports.items()],
            'outbounds':source['outbounds'],'route':{'rules':[{'inbound':[name],'action':'route','outbound':name} for name in ports]+[{'action':'reject'}]}}
    result={'method':'Second authorized Linux host; sing-box client, verified TLS, exact HTTP body and UDP echo comparisons; not a maximum-throughput benchmark','engine_version':subprocess.check_output([str(args.engine),'version'],text=True).splitlines()[0],'cases':[]}
    with tempfile.TemporaryDirectory(prefix='relay-wan-client-') as temp:
        path=Path(temp)/'config.json'; path.write_text(json.dumps(config));path.chmod(0o600)
        client=subprocess.Popen([str(args.engine),'run','-c',str(path)],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            for port in ports.values():
                for _ in range(100):
                    if client.poll() is not None: raise RuntimeError('protocol client exited')
                    try:
                        with socket.create_connection(('127.0.0.1',port),timeout=.1):break
                    except OSError:time.sleep(.05)
                else:raise RuntimeError('client startup timed out')
            for name,port in ports.items():
                item={'protocol':name}
                for size in (1024,1024*1024):
                    start=time.monotonic()
                    p=subprocess.run(['curl','--silent','--show-error','--fail','--max-time','45','--connect-timeout','10','--noproxy','','--socks5-hostname',f'127.0.0.1:{port}',f'http://127.0.0.1:{source["origin_port"]}/bytes/{size}'],capture_output=True)
                    elapsed=time.monotonic()-start
                    item.setdefault('tcp',[]).append({'size':size,'received':len(p.stdout),'seconds':elapsed,'mbps':len(p.stdout)*8/elapsed/1e6,'passed':p.returncode==0 and p.stdout==b'x'*size,'exit_code':p.returncode,'error':p.stderr.decode(errors='replace')[:200]})
                if name!='any_tls':
                    try:item['udp']=udp(port,source['udp_port'])
                    except Exception as error:item['udp']={'passed':False,'error':str(error)}
                result['cases'].append(item)
                args.output.write_text(json.dumps(result,indent=2)+'\n')
            result['passed']=all(all(p['passed'] for p in c['tcp']) and c.get('udp',{}).get('passed',True) for c in result['cases'])
            args.output.write_text(json.dumps(result,indent=2)+'\n')
            print(json.dumps({'passed':result['passed'],'protocols':len(result['cases'])}))
        finally:
            client.terminate()
            try:client.wait(timeout=5)
            except subprocess.TimeoutExpired:client.kill();client.wait()
    if not result.get('passed'): raise SystemExit(1)

if __name__=='__main__':main()
