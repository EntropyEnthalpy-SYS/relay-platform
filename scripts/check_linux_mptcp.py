#!/usr/bin/env python3
"""Opt-in root-only MPTCP test in two disposable Linux network namespaces.

No host routes, endpoints, firewall rules or sysctls are changed. Checks a real
relay connection, extra kernel subflows, primary-path loss, data and metering.
"""
import argparse
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time


def run(*args, **kwargs):
    return subprocess.run(list(map(str, args)), check=True, capture_output=True, text=True, timeout=30, **kwargs).stdout


CLIENT = r'''
import hashlib,json,socket,subprocess,time
from pathlib import Path
root=Path(__import__('sys').argv[1]); interface=__import__('sys').argv[2]
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM,262);s.settimeout(12);s.connect(('10.203.1.2',33009))
def info():
 b=s.getsockopt(284,1,128)
 return {'negotiated':bool(int.from_bytes(b[8:12],__import__('sys').byteorder)&2),'additional_subflows':b[0],'total_subflows':b[80] if len(b)>80 else None}
for _ in range(100):
 status=info()
 if (status['total_subflows'] or 0)>=2:break
 time.sleep(.1)
assert status['negotiated'] and status['total_subflows']>=2,status
payload=bytes(range(256))*4096
def exchange():
 import threading
 error=[]
 def send():
  try:s.sendall(payload)
  except Exception as e:error.append(str(e))
 sender=threading.Thread(target=send);sender.start();data=bytearray()
 while len(data)<len(payload):
  block=s.recv(min(65536,len(payload)-len(data)))
  assert block,'early EOF';data.extend(block)
 sender.join(15);assert not sender.is_alive() and not error,error
 assert data==payload
 return hashlib.sha256(data).hexdigest()
before=exchange()
subprocess.run(['ip','link','set',interface,'down'],check=True)
after=exchange()
result={'passed':True,'before_path_loss':status,'after_path_loss':info(),'payload_bytes_each_direction':len(payload)*2,'sha256_before':before,'sha256_after':after}
(root/'client.json').write_text(json.dumps(result,indent=2)+'\n')
s.shutdown(socket.SHUT_WR)
while s.recv(4096):pass
s.close()
'''
ORIGIN = r'''
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM,262);s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('127.0.0.1',33010));s.listen(8)
while True:
 c,_=s.accept()
 while True:
  data=c.recv(65536)
  if not data:break
  c.sendall(data)
 c.shutdown(socket.SHUT_WR);c.close()
'''


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary',type=Path,required=True)
    p.add_argument('--workdir',type=Path,required=True)
    args=p.parse_args()
    if sys.platform!='linux' or os.geteuid()!=0:p.error('Linux root is required for isolated network namespaces')
    os.umask(0o077)
    root=args.workdir.resolve();root.mkdir(parents=True,exist_ok=False)
    binary=args.binary.resolve()
    suffix=secrets.token_hex(3);left='relaymc-'+suffix;right='relayms-'+suffix
    namespaces=[];processes=[];handles=[]
    def ns(namespace,*command):return run('ip','netns','exec',namespace,*command)
    def start(namespace,filename,*command):
        handle=(root/filename).open('w');handles.append(handle)
        child=subprocess.Popen(['ip','netns','exec',namespace,*map(str,command)],stdout=handle,stderr=subprocess.STDOUT)
        processes.append(child);return child
    try:
        for name in [left,right]:
            run('ip','netns','add',name);namespaces.append(name)
            ns(name,'ip','link','set','lo','up')
            ns(name,'sysctl','-qw','net.mptcp.enabled=1')
            ns(name,'ip','mptcp','limits','set','subflows','4','add_addr_accepted','4')
        for index in [1,2]:
            a=f'mc{index}{suffix}';b=f'ms{index}{suffix}'
            run('ip','link','add',a,'netns',left,'type','veth','peer','name',b,'netns',right)
            for name,device,ip in [(left,a,f'10.203.{index}.1/24'),(right,b,f'10.203.{index}.2/24')]:
                ns(name,'ip','address','add',ip,'dev',device);ns(name,'ip','link','set',device,'up')
        ns(right,'ip','mptcp','endpoint','add','10.203.2.2','dev',f'ms2{suffix}','id','2','signal')
        ns(left,'ip','mptcp','endpoint','add','10.203.2.1','dev',f'mc2{suffix}','id','2','subflow')
        config={'api_version':1,'node_id':'mptcp-lab','revision':1,'rules':[{
            'id':'mptcp-test','tenant_id':'default','owner_id':'admin','name':'Isolated MPTCP acceptance',
            'listen':'0.0.0.0:33009','protocol':'tcp','targets':[{'address':'127.0.0.1:33010','weight':1}],
            'enabled':True,'balance':'weighted_round_robin','connect_timeout_ms':10000,'idle_timeout_secs':30,
            'max_connections':16,'udp_max_sessions':16,
            'quota_bytes':None,'rate_bytes_per_sec':None,'expires_at_ms':None,'meter_epoch':'mptcp-lab',
            'allow_sources':['10.203.0.0/16'],'deny_sources':[],
            'mptcp':{'inbound':'require','outbound':'require'}}]}
        (root/'config.json').write_text(json.dumps(config))
        run(binary,'validate','--config',root/'config.json')
        start(right,'origin.log',sys.executable,'-u','-c',ORIGIN)
        relay=start(right,'relay.log',binary,'standalone','--config',root/'config.json','--database',root/'agent.sqlite')
        ready=False
        for _ in range(100):
            if relay.poll() is not None:raise RuntimeError('relay exited; see relay.log')
            if ':33009' in ns(right,'ss','-lnt'):ready=True;break
            time.sleep(.1)
        assert ready,'relay listener did not become ready'
        client=start(left,'client.log',sys.executable,'-u','-c',CLIENT,root,f'mc1{suffix}')
        assert client.wait(timeout=60)==0,'MPTCP client failed; see client.log'
        relay.terminate();relay.wait(timeout=10)
        usage=json.loads(run(binary,'usage','--database',root/'agent.sqlite'))
        result=json.loads((root/'client.json').read_text())
        expected=result['payload_bytes_each_direction']
        assert len(usage)==1 and usage[0]['upload_bytes']==expected and usage[0]['download_bytes']==expected,usage
        result.update(usage=usage,build=json.loads(run(binary,'build-info')),method='Two disposable network namespaces and two virtual Ethernet paths; not a WAN throughput benchmark')
        (root/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
    finally:
        for child in reversed(processes):
            if child.poll() is None:
                child.terminate()
                try:child.wait(timeout=5)
                except subprocess.TimeoutExpired:child.kill();child.wait()
        for handle in handles:handle.close()
        for name in reversed(namespaces):run('ip','netns','delete',name)
        (root/'cleanup.json').write_text(json.dumps({'removed_namespaces':namespaces,'children_stopped':all(p.poll() is not None for p in processes)},indent=2)+'\n')


if __name__=='__main__':main()
