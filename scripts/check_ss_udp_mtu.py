#!/usr/bin/env python3
"""Linux root-only SS UDP regression in disposable network namespaces at MTU 1280.

Does not change host routes, firewall rules or existing interfaces. Compares the
bundled default with explicit fragmentation, UoT and a no-fragment negative control.
"""
import argparse
import base64
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time
import uuid

from check_shadowsocks_interop import Associate, wait_port


def stop(process):
    try: os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError: pass
    try: process.wait(5)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL); process.wait()


def worker(directory, client, case):
    root = Path(directory); profile = json.loads((root/'profile.json').read_text())
    negative = case in ['explicit-false', 'previous-default']
    if case == 'explicit-false': profile['outbounds'][0]['udp_fragment'] = False
    if case == 'explicit-true': profile['outbounds'][0]['udp_fragment'] = True
    if case == 'uot': profile['outbounds'][0]['udp_over_tcp'] = {'enabled':True, 'version':2}
    path=root/(case+'.json');path.write_text(json.dumps(profile));path.chmod(0o600)
    rows=[]
    with (root/(case+'.log')).open('wb') as log:
        process=subprocess.Popen([client,'run','-c',str(path)],stdout=log,stderr=log)
        try:
            wait_port(28340,process)
            association=Associate(28340);association.udp.settimeout(.4 if negative else 3)
            try:
                if negative:
                    reply=association.exchange('127.0.0.1',28230,b'control')
                    assert reply is not None and reply[1]==b'control', 'negative-control client cannot reach the echo'
                sizes=[1400,4096,8192] if negative else [0,1,64,512,1000,1180,1200,1400,4096,8192]*3
                for index,size in enumerate(sizes):
                    body=(bytes([index%251])+bytes(range(251)))*max(1,size);body=body[:size]
                    started=time.monotonic();reply=association.exchange('127.0.0.1',28230,body)
                    equal=reply is not None and reply[0]==('127.0.0.1',28230) and reply[1]==body
                    rows.append({'sample':index+1,'bytes':size,'delivered':equal,'elapsed_ms':round((time.monotonic()-started)*1000,2)})
            finally:association.close()
        finally:
            process.terminate()
            try:process.wait(5)
            except subprocess.TimeoutExpired:process.kill();process.wait()
    return {'case':case,'negative_control':negative,'passed':all(not r['delivered'] if negative else r['delivered'] for r in rows),'samples':rows}


def run(args):
    if sys.platform!='linux' or os.geteuid()!=0: raise RuntimeError('requires Linux root and iproute2')
    suffix=uuid.uuid4().hex[:7];names=['r121c'+suffix,'r121s'+suffix];links=['r121a'+suffix,'r121b'+suffix]
    created=[];processes=[];logs=[];results=[]
    def ip(*values):return subprocess.run(['ip',*values],check=True,capture_output=True,text=True,timeout=15)
    def launch(namespace, command, log):
        stream=log.open('wb');logs.append(stream)
        p=subprocess.Popen(['ip','netns','exec',namespace,*map(str,command)],stdout=stream,stderr=stream,start_new_session=True)
        processes.append(p);return p
    with tempfile.TemporaryDirectory(prefix='relay-mtu-') as directory:
        root=Path(directory);os.chmod(root,0o700)
        try:
            for name in names:ip('netns','add',name);created.append(name)
            ip('link','add',links[0],'type','veth','peer','name',links[1])
            for index,name in enumerate(names):
                ip('link','set',links[index],'netns',name)
                ip('-n',name,'link','set','lo','up')
                ip('-n',name,'addr','add',f'198.18.0.{index+1}/24','dev',links[index])
                ip('-n',name,'link','set',links[index],'mtu','1280','up')
            secret=base64.b64encode(os.urandom(32)).decode()
            base={'tenant_id':'default','owner_id':'admin','protocol':'both','enabled':True,'meter_epoch':'mtu','connect_timeout_ms':3000,'idle_timeout_secs':30}
            rules=[{**base,'id':'entry','name':'MTU entry','listen':'198.18.0.2:28228','targets':[{'address':'127.0.0.1:28229','weight':1}]},
                   {**base,'id':'exit','name':'MTU SS exit','listen':'127.0.0.1:28229','targets':[],
                    'inbound_shadowsocks':{'method':'2022-blake3-aes-256-gcm','password':secret,'allow_private_destinations':True,'udp_over_tcp':True}}]
            config=root/'relay.json';config.write_text(json.dumps({'api_version':1,'node_id':'mtu-fixture','revision':1,'rules':rules}));config.chmod(0o600)
            profile={'log':{'level':'warn'},'inbounds':[{'type':'socks','listen':'127.0.0.1','listen_port':28340}],
                     'outbounds':[{'type':'shadowsocks','tag':'test','server':'198.18.0.2','server_port':28228,'method':'2022-blake3-aes-256-gcm','password':secret}],
                     'route':{'final':'test'}}
            (root/'profile.json').write_text(json.dumps(profile));(root/'profile.json').chmod(0o600)
            echo="import socket\ns=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('127.0.0.1',28230))\nwhile True:\n b,p=s.recvfrom(65535);s.sendto(b,p)"
            launch(names[1],[sys.executable,'-c',echo],root/'echo.log')
            relay=launch(names[1],[args.binary,'standalone','--config',config,'--database',root/'state.sqlite'],root/'relay.log')
            ready="import socket,time\nend=time.monotonic()+15\nwhile True:\n try:\n  s=socket.create_connection(('198.18.0.2',28228),timeout=.2);s.close();break\n except OSError:\n  if time.monotonic()>end:raise\n  time.sleep(.05)"
            subprocess.run(['ip','netns','exec',names[1],sys.executable,'-c',ready],check=True,capture_output=True,timeout=20)
            cases=[('explicit-false',args.client),('default',args.client),('explicit-true',args.client),('uot',args.client)]
            if args.previous_client:cases.insert(0,('previous-default',args.previous_client))
            for case,client in cases:
                p=subprocess.Popen(['ip','netns','exec',names[0],sys.executable,str(Path(__file__).resolve()),'--worker',case,'--directory',str(root),'--client',str(client)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
                try:
                    out,err=p.communicate(timeout=120)
                    if p.returncode:raise RuntimeError('MTU worker failed: '+err.decode())
                    results.append(json.loads(out))
                finally:stop(p)
            assert relay.poll() is None, 'Relay exited during MTU probes'
        finally:
            for process in reversed(processes):stop(process)
            for log in logs:log.close()
            for name in reversed(created):subprocess.run(['ip','netns','del',name],capture_output=True,timeout=15)
            # Handles partial setup before a veth end was moved into a namespace.
            for link in links:subprocess.run(['ip','link','del',link],capture_output=True,timeout=15)
    present=subprocess.check_output(['ip','netns','list'],text=True)
    cleaned=all(name not in present for name in created)
    return {'completed':True,'mtu':1280,'topology':'two disposable namespaces; plain entry -> SS exit -> UDP echo','cases':results,'cleanup_passed':cleaned,'passed':cleaned and all(r['passed'] for r in results)}


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--binary',type=Path);p.add_argument('--client',type=Path,required=True);p.add_argument('--previous-client',type=Path);p.add_argument('--output',type=Path);p.add_argument('--worker');p.add_argument('--directory');a=p.parse_args()
    if a.worker:print(json.dumps(worker(a.directory,str(a.client),a.worker)))
    else:
        if not a.binary or not a.output:p.error('--binary and --output are required')
        a.binary=a.binary.resolve();a.client=a.client.resolve()
        result=run(a);a.output.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'passed':result['passed'],'cases':[(c['case'],c['passed']) for c in result['cases']]}));raise SystemExit(0 if result['passed'] else 1)
