#!/usr/bin/env python3
"""Exercise real mux CLI startup, delayed scheduling, errors and cleanup."""
import argparse
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time


def run(binary, cycles):
    checks = []
    with tempfile.TemporaryDirectory(prefix='relay-startup-') as directory:
        root = Path(directory)
        token = root / 'token'; token.write_text('private-test-only-token'); token.chmod(0o600)
        for cycle in range(cycles):
            ready = root / f'ready-{cycle}.json'; log = root / f'log-{cycle}.txt'
            args = [str(binary), 'reverse-mux-server', '--control-listen', '127.0.0.1:0',
                    '--public-listen', '127.0.0.1:0', '--token-file', str(token),
                    '--ready-file', str(ready)]
            delay = 3 if cycle == 0 else 0
            if delay:
                args = [sys.executable, '-c', 'import os,sys,time;time.sleep(3);os.execv(sys.argv[1],sys.argv[1:])', *args]
            with log.open('wb') as stream:
                child = subprocess.Popen(args, stdout=stream, stderr=stream)
                try:
                    started = time.monotonic(); deadline = started + 20
                    while True:
                        if child.poll() is not None:
                            raise RuntimeError('startup exited: ' + log.read_text())
                        try: value = json.loads(ready.read_text())
                        except (FileNotFoundError, json.JSONDecodeError): value = None
                        if value is not None:
                            if value['pid'] != child.pid or value['state'] != 'listeners_bound':
                                raise RuntimeError('stale or invalid readiness')
                            break
                        if time.monotonic() >= deadline: raise TimeoutError('readiness deadline: ' + log.read_text())
                        time.sleep(.02)
                    endpoints = [tuple(address.rsplit(':', 1)) for address in [value['control_listen'], value['public_listen']]]
                    assert endpoints[0] != endpoints[1]
                    for host, port in endpoints:
                        with socket.create_connection((host, int(port)), timeout=5): pass
                    checks.append({'cycle':cycle+1, 'passed':True, 'delayed_start_seconds':delay,
                                   'startup_ms':round((time.monotonic()-started)*1000,2),
                                   'control':value['control_listen'], 'public':value['public_listen']})
                finally:
                    child.terminate()
                    try: child.wait(5)
                    except subprocess.TimeoutExpired: child.kill(); child.wait()
            for host, port in endpoints:
                with socket.socket() as probe:
                    probe.settimeout(1)
                    assert probe.connect_ex((host, int(port))) != 0, 'listener survived process exit'
    return {'completed':True, 'passed':all(c['passed'] for c in checks), 'cycles':checks}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--cycles', type=int, default=30)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if not 1 <= args.cycles <= 1000: parser.error('cycles must be 1..1000')
    result = run(args.binary.resolve(), args.cycles)
    args.output.write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps({'passed':result['passed'], 'cycles':len(result['cycles'])}))
