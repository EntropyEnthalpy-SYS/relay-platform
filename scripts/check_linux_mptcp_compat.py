#!/usr/bin/env python3
"""Run managed MPTCP acceptance on the actual required Linux kernel.

A container's distribution is not proof of its kernel version. This probe
records uname and the raw socket-option behavior before running all managed
MPTCP tests, including explicit source binding and strict peer rejection.
Uses loopback and ephemeral ports only; does not change services or sysctls.
"""
import argparse
import errno
import hashlib
import json
import platform
import re
from pathlib import Path
import socket
import subprocess
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--test-binary', type=Path, required=True)
    parser.add_argument('--expected-kernel-prefix', required=True)
    parser.add_argument('--expect-unsupported-bind-option', action='store_true')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    kernel = platform.release()
    result = {'kernel': kernel, 'expected_kernel_prefix': args.expected_kernel_prefix,
              'started_at': time.time(), 'raw_sockets': [], 'passed': False,
              'test_binary_sha256': hashlib.sha256(args.test_binary.read_bytes()).hexdigest()}
    try:
        if platform.system() != 'Linux' or not kernel.startswith(args.expected_kernel_prefix):
            raise RuntimeError('The running kernel does not match the requested regression kernel')
        for family, address in [(socket.AF_INET, ('127.0.0.1', 0)),
                                (socket.AF_INET6, ('::1', 0))]:
            for protocol in [socket.IPPROTO_TCP, 262]:  # IPPROTO_MPTCP
                with socket.socket(family, socket.SOCK_STREAM, protocol) as stream:
                    row = {'family': 'IPv4' if family == socket.AF_INET else 'IPv6',
                           'protocol': 'TCP' if protocol == socket.IPPROTO_TCP else 'MPTCP',
                           'bind_option_errno': None}
                    try:
                        stream.setsockopt(socket.IPPROTO_IP, 24, 1)  # IP_BIND_ADDRESS_NO_PORT
                    except OSError as error:
                        row['bind_option_errno'] = error.errno
                        if protocol == socket.IPPROTO_TCP or error.errno not in (errno.EOPNOTSUPP, errno.ENOPROTOOPT):
                            raise
                    stream.bind(address)
                    row['port_reserved_at_bind'] = stream.getsockname()[1] != 0
                    result['raw_sockets'].append(row)
        if args.expect_unsupported_bind_option and not all(
                row['bind_option_errno'] in (errno.EOPNOTSUPP, errno.ENOPROTOOPT)
                for row in result['raw_sockets'] if row['protocol'] == 'MPTCP'):
            raise RuntimeError('This kernel did not reproduce the legacy MPTCP option rejection')
        executable = str(args.test_binary.resolve())
        listing = subprocess.run([executable, '--list'], capture_output=True, text=True, timeout=30)
        required = {
            'preferred_mode_allows_plain_tcp_and_releases_observers_on_disable',
            'linux::required_mptcp_forwards_and_reports_live_negotiation',
            'linux::required_modes_reject_plain_tcp_peers',
            'linux::outbound_modes_preserve_source_binding_on_both_address_families',
        }
        available = {line.removesuffix(': test') for line in listing.stdout.splitlines() if line.endswith(': test')}
        if listing.returncode or not required.issubset(available):
            raise RuntimeError('The executable is missing required managed MPTCP regression tests')
        test = subprocess.run([executable, '--test-threads=1', '--include-ignored'],
                              capture_output=True, text=True, timeout=180)
        result['tests'] = {'exit_code': test.returncode, 'stdout': test.stdout, 'stderr': test.stderr}
        summary = re.search(r'test result: ok\. (\d+) passed; 0 failed; 0 ignored;', test.stdout)
        result['passed'] = test.returncode == 0 and summary is not None and int(summary[1]) == len(available)
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        result['error'] = str(error)
    finally:
        result['ended_at'] = time.time()
        args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'kernel': kernel, 'passed': result['passed'], 'output': str(args.output)}))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
