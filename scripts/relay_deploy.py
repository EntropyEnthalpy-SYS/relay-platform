#!/usr/bin/env python3
"""Build/verify signed offline bundles and manage stopped Linux installations.

Use --root ABSOLUTE_PRIVATE_DIRECTORY to stage and inspect files without changing
host services. Staged roots cannot start/stop/enable/disable system services.
"""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import tarfile

from deployment import bundle
from deployment.bundle import DeployError, regular, require
from deployment.install import Layout, control, deploy, preflight, recover, remove, rollback


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest='command', required=True)
    key = commands.add_parser('keygen', help='create a new private RSA-3072 signing key directory')
    key.add_argument('--directory', type=Path, required=True)
    pack = commands.add_parser('pack', help='sign a native binary and its component/license list')
    pack.add_argument('--binary', type=Path, required=True)
    pack.add_argument('--third-party', type=Path, default=Path(__file__).resolve().parents[1] / 'docs/THIRD_PARTY.md')
    pack.add_argument('--signing-key', type=Path, required=True)
    pack.add_argument('--source-revision', required=True)
    pack.add_argument('--output', type=Path, required=True)
    verify = commands.add_parser('verify', help='verify against an independently obtained trusted public key')
    verify.add_argument('--bundle', type=Path, required=True)
    verify.add_argument('--trusted-key', type=Path, required=True)
    for name in ('preflight', 'install', 'status', 'recover', 'rollback', 'remove', 'start', 'stop', 'enable', 'disable'):
        command = commands.add_parser(name)
        command.add_argument('--root', type=Path, default=Path('/'))
        command.add_argument('--role', choices=('controller', 'agent'), required=True)
        command.add_argument('--manager', choices=('systemd', 'openrc'))
        if name in ('preflight', 'install'):
            command.add_argument('--bundle', type=Path, required=name == 'install')
            command.add_argument('--trusted-key', type=Path)
            command.add_argument('--config', type=Path, required=name == 'install', help='role settings JSON; never shell source')
        if name == 'install':
            command.add_argument('--enrollment-token-file', type=Path)
            command.add_argument('--ca-certificate', type=Path)
    return result


def execute(args):
    if args.command == 'keygen':
        return bundle.keygen(args.directory)
    if args.command == 'pack':
        return bundle.pack(args.binary, args.third_party, args.signing_key, args.output, args.source_revision)
    if args.command == 'verify':
        verified = bundle.verify(args.bundle, args.trusted_key)
        return {'verified': True, 'manifest_sha256': verified['id'], 'manifest': verified['manifest'], 'payload_executed': False}
    layout = Layout(args.root, args.role, args.manager)
    if args.command == 'status':
        return layout.status()
    if args.command in ('start', 'stop', 'enable', 'disable'):
        return control(layout, args.command)
    if args.command in ('recover', 'rollback', 'remove'):
        return {'recover': recover, 'rollback': rollback, 'remove': remove}[args.command](layout)
    verified = None
    if args.bundle:
        require(args.trusted_key, '--trusted-key is required with --bundle')
        verified = bundle.verify(args.bundle, args.trusted_key)
    if args.command == 'preflight':
        return preflight(layout, verified, json.loads(regular(args.config, 65536)) if args.config else None)
    supplied = json.loads(regular(args.config, 65536))
    return deploy(layout, verified, supplied, args.enrollment_token_file, args.ca_certificate)


def main():
    args = parser().parse_args()
    try:
        require(sys.version_info >= (3, 9), 'deployment tooling requires Python 3.9 or newer')
        result = execute(args)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 2 if result.get('ready') is False else 0
    except (DeployError, OSError, ValueError, KeyError, TypeError, EOFError, subprocess.TimeoutExpired, tarfile.TarError) as error:
        print(json.dumps({'error': str(error)}, ensure_ascii=False), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
