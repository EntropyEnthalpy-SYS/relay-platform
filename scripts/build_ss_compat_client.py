#!/usr/bin/env python3
"""Build the optional Relay SS compatibility client from pinned source.

Uses Go's verified module downloads. Output includes matching source archives,
patch and licenses; it never replaces a system client or changes services.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build(directory, target, go):
    root = Path(__file__).resolve().parents[1] / 'third_party'
    upstream = json.loads((root / 'sing-box/manifest.json').read_text())
    patch_manifest = json.loads((root / 'relay-ss-client/manifest.json').read_text())
    source = root / 'sing-box' / upstream['source']['filename']
    dependency = root / 'relay-ss-client' / patch_manifest['dependency_source']['filename']
    patch = root / 'relay-ss-client/half-close.patch'
    for path, expected in [(source, upstream['source']['sha256']),
                           (dependency, patch_manifest['dependency_source']['sha256']),
                           (patch, patch_manifest['patch_sha256'])]:
        if sha(path) != expected:
            raise ValueError(f'source checksum mismatch: {path.name}')
    directory = Path(directory).absolute()
    if directory.exists():
        raise ValueError('output directory must not exist')
    with tempfile.TemporaryDirectory(prefix='relay-ss-build-', dir=directory.parent) as temp:
        temp = Path(temp)
        for archive in [source, dependency]:
            with tarfile.open(archive) as package:
                package.extractall(temp, filter='data')
        client_source = temp / ('sing-box-' + upstream['version'])
        dependency_source = temp / 'sing-shadowsocks2-a69d1086332b'
        with patch.open('rb') as changes:
            subprocess.run(['patch', '-p1', '--batch'], cwd=dependency_source, stdin=changes, check=True)
        subprocess.run([go, 'mod', 'edit', '-replace',
                        'github.com/sagernet/sing-shadowsocks2=' + str(dependency_source)],
                       cwd=client_source, check=True)
        staged = temp / 'output'; staged.mkdir()
        env = dict(os.environ, CGO_ENABLED='0', GOOS=target.split('-')[0], GOARCH=target.split('-')[1])
        subprocess.run([go, 'build', '-trimpath', '-ldflags',
                        '-s -w -X github.com/sagernet/sing-box/constant.Version=relay-ss-client-0.119.0',
                        '-o', str(staged / 'relay-ss-client'), './cmd/sing-box'],
                       cwd=client_source, env=env, check=True)
        for path in [source, dependency, patch, root / 'sing-box/LICENSE',
                     root / 'sing-box/COPYING.GPL-3.0.txt', root / 'relay-ss-client/LICENSE.sing-shadowsocks2']:
            shutil.copy2(path, staged / path.name)
        manifest = dict(patch_manifest, target=target, binary_sha256=sha(staged / 'relay-ss-client'),
                        upstream_source_sha256=upstream['source']['sha256'])
        (staged / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
        os.rename(staged, directory)
    return manifest


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--target', choices=['darwin-arm64', 'linux-amd64', 'linux-arm64'], required=True)
    parser.add_argument('--go', default='go')
    args = parser.parse_args()
    print(json.dumps(build(args.directory, args.target, args.go), indent=2))
