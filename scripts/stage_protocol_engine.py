#!/usr/bin/env python3
"""Stage the pinned optional engine, its corresponding source, and licenses.

Does not change services or install into a system directory. The destination
must not exist. Hashes are pinned in the source repository; no latest lookup.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tarfile
import tempfile


def sha(path):
    with path.open('rb') as handle:
        return hashlib.file_digest(handle, 'sha256').hexdigest()


def stage(destination, archive=None, target=None):
    root = Path(__file__).resolve().parents[1] / 'third_party/sing-box'
    manifest = json.loads((root / 'manifest.json').read_text())
    if target is None:
        system = platform.system().lower()
        machine = {'x86_64':'amd64', 'aarch64':'arm64', 'arm64':'arm64'}.get(platform.machine())
        target = f'{system}-{machine}'
    filename = f'sing-box-{manifest["version"]}-{target}.tar.gz'
    asset = next((a for a in manifest['assets'] if a['filename'] == filename), None)
    if asset is None:
        raise ValueError('unsupported target; build from the bundled upstream source')
    source = root / manifest['source']['filename']
    if sha(source) != manifest['source']['sha256']:
        raise ValueError('bundled source checksum mismatch')
    destination = Path(destination).absolute()
    if destination.exists() or destination.is_symlink():
        raise ValueError('destination must not exist')
    with tempfile.TemporaryDirectory(prefix='relay-engine-stage-', dir=destination.parent) as temporary:
        temp = Path(temporary)
        if archive is None:
            archive = temp / filename
            subprocess.run(['curl','--fail','--silent','--show-error','--location','--proto','=https','--tlsv1.2','--max-time','180','--output',str(archive),asset['url']],check=True)
        else:
            archive = Path(archive)
        if sha(archive) != asset['sha256']:
            raise ValueError('engine archive checksum mismatch')
        staged = temp / 'package'; staged.mkdir(mode=0o755)
        expected = filename.removesuffix('.tar.gz') + '/sing-box'
        with tarfile.open(archive, 'r:gz') as package:
            candidates = [m for m in package.getmembers() if m.name == expected]
            if len(candidates) != 1 or not candidates[0].isfile() or not 0 < candidates[0].size <= 256 * 1024 * 1024:
                raise ValueError('engine archive has no unique bounded regular binary')
            with package.extractfile(candidates[0]) as incoming, (staged/'sing-box').open('xb') as outgoing:
                shutil.copyfileobj(incoming, outgoing)
        (staged/'sing-box').chmod(0o755)
        for name in ['LICENSE','COPYING.GPL-3.0.txt','manifest.json',source.name]:
            shutil.copyfile(root/name,staged/name)
        os.rename(staged, destination)
    return {'version':manifest['version'], 'target':target, 'directory':str(destination), 'binary_sha256':sha(destination/'sing-box'), 'source_sha256':manifest['source']['sha256']}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory',type=Path,required=True)
    parser.add_argument('--archive',type=Path,help='optional previously downloaded archive; checksum is still mandatory')
    parser.add_argument('--target',choices=['linux-amd64','linux-arm64','darwin-arm64'])
    args=parser.parse_args()
    print(json.dumps(stage(args.directory,args.archive,args.target),indent=2))

if __name__ == '__main__':
    main()
