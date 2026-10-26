"""Bounded, signed offline bundles; verification never executes their payload."""
import hashlib
import gzip
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile

MAX_BINARY = 256 * 1024 * 1024
LIMITS = {'manifest.json': 65536, 'manifest.sig': 2048, 'relay': MAX_BINARY, 'THIRD_PARTY.md': 2 * 1024 * 1024}


class DeployError(Exception):
    pass


def require(condition, message):
    if not condition:
        raise DeployError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True) + '\n').encode()


def regular(path, limit, private=False):
    path = Path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_size <= limit, f'not a bounded regular file: {path}')
        if private:
            require(info.st_mode & 0o077 == 0, 'private signing material must have mode 0600 or stricter')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            data = stream.read(limit + 1)
        require(len(data) <= limit, f'file grew beyond the limit: {path}')
        return data
    finally:
        os.close(fd)


def openssl(*args, data=None):
    path = shutil.which('openssl', path='/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin')
    require(path is not None, 'OpenSSL or compatible LibreSSL CLI is required')
    result = subprocess.run([path, *map(str, args)], input=data, capture_output=True, timeout=60)
    require(result.returncode == 0, f'openssl {args[0]} failed; key or signature verification rejected')
    return result.stdout


def public_fingerprint(public):
    modulus = openssl('rsa', '-pubin', '-in', public, '-modulus', '-noout').decode().strip()
    require(re.fullmatch(r'Modulus=[A-Fa-f0-9]+', modulus), 'trusted key must be RSA')
    bits = int(modulus.split('=', 1)[1], 16).bit_length()
    require(3072 <= bits <= 8192, 'RSA key must have 3072..8192 bits')
    return sha(openssl('pkey', '-pubin', '-in', public, '-outform', 'DER'))


def create_new(path, data, mode):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    os.fchmod(fd, mode)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def keygen(directory):
    directory = Path(directory)
    directory.mkdir(mode=0o700, parents=False, exist_ok=False)
    private, public = directory / 'signing-private.pem', directory / 'signing-public.pem'
    # The directory is private before OpenSSL creates its output. No key is printed.
    openssl('genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:3072', '-out', private)
    private.chmod(0o600)
    openssl('pkey', '-in', private, '-pubout', '-out', public)
    public.chmod(0o644)
    return {'private_key': str(private), 'public_key': str(public), 'public_key_sha256': public_fingerprint(public)}


def build_info(binary):
    result = subprocess.run([str(Path(binary).resolve()), 'build-info'], capture_output=True, timeout=10)
    require(result.returncode == 0 and len(result.stdout) <= 65536, 'binary must support build-info')
    info = json.loads(result.stdout)
    validate_info(info)
    return info


def validate_info(info):
    require(isinstance(info, dict) and set(info) == {'product', 'version', 'os', 'arch', 'deployment_format', 'state_contract', 'controller_schema'}, 'invalid build-info fields')
    require(info['product'] == 'relay-platform' and info['deployment_format'] == 1, 'unsupported deployment format')
    require(re.fullmatch(r'\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?', info['version']), 'invalid release version')
    require(info['os'] in ('linux', 'macos') and info['arch'] in ('x86_64', 'aarch64'), 'unsupported build target')
    require(info['controller_schema'] == 5, 'unsupported controller schema')
    require(isinstance(info['state_contract'], dict) and set(info['state_contract']) == {'controller', 'agent'}, 'invalid state contract')
    require(all(type(n) is int and 0 < n <= 65535 for n in info['state_contract'].values()), 'invalid compatibility epoch')


def target_header(data, info):
    """Check the executable header independently of the signed target labels."""
    require(len(data) >= 64, 'truncated executable')
    if info['os'] == 'linux':
        require(data[:6] == b'\x7fELF\x02\x01', 'Linux bundle requires a 64-bit little-endian ELF')
        machine = int.from_bytes(data[18:20], 'little')
        require(machine == {'x86_64': 62, 'aarch64': 183}[info['arch']], 'ELF architecture does not match manifest')
        require(int.from_bytes(data[16:18], 'little') in (2, 3), 'ELF is not an executable or PIE')
    else:
        require(data[:4] == b'\xcf\xfa\xed\xfe', 'macOS development bundle requires thin 64-bit Mach-O')
        cpu = int.from_bytes(data[4:8], 'little')
        require(cpu == {'x86_64': 0x1000007, 'aarch64': 0x100000c}[info['arch']], 'Mach-O architecture does not match manifest')


def pack(binary, third_party, private, output, source_revision):
    require(re.fullmatch(r'[0-9a-f]{40}', source_revision), 'source revision must be a full Git commit ID')
    payload = regular(binary, MAX_BINARY)
    info = build_info(binary)
    target_header(payload, info)
    license_data = regular(third_party, LIMITS['THIRD_PARTY.md'])
    key_data = regular(private, 32768, private=True)
    with tempfile.TemporaryDirectory(prefix='relay-sign-') as tmp:
        tmp = Path(tmp)
        key, pub, manifest_file = tmp / 'key.pem', tmp / 'pub.pem', tmp / 'manifest.json'
        create_new(key, key_data, 0o600)
        openssl('pkey', '-in', key, '-pubout', '-out', pub)
        fingerprint = public_fingerprint(pub)
        manifest = {'format': 1, 'build': info, 'source_revision': source_revision, 'signing_key_sha256': fingerprint,
            'files': {name: {'size': len(value), 'sha256': sha(value)} for name, value in [('relay', payload), ('THIRD_PARTY.md', license_data)]}}
        raw = encoded(manifest)
        create_new(manifest_file, raw, 0o600)
        signature = openssl('dgst', '-sha256', '-sign', key, manifest_file)
    # Exclusive output creation prevents accidental replacement of a shipped bundle.
    with open(output, 'xb') as stream:
        with tarfile.open(fileobj=stream, mode='w:gz', format=tarfile.USTAR_FORMAT) as archive:
            for name, value in [('manifest.json', raw), ('manifest.sig', signature), ('relay', payload), ('THIRD_PARTY.md', license_data)]:
                entry = tarfile.TarInfo(name)
                entry.size, entry.mode, entry.mtime = len(value), 0o755 if name == 'relay' else 0o644, 0
                archive.addfile(entry, io.BytesIO(value))
        stream.flush()
        os.fsync(stream.fileno())
    return {'bundle': str(output), 'manifest_sha256': sha(raw), 'bundle_sha256': sha(regular(output, MAX_BINARY + 4 * 1024 * 1024)), 'build': info, 'signing_key_sha256': fingerprint}


def verify(bundle, trusted_public):
    # Copy the explicitly trusted key once; an archive-supplied key is never trusted.
    public_bytes = regular(trusted_public, 32768)
    values = {}
    # Parse fixed USTAR records ourselves so a PAX/long-name header cannot make
    # tarfile allocate unbounded metadata before our member checks run.
    fd = os.open(bundle, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as compressed, gzip.GzipFile(fileobj=compressed) as archive:
        metadata = os.fstat(compressed.fileno())
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_size <= MAX_BINARY + 4 * 1024 * 1024, 'bundle must be a bounded regular file')
        while True:
            header = archive.read(512)
            require(len(header) == 512, 'truncated tar header')
            if header == b'\0' * 512:
                tail = archive.read(10241)
                require(512 <= len(tail) <= 10240 and not tail.strip(b'\0'), 'invalid or excessive tar trailer')
                break
            require(header[257:265] == b'ustar\0' + b'00', 'only USTAR headers are allowed')
            member = tarfile.TarInfo.frombuf(header, 'utf-8', 'strict')
            require(member.name in LIMITS and member.name not in values, 'unexpected or duplicate archive member')
            require(member.type in (tarfile.REGTYPE, tarfile.AREGTYPE) and not member.pax_headers, 'only ordinary fixed-name files are allowed')
            require(0 < member.size <= LIMITS[member.name], 'archive member exceeds its limit')
            values[member.name] = archive.read(member.size)
            require(len(values[member.name]) == member.size, 'archive member size changed')
            padding = archive.read((-member.size) % 512)
            require(len(padding) == (-member.size) % 512 and not padding.strip(b'\0'), 'invalid tar padding')
    require(set(values) == set(LIMITS), 'incomplete bundle')
    return verify_values(values, public_bytes)


def verify_values(values, public_bytes):
    require(set(values) == set(LIMITS), 'incomplete bundle files')
    require(all(0 < len(value) <= LIMITS[name] for name, value in values.items()), 'bundle file exceeds limit')
    raw = values['manifest.json']
    with tempfile.TemporaryDirectory(prefix='relay-verify-') as tmp:
        tmp = Path(tmp)
        for name, value in [('key.pem', public_bytes), ('manifest.json', raw), ('manifest.sig', values['manifest.sig'])]:
            create_new(tmp / name, value, 0o600)
        fingerprint = public_fingerprint(tmp / 'key.pem')
        openssl('dgst', '-sha256', '-verify', tmp / 'key.pem', '-signature', tmp / 'manifest.sig', tmp / 'manifest.json')
    manifest = json.loads(raw)
    require(encoded(manifest) == raw, 'manifest must use the canonical format; duplicate fields are forbidden')
    require(set(manifest) == {'format', 'build', 'source_revision', 'signing_key_sha256', 'files'} and manifest['format'] == 1, 'unknown manifest format')
    validate_info(manifest['build'])
    require(re.fullmatch(r'[0-9a-f]{40}', manifest['source_revision']), 'invalid source revision')
    require(manifest['signing_key_sha256'] == fingerprint, 'manifest signing key does not match trusted key')
    require(set(manifest['files']) == {'relay', 'THIRD_PARTY.md'}, 'unexpected manifest payload')
    for name, record in manifest['files'].items():
        require(record == {'size': len(values[name]), 'sha256': sha(values[name])}, 'payload checksum or size mismatch')
    target_header(values['relay'], manifest['build'])
    return {'manifest': manifest, 'id': sha(raw), 'files': values, 'public_key': public_bytes}
