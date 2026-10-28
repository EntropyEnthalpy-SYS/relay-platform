"""Owned installation generations, atomic selection and recoverable switches.

Runtime state is outside generations. Neither rollback nor removal rewinds it.
"""
from contextlib import contextmanager
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import socket
import stat
import subprocess
from urllib.parse import urlsplit
import uuid

from . import bundle
from .bundle import DeployError, encoded, regular, require, sha
from .host import Services, account, command, inventory, logrotate_text, service_text

OWNER = {'product': 'relay-platform', 'installer_format': 1}


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic(path, data, mode=0o600):
    temporary = path.with_name('.' + path.name + '.' + uuid.uuid4().hex)
    try:
        bundle.create_new(temporary, data, mode)
        os.replace(temporary, path)
        sync_directory(path.parent)
    finally:
        if temporary.exists():
            temporary.unlink()


def provision_file(layout, path, data, mode, uid=None, gid=None):
    layout.guard(path)
    if path.exists():
        require(regular(path, max(len(data), 1)) == data, f'interrupted provision has unexpected file content: {path}')
        require(path.stat().st_uid in (os.geteuid(), uid), 'unexpected provisioning file owner')
        require(path.stat().st_nlink == 1, 'refusing to modify a multiply linked provisioning file')
    else:
        bundle.create_new(path, data, mode)
    path.chmod(mode)
    if uid is not None:
        os.chown(path, uid, gid)
    sync_directory(path.parent)


def settings(role, supplied):
    require(isinstance(supplied, dict), 'settings must be a JSON object')
    if role == 'controller':
        require(set(supplied) <= {'listen', 'behind_tls_proxy'}, 'unknown controller setting')
        result = {'listen': '127.0.0.1:8080', 'behind_tls_proxy': False, **supplied}
        require(type(result['behind_tls_proxy']) is bool, 'behind_tls_proxy must be boolean')
        address, separator, port = result['listen'].rpartition(':')
        require(separator and port.isdigit() and 1024 <= int(port) <= 65535, 'controller listen requires a nonprivileged port')
        ip = ipaddress.ip_address(address.strip('[]'))
        require(ip.is_loopback or result['behind_tls_proxy'], 'non-loopback controller requires behind_tls_proxy')
        require('[' not in address if ip.version == 4 else address.startswith('[') and address.endswith(']'), 'invalid listen address')
        return result
    require(set(supplied) <= {'controller', 'node_id', 'poll_seconds', 'protocol_engine', 'tls_directory'} and {'controller', 'node_id'} <= set(supplied), 'agent settings require controller and node_id')
    result = {'poll_seconds': 5, **supplied}
    for key in ('protocol_engine', 'tls_directory'):
        if key in result:
            value = result[key]
            require(isinstance(value, str) and re.fullmatch(r'/[A-Za-z0-9_./-]+', value) and '..' not in Path(value).parts, f'{key} must be an absolute local path without traversal or shell metacharacters')
    require(isinstance(result['node_id'], str) and re.fullmatch(r'[A-Za-z0-9_-]{1,128}', result['node_id']), 'invalid node identifier')
    require(type(result['poll_seconds']) is int and 1 <= result['poll_seconds'] <= 300, 'poll_seconds must be 1..300')
    url = urlsplit(result['controller'])
    require(url.hostname and not url.username and not url.password and not url.query and not url.fragment and url.path in ('', '/'), 'controller must be a plain origin URL')
    require(url.port is None or 1 <= url.port <= 65535, 'invalid controller port')
    require(url.scheme == 'https' or (url.scheme == 'http' and url.hostname in ('localhost', '127.0.0.1', '::1')), 'remote controller requires HTTPS')
    result['controller'] = result['controller'].rstrip('/')
    return result


class Layout:
    def __init__(self, root, role, manager=None):
        require(role in ('controller', 'agent'), 'invalid role')
        given = Path(root).absolute()
        require(not given.is_symlink(), 'staging root cannot be a symlink')
        self.root = given.resolve()
        # Native paths are fixed; stage paths also appear in init files.
        require(re.fullmatch(r'/[A-Za-z0-9_./-]*', str(self.root)), 'installation root must be an absolute path without whitespace or shell metacharacters')
        self.staged = self.root != Path('/')
        self.role = role
        self.prefix = self.path('/opt/relay-platform')
        self.admin = self.prefix / '.admin'
        self.base = self.prefix / 'roles' / role
        self.generations = self.base / 'generations'
        self.current = self.base / 'current'
        self.index = self.base / 'installation.json'
        self.pending = self.base / 'pending.json'
        self.state = self.path('/var/lib/relay-platform/' + role)
        self.config = self.path('/etc/relay-platform/' + role)
        self.log = self.path('/var/log/relay-platform/' + role + '/relay.log')
        self.manager = manager

    def path(self, path):
        require(isinstance(path, str) and path.startswith('/') and '..' not in Path(path).parts, 'invalid managed absolute path')
        return self.root / path.lstrip('/')

    def guard(self, path, allow_leaf_symlink=False):
        require(path.is_relative_to(self.root), 'path escapes installation root')
        current = self.root
        if current.exists():
            root_info = current.stat()
            require(root_info.st_uid == os.geteuid() and root_info.st_mode & 0o022 == 0, 'installation root is not privately controlled by the installer account')
        for part in path.relative_to(self.root).parts:
            current /= part
            try:
                info = current.lstat()
            except FileNotFoundError:
                break
            if allow_leaf_symlink and current == path and stat.S_ISLNK(info.st_mode):
                continue
            require(not stat.S_ISLNK(info.st_mode), f'symlink in managed path: {current}')
            if current != path:
                require(stat.S_ISDIR(info.st_mode), 'non-directory path component')
                require(info.st_mode & 0o022 == 0, f'writable ancestor of managed path: {current}')
                if current != self.log.parent:
                    require(info.st_uid == os.geteuid(), f'ancestor belongs to another account: {current}')

    def owned(self, path):
        self.guard(path)
        info = path.stat()
        require(info.st_uid == os.geteuid() and info.st_mode & 0o022 == 0, f'managed path is writable by another account: {path}')
        require(not stat.S_ISREG(info.st_mode) or info.st_nlink == 1, 'managed files must not be hard-linked elsewhere')

    def mkdir(self, path, mode=0o755):
        self.guard(path)
        missing = []
        current = path
        while not current.exists():
            missing.append(current)
            current = current.parent
        for directory in reversed(missing):
            desired = mode if directory == path else 0o755
            directory.mkdir(mode=desired)
            directory.chmod(desired)
            sync_directory(directory.parent)
        require(path.is_dir(), f'not a directory: {path}')

    def read(self, path):
        self.guard(path)
        self.owned(path)
        return json.loads(regular(path, 1024 * 1024))

    def owner(self):
        self.owned(self.prefix)
        require(self.read(self.prefix / 'OWNER.json') == OWNER, 'installation directory belongs to another tool')

    @contextmanager
    def lock(self, create=False):
        self.guard(self.prefix)
        if not self.prefix.exists():
            require(create, 'no managed installation')
            self.mkdir(self.prefix.parent)
            self.prefix.mkdir(mode=0o755)
            self.prefix.chmod(0o755)
            bundle.create_new(self.prefix / 'OWNER.json', encoded(OWNER), 0o644)
            sync_directory(self.prefix)
        self.owner()
        self.mkdir(self.admin, 0o700)
        self.owned(self.admin)
        fd = os.open(self.admin / 'lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield
        except BlockingIOError:
            raise DeployError('another deployment is in progress') from None
        finally:
            os.close(fd)

    def service_path(self, manager):
        return self.path('/etc/systemd/system/relay-platform-' + self.role + '.service' if manager == 'systemd'
                         else '/etc/init.d/relay-platform-' + self.role)

    def rotation_path(self):
        return self.path('/etc/logrotate.d/relay-platform-' + self.role)

    def load_index(self):
        self.guard(self.index)
        if not self.index.exists():
            return None
        value = self.read(self.index)
        self.validate_index(value)
        return value

    def validate_index(self, value):
        require(set(value) == {'format', 'role', 'manager', 'staged', 'uid', 'gid', 'user', 'current', 'previous', 'managed_files', 'removed', 'state_contract', 'settings'}, 'invalid installation record fields')
        require(value.get('role') == self.role and value.get('format') == 1 and value.get('staged') == self.staged, 'invalid installation record')
        require(value.get('manager') in ('systemd', 'openrc'), 'invalid installed service manager')
        require(self.manager is None or self.manager == value['manager'], 'service manager changes require a separate migration')
        expected = {'/' + self.service_path(value['manager']).relative_to(self.root).as_posix()}
        if value['manager'] == 'openrc':
            expected.add('/' + self.rotation_path().relative_to(self.root).as_posix())
        require(set(value['managed_files']) == expected, 'installation record references unmanaged paths')
        require(all(re.fullmatch(r'[0-9a-f]{64}', h) for h in value['managed_files'].values()), 'invalid recorded service digest')
        require(all(value[k] is None or re.fullmatch(r'[0-9a-f]{64}', value[k]) for k in ('current', 'previous')), 'invalid recorded generation')
        require(type(value['removed']) is bool, 'invalid removal state')
        require(type(value['state_contract']) is int and 0 < value['state_contract'] <= 65535, 'invalid installed state contract')
        require(settings(self.role, value['settings']) == value['settings'], 'invalid installed settings')

    def selected(self):
        self.guard(self.current, allow_leaf_symlink=True)
        if not self.current.is_symlink():
            require(not self.current.exists(), 'current selection is not a managed symlink')
            return None
        value = os.readlink(self.current)
        require(re.fullmatch(r'generations/[0-9a-f]{64}', value), 'current link is not an owned generation')
        return value.split('/')[1]

    def check_files(self, index):
        self.validate_index(index)
        for path, digest in index['managed_files'].items():
            file = self.path(path)
            self.owned(file)
            require(sha(regular(file, 1024 * 1024)) == digest, f'managed service file was modified: {file}')

    def generation(self, identity):
        require(isinstance(identity, str) and re.fullmatch(r'[0-9a-f]{64}', identity), 'invalid generation ID')
        folder = self.generations / identity
        self.owned(folder)
        config = self.read(folder / 'settings.json')
        require(set(config) == {'bundle_id', 'settings', 'ca_sha256', 'role'}, 'invalid generation settings')
        require(sha(encoded(config)) == identity and config['role'] == self.role, 'generation settings were changed')
        require(settings(self.role, config['settings']) == config['settings'], 'noncanonical generation settings')
        values = {name: regular(folder / name, limit) for name, limit in bundle.LIMITS.items()}
        for name in [*bundle.LIMITS, 'trusted-key.pem', 'settings.json', 'run']:
            self.owned(folder / name)
        verified = bundle.verify_values(values, regular(folder / 'trusted-key.pem', 32768))
        require(verified['id'] == config['bundle_id'], 'generation bundle changed')
        ca = None
        expected = {*bundle.LIMITS, 'trusted-key.pem', 'settings.json', 'run'}
        if config['ca_sha256']:
            self.owned(folder / 'ca.pem')
            ca = regular(folder / 'ca.pem', 1024 * 1024)
            require(sha(ca) == config['ca_sha256'], 'CA certificate changed')
            expected.add('ca.pem')
        require({p.name for p in folder.iterdir()} == expected, 'untracked files in generation; refusing to modify it')
        require(regular(folder / 'run', 65536) == self.wrapper(config['settings'], folder, bool(ca)), 'service wrapper changed')
        return verified, config

    def wrapper(self, config, folder, ca):
        args = [str(folder / 'relay')]
        if self.role == 'controller':
            args += ['server', '--listen', config['listen'], '--state', str(self.state)]
            if config['behind_tls_proxy']:
                args += ['--behind-tls-proxy']
        else:
            args += ['agent', '--controller', config['controller'], '--node-id', config['node_id'],
                     '--state', str(self.state), '--poll-seconds', str(config['poll_seconds']),
                     '--enrollment-token-file', str(self.config / 'enrollment.secret')]
            if ca:
                args += ['--ca-certificate', str(folder / 'ca.pem')]
            if config.get('tls_directory'):
                args += ['--tls-directory', config['tls_directory']]
            if config.get('protocol_engine'):
                args = ['/usr/bin/env', 'RELAY_PROTOCOL_ENGINE=' + config['protocol_engine'], *args]
        return ('#!/bin/sh\numask 077\nexec ' + shlex.join(args) + '\n').encode()

    def write_generation(self, verified, config, ca):
        descriptor = {'bundle_id': verified['id'], 'settings': config, 'ca_sha256': sha(ca) if ca else None, 'role': self.role}
        identity = sha(encoded(descriptor))
        target = self.generations / identity
        self.mkdir(self.generations)
        if target.exists():
            self.generation(identity)
            return identity
        temporary = self.generations / ('.preparing-' + uuid.uuid4().hex)
        temporary.mkdir(mode=0o755)
        temporary.chmod(0o755)
        try:
            for name, value in {**verified['files'], 'trusted-key.pem': verified['public_key'],
                                'settings.json': encoded(descriptor), 'run': self.wrapper(config, target, bool(ca))}.items():
                bundle.create_new(temporary / name, value, 0o755 if name in ('relay', 'run') else 0o644)
            if ca:
                bundle.create_new(temporary / 'ca.pem', ca, 0o644)
            sync_directory(temporary)
            os.rename(temporary, target)
            sync_directory(self.generations)
        finally:
            if temporary.exists():
                shutil.rmtree(temporary)
        self.generation(identity)
        return identity

    def switch(self, old, new, index, checkpoint=lambda _: None, files=None):
        require(not self.pending.exists(), 'recover the pending deployment first')
        operation = {'format': 1, 'from': old, 'to': new, 'index': index}
        if files:
            operation['files'] = files
        atomic(self.pending, encoded(operation))
        checkpoint('intent_durable')
        self.finish(operation, checkpoint)

    def finish(self, operation, checkpoint=lambda _: None):
        require(operation.get('format') == 1, 'invalid pending deployment format')
        require(self.selected() in (operation['from'], operation['to']), 'current selection conflicts with pending operation')
        verified, descriptor = self.generation(operation['to'])
        index = operation['index']
        self.validate_index(index)
        require(index['settings'] == descriptor['settings'] and index['state_contract'] == verified['manifest']['build']['state_contract'][self.role], 'pending installation receipt differs from target generation')
        require(index['current'] == operation['to'] and index['previous'] == operation['from'], 'pending receipt mismatch')
        # Service files rendered by a newer installer replace the ones it
        # recorded; an interrupted switch finds either version and finishes.
        for path, change in operation.get('files', {}).items():
            file = self.path(path)
            self.owned(file)
            body = change['body'].encode()
            found = sha(regular(file, 1024 * 1024))
            require(found in (change['from'], sha(body)), f'managed service file was modified: {file}')
            if found != sha(body):
                atomic(file, body, change['mode'])
        self.check_files(index)
        temporary = self.current.with_name('.select-' + uuid.uuid4().hex)
        try:
            os.symlink('generations/' + operation['to'], temporary)
            os.replace(temporary, self.current)
            sync_directory(self.base)
        finally:
            if temporary.is_symlink():
                temporary.unlink()
        checkpoint('selection_durable')
        atomic(self.index, encoded(index))
        checkpoint('receipt_durable')
        self.pending.unlink()
        sync_directory(self.base)

    def status(self):
        self.guard(self.prefix)
        if not self.prefix.exists():
            return {'role': self.role, 'installed': False, 'staged': self.staged}
        self.owner()
        index = self.load_index()
        pending = self.read(self.pending) if self.pending.exists() else None
        removing = (self.base / 'removing.json').exists()
        result = {'role': self.role, 'installed': index is not None and not index.get('removed'), 'staged': self.staged,
                  'current': self.selected(), 'pending': None if pending is None else {k: pending[k] for k in ('from', 'to')},
                  'state_directory': str(self.state), 'runtime_state_preserved': True}
        result['removal_pending'] = removing
        result['provisioning_pending'] = (self.base / 'provisioning.json').exists()
        if index:
            result.update(previous=index['previous'], manager=index['manager'], removed=index.get('removed', False))
            if not index.get('removed') and not pending and not removing:
                self.check_files(index)
                verified, _ = self.generation(result['current'])
                result['build'] = verified['manifest']['build']
                result['service_state'] = Services(index['manager'], self.staged).status(self.role)
        return result


def preflight(layout, verified=None, supplied=None):
    host = inventory()
    errors = []
    manager = layout.manager or host['service_manager']
    if manager not in ('systemd', 'openrc'):
        errors.append('no running supported service manager; specify one only for staged rendering')
    if not layout.staged:
        if not host['system_install_supported']:
            errors.append('native installation requires Linux with systemd or OpenRC')
        if os.geteuid() != 0:
            errors.append('native installation requires root')
        if manager != host['service_manager']:
            errors.append('selected manager is not the host manager')
        if manager == 'openrc':
            for name in ('supervise-daemon', 'logrotate', 'rc-update'):
                try:
                    command(name)
                except DeployError as error:
                    errors.append(str(error))
    if verified:
        build = verified['manifest']['build']
        if (build['os'], build['arch']) != (host['os'], host['arch']):
            errors.append('bundle target differs from this host; verification succeeds but execution/installation is not allowed')
        if not layout.staged and build['os'] != 'linux':
            errors.append('macOS bundles are development-only and cannot be installed on Linux')
    nearest = layout.root
    while not nearest.exists():
        nearest = nearest.parent
    available = shutil.disk_usage(nearest).free
    required = sum(len(value) for value in verified['files'].values()) + 16 * 1024 * 1024 if verified else 0
    if available < required:
        errors.append('insufficient free space for one new installation generation')
    bindable = None
    if supplied is not None:
        try:
            config = settings(layout.role, supplied)
            if layout.role == 'controller':
                address, _, port = config['listen'].rpartition(':')
                host_address = address.strip('[]')
                family = socket.AF_INET6 if ':' in host_address else socket.AF_INET
                with socket.socket(family, socket.SOCK_STREAM) as probe:
                    probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    probe.bind((host_address, int(port)))
                bindable = True
        except (DeployError, OSError, ValueError, TypeError) as error:
            bindable = False if layout.role == 'controller' else None
            errors.append('configuration/listener preflight: ' + str(error))
    for path in (layout.prefix, layout.state, layout.config, layout.log.parent):
        try:
            layout.guard(path)
        except DeployError as error:
            errors.append(str(error))
    return {'host': host, 'staged': layout.staged, 'role': layout.role, 'manager': manager,
            'ready': not errors, 'errors': errors, 'changes_system': False,
            'free_bytes': available, 'new_generation_required_bytes': required,
            'controller_listener_bindable_now': bindable,
            'limitations': ['service-manager active is not node enrollment or business readiness',
                            'no firewall, sysctl, routing or low-port capabilities are changed']}


def refreshed_files(layout, index):
    """Managed service files whose rendering changed since they were installed."""
    manager, user = index['manager'], index['user']
    wanted = [(layout.service_path(manager), service_text(manager, layout.role, layout.current, layout.state, user, layout.log),
               0o644 if manager == 'systemd' else 0o755)]
    if manager == 'openrc':
        wanted.append((layout.rotation_path(), logrotate_text(layout.log, user), 0o644))
    changes = {}
    for path, body, mode in wanted:
        key = '/' + path.relative_to(layout.root).as_posix()
        if key in index['managed_files'] and index['managed_files'][key] != sha(body.encode()):
            changes[key] = {'from': index['managed_files'][key], 'body': body, 'mode': mode}
    return changes


def deploy(layout, verified, supplied, enrollment=None, ca=None, checkpoint=lambda _: None):
    report = preflight(layout, verified, supplied)
    require(report['ready'], '; '.join(report['errors']))
    manager = report['manager']
    config = settings(layout.role, supplied)
    token = None
    if enrollment:
        token = regular(enrollment, 256).strip()
        require(re.fullmatch(rb'[a-fA-F0-9]{64}', token), 'enrollment token file must contain a 256-bit hexadecimal token')
    ca_bytes = regular(ca, 1024 * 1024) if ca else None
    require(not ca_bytes or (b'-----BEGIN CERTIFICATE-----' in ca_bytes and b'PRIVATE KEY' not in ca_bytes), 'CA input must contain certificates, not private keys')
    require(layout.role == 'agent' or (token is None and ca_bytes is None), 'controller does not use agent enrollment or CA options')
    with layout.lock(create=True):
        layout.mkdir(layout.base)
        require(not layout.pending.exists(), 'recover pending deployment before installing another version')
        require(not (layout.base / 'removing.json').exists(), 'recover pending removal first')
        provision = layout.base / 'provisioning.json'
        old_index = layout.load_index()
        restoring = bool(old_index and old_index['removed'])
        if old_index:
            if restoring:
                require(layout.selected() is None, 'removed role unexpectedly has a selected generation')
                if not provision.exists():
                    for path in old_index['managed_files']:
                        file = layout.path(path); layout.guard(file)
                        require(not file.exists(), 'reinstall would overwrite a service file created after removal')
                for path in (layout.state, layout.log.parent):
                    layout.guard(path)
                    require(path.is_dir() and path.stat().st_uid == old_index['uid'] and path.stat().st_mode & 0o077 == 0, 'retained runtime directory ownership or permissions changed')
                layout.owned(layout.config)
            else:
                layout.check_files(old_index)
                Services(manager, layout.staged).stopped(layout.role)
                old_verified, old_config = layout.generation(old_index['current'])
                require(old_verified['manifest']['build']['state_contract'][layout.role] == old_index['state_contract'] and old_config['settings'] == old_index['settings'], 'installed receipt does not match selected generation')
                require(layout.selected() == old_index['current'], 'selection differs from installation record')
            require(old_index['state_contract'] == verified['manifest']['build']['state_contract'][layout.role], 'incompatible state contract; use a separately verified migration, not this deployment path')
            require(token is None, 'existing identity cannot be replaced by an installer enrollment file')
            if layout.role == 'agent':
                require(all(config[k] == old_index['settings'][k] for k in ('controller', 'node_id')), 'agent identity is fixed to its existing controller and node ID')
                if ca_bytes is None and not restoring and old_config['ca_sha256']:
                    # Upgrades keep trusting the controller CA unless a new one is supplied.
                    ca_bytes = regular(layout.generations / old_index['current'] / 'ca.pem', 1024 * 1024)
        else:
            require(layout.selected() is None, 'unrecorded current selection exists')
            if not provision.exists():
                for path in (layout.state, layout.config, layout.service_path(manager), layout.log.parent):
                    layout.guard(path)
                    require(not path.exists(), f'preexisting unowned installation path: {path}')
                if manager == 'openrc':
                    layout.guard(layout.rotation_path())
                    require(not layout.rotation_path().exists(), 'unowned logrotate file already exists')
            require(layout.role != 'agent' or token is not None, 'first agent installation requires a token file')
        generation = layout.write_generation(verified, config, ca_bytes)
        # Execute only the already-verified native payload, before selecting it.
        actual = bundle.build_info(layout.generations / generation / 'relay')
        require(actual == verified['manifest']['build'], 'binary build-info differs from its signed manifest')
        refresh = refreshed_files(layout, old_index) if old_index and not restoring else {}
        if old_index and not restoring and generation == old_index['current'] and not refresh:
            return {'changed': False, **layout.status()}
        if old_index and not restoring:
            managed = {**old_index['managed_files'], **{k: sha(v['body'].encode()) for k, v in refresh.items()}}
            if generation == old_index['current']:
                # Same program and settings; only the service files change.
                index = {**old_index, 'managed_files': managed}
            else:
                index = {**old_index, 'current': generation, 'previous': old_index['current'], 'settings': config, 'managed_files': managed}
        else:
            # Exact repeat of the original signed bundle/settings resumes a first
            # provision. No service can start before the selection is committed.
            intent = {'format': 1, 'manager': manager, 'generation': generation, 'token_sha256': sha(token) if token else None, 'restoring': restoring}
            if provision.exists():
                require(layout.read(provision) == intent, 'repeat the original first deployment with the same settings and enrollment file')
            else:
                atomic(provision, encoded(intent))
            checkpoint('provision_intent_durable')
            uid, gid, user = account(layout.role, layout.state, layout.staged)
            if restoring:
                require((uid, gid, user) == (old_index['uid'], old_index['gid'], old_index['user']), 'retained service account changed; explicit account recovery is required')
            for path in (layout.state, layout.config, layout.log.parent):
                layout.guard(path)
                if path.exists():
                    require(path.is_dir() and path.stat().st_uid in (os.geteuid(), uid), 'unexpected provisioning directory')
                    if not restoring:
                        allowed = {'enrollment.secret'} if path == layout.config and token else {'relay.log'} if path == layout.log.parent and manager == 'openrc' else set()
                        require({p.name for p in path.iterdir()} <= allowed, 'provisioning directory contains unexpected data; refusing to adopt it')
                layout.mkdir(path, 0o700 if path != layout.config else 0o755)
                if path != layout.config:
                    os.chown(path, uid, gid)
            if token:
                file = layout.config / 'enrollment.secret'
                provision_file(layout, file, token + b'\n', 0o600, uid, gid)
            if manager == 'openrc':
                if restoring and layout.log.exists():
                    layout.guard(layout.log)
                    info = layout.log.stat()
                    require(stat.S_ISREG(info.st_mode) and info.st_uid == uid and info.st_nlink == 1, 'retained log path is not owned by the managed service')
                else:
                    provision_file(layout, layout.log, b'', 0o600, uid, gid)
            files = {}
            service = layout.service_path(manager)
            layout.mkdir(service.parent)
            body = service_text(manager, layout.role, layout.current, layout.state, user, layout.log).encode()
            provision_file(layout, service, body, 0o644 if manager == 'systemd' else 0o755)
            checkpoint('service_file_durable')
            files['/' + service.relative_to(layout.root).as_posix()] = sha(body)
            if manager == 'openrc':
                rotation = layout.rotation_path()
                layout.mkdir(rotation.parent)
                body = logrotate_text(layout.log, user).encode()
                provision_file(layout, rotation, body, 0o644)
                files['/' + rotation.relative_to(layout.root).as_posix()] = sha(body)
            index = {'format': 1, 'role': layout.role, 'manager': manager, 'staged': layout.staged,
                     'uid': uid, 'gid': gid, 'user': user, 'current': generation, 'previous': None,
                     'managed_files': files, 'removed': False, 'settings': config,
                     'state_contract': verified['manifest']['build']['state_contract'][layout.role]}
        layout.switch(index['previous'], generation, index, checkpoint, refresh)
        provision = layout.base / 'provisioning.json'
        if provision.exists():
            provision.unlink()
            sync_directory(layout.base)
        Services(manager, layout.staged).reload()
        return {'changed': True, **layout.status()}


def recover(layout):
    with layout.lock():
        removal = layout.base / 'removing.json'
        if removal.exists():
            return finish_remove(layout, layout.read(removal))
        require(layout.pending.exists(), 'no pending selection to recover')
        operation = layout.read(layout.pending)
        Services(operation['index']['manager'], layout.staged).stopped(layout.role)
        layout.finish(operation)
        provision = layout.base / 'provisioning.json'
        if provision.exists():
            provision.unlink()
            sync_directory(layout.base)
        Services(operation['index']['manager'], layout.staged).reload()
        return layout.status()


def rollback(layout, checkpoint=lambda _: None):
    with layout.lock():
        require(not layout.pending.exists(), 'recover the pending deployment first')
        require(not (layout.base / 'removing.json').exists(), 'recover pending removal before rollback')
        index = layout.load_index()
        require(index and not index['removed'] and index['previous'], 'no installed previous generation')
        require(layout.selected() == index['current'], 'selection differs from installation record')
        layout.check_files(index)
        Services(index['manager'], layout.staged).stopped(layout.role)
        current, _ = layout.generation(index['current'])
        previous, previous_config = layout.generation(index['previous'])
        require(current['manifest']['build']['state_contract'][layout.role] == previous['manifest']['build']['state_contract'][layout.role], 'rollback would cross a persisted-state compatibility boundary')
        result = {**index, 'current': index['previous'], 'previous': index['current'], 'settings': previous_config['settings']}
        layout.switch(result['previous'], result['current'], result, checkpoint)
        return {'runtime_state_restored': False, **layout.status()}


def control(layout, action):
    with layout.lock():
        require(not layout.pending.exists(), 'recover pending deployment before service actions')
        require(not (layout.base / 'removing.json').exists(), 'recover pending removal before service actions')
        index = layout.load_index()
        require(index and not index['removed'], 'role is not installed')
        layout.check_files(index)
        require(layout.selected() == index['current'], 'selection differs from installation record')
        layout.generation(index['current'])
        Services(index['manager'], layout.staged).action(layout.role, action)
        return layout.status()


def remove(layout, checkpoint=lambda _: None):
    with layout.lock():
        require(not layout.pending.exists(), 'recover pending deployment before removal')
        require(not (layout.base / 'removing.json').exists(), 'recover pending removal first')
        index = layout.load_index()
        require(index and not index['removed'], 'role is not installed')
        require(layout.selected() == index['current'], 'selection differs from installation record')
        layout.check_files(index)
        manager = Services(index['manager'], layout.staged)
        manager.stopped(layout.role)
        # Validate every owned generation before any deletion. Unknown content is
        # preserved for the operator, never recursively removed from a guessed path.
        generations = list(layout.generations.iterdir())
        for folder in generations:
            layout.generation(folder.name)
        if not layout.staged:
            manager.action(layout.role, 'disable')
        operation = {'format': 1, 'index': index, 'generations': {
            folder.name: {file.name: sha(regular(file, bundle.MAX_BINARY)) for file in folder.iterdir()} for folder in generations}}
        atomic(layout.base / 'removing.json', encoded(operation))
        checkpoint('removal_intent_durable')
        return finish_remove(layout, operation, checkpoint)


def finish_remove(layout, operation, checkpoint=lambda _: None):
    require(operation.get('format') == 1, 'invalid removal intent')
    index = operation['index']
    layout.validate_index(index)
    manager = Services(index['manager'], layout.staged)
    service = layout.service_path(index['manager'])
    if service.exists():
        manager.stopped(layout.role)
    # Removal was authorized only after proving the managed service stopped. A
    # removed OpenRC script is no longer queryable; no tool action can start it.
    require(layout.selected() in (None, index['current']), 'unexpected current selection during removal')
    known = operation['generations']
    require({p.name for p in layout.generations.iterdir()} <= set(known), 'unknown generation appeared during removal')
    for identity, files in known.items():
        require(re.fullmatch(r'[0-9a-f]{64}', identity), 'invalid removal generation')
        folder = layout.generations / identity
        layout.guard(folder)
        if folder.exists():
            layout.owned(folder)
            require({p.name for p in folder.iterdir()} <= set(files), 'new file appeared during removal')
            for file in folder.iterdir():
                layout.owned(file)
                require(sha(regular(file, bundle.MAX_BINARY)) == files[file.name], 'generation changed during removal')
    for path, digest in index['managed_files'].items():
        file = layout.path(path)
        layout.guard(file)
        if file.exists():
            layout.owned(file)
            require(sha(regular(file, 1024 * 1024)) == digest, 'service file changed during removal')
    for path in index['managed_files']:
        file = layout.path(path)
        if file.exists():
            file.unlink()
            sync_directory(file.parent)
    checkpoint('service_files_removed')
    if layout.current.is_symlink():
        layout.current.unlink()
        sync_directory(layout.base)
    for identity in known:
        folder = layout.generations / identity
        if folder.exists():
            for file in folder.iterdir():
                file.unlink()
                checkpoint('generation_file_removed')
            folder.rmdir()
    sync_directory(layout.generations)
    atomic(layout.index, encoded({**index, 'removed': True, 'current': None, 'previous': None}))
    (layout.base / 'removing.json').unlink()
    sync_directory(layout.base)
    manager.reload()
    return {'runtime_state_deleted': False, 'service_account_deleted': False, **layout.status()}
