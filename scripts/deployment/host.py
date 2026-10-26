"""Read-only host inventory and explicit native service operations."""
import os
import grp
from pathlib import Path
import platform
import pwd
import shutil
import subprocess

from .bundle import DeployError, require

SAFE_PATH = '/usr/sbin:/usr/bin:/sbin:/bin'


def command(name):
    path = shutil.which(name, path=SAFE_PATH)
    require(path, f'required host command is missing: {name}')
    return path


def run(name, *args, allowed=(0,)):
    result = subprocess.run([command(name), *map(str, args)], capture_output=True, timeout=45,
                            env={**os.environ, 'PATH': SAFE_PATH, 'LC_ALL': 'C'})
    require(result.returncode in allowed, f'{name} {args[0] if args else ""} failed (exit {result.returncode})')
    return result


def inventory():
    system = {'Linux': 'linux', 'Darwin': 'macos'}.get(platform.system(), platform.system().lower())
    architecture = {'arm64': 'aarch64', 'aarch64': 'aarch64', 'amd64': 'x86_64', 'x86_64': 'x86_64'}.get(platform.machine().lower(), platform.machine())
    distribution = {}
    if system == 'linux' and Path('/etc/os-release').is_file():
        # Parse data; never source the shell-compatible os-release file.
        for line in Path('/etc/os-release').read_text().splitlines():
            key, _, value = line.partition('=')
            if key in ('ID', 'VERSION_ID', 'PRETTY_NAME'):
                distribution[key.lower()] = value.strip().strip('"')
    manager = None
    if system == 'linux':
        if Path('/run/systemd/system').is_dir() and shutil.which('systemctl', path=SAFE_PATH):
            manager = 'systemd'
        elif Path('/sbin/openrc-run').is_file() and shutil.which('rc-service', path=SAFE_PATH) and Path('/run/openrc').is_dir():
            manager = 'openrc'
    return {'os': system, 'arch': architecture, 'kernel': platform.release(), 'distribution': distribution,
            'service_manager': manager, 'effective_uid': os.geteuid(), 'python': platform.python_version(),
            'openssl': bool(shutil.which('openssl', path=SAFE_PATH)),
            'system_install_supported': system == 'linux' and architecture in ('x86_64', 'aarch64') and manager is not None}


class Services:
    def __init__(self, manager, staged=False):
        require(manager in ('systemd', 'openrc'), 'select systemd or openrc')
        self.manager, self.staged = manager, staged

    def _native(self):
        require(not self.staged, 'a staged filesystem cannot control host services')
        info = inventory()
        require(info['os'] == 'linux' and info['effective_uid'] == 0, 'system service operations require Linux root')
        require(info['service_manager'] == self.manager, 'selected manager is not the running host manager')

    def status(self, role):
        if self.staged:
            return 'staged'
        self._native()
        name = 'relay-platform-' + role
        if self.manager == 'systemd':
            result = run('systemctl', 'show', name, '--property=ActiveState', '--value', allowed=(0, 1))
            value = result.stdout.decode().strip()
            require(value in ('active', 'inactive', 'failed', 'activating', 'deactivating', 'reloading'), 'cannot determine systemd service state')
            return value
        result = run('rc-service', name, 'status', allowed=(0, 1, 3))
        if result.returncode == 0:
            return 'active'
        # OpenRC status 3 is stopped; a failed/unknown status is not proof of stop.
        require(result.returncode == 3, 'cannot prove OpenRC service is stopped')
        return 'inactive'

    def stopped(self, role):
        require(self.status(role) in ('staged', 'inactive', 'failed'), 'stop the managed service before changing or removing its installation')

    def reload(self):
        if self.staged:
            return
        self._native()
        if self.manager == 'systemd':
            run('systemctl', 'daemon-reload')

    def action(self, role, action):
        self._native()
        name = 'relay-platform-' + role
        require(action in ('start', 'stop', 'enable', 'disable'), 'unsupported service action')
        if self.manager == 'systemd':
            run('systemctl', action, name)
        elif action in ('enable', 'disable'):
            listing = run('rc-update', 'show', 'default').stdout.decode().splitlines()
            enabled = any(line.split() and line.split()[0] == name for line in listing)
            if enabled != (action == 'enable'):
                run('rc-update', 'add' if action == 'enable' else 'del', name, 'default')
        else:
            run('rc-service', name, action)
        if action == 'stop':
            self.stopped(role)
        if action == 'start':
            require(self.status(role) == 'active', 'service manager did not report active; inspect service logs')


def account(role, state, staged=False):
    if staged:
        return os.geteuid(), os.getegid(), 'staged-current-user'
    require(os.geteuid() == 0, 'system installation requires root')
    name = 'relayp-' + role
    try:
        user = pwd.getpwnam(name)
    except KeyError:
        shell = '/usr/sbin/nologin' if Path('/usr/sbin/nologin').is_file() else '/sbin/nologin'
        require(Path(shell).is_file(), 'nologin shell is missing')
        try:
            group = grp.getgrnam(name)
            require(not group.gr_mem and not any(p.pw_gid == group.gr_gid for p in pwd.getpwall()), 'existing provisioning group is not empty')
        except KeyError:
            group = None
        if shutil.which('useradd', path=SAFE_PATH):
            group_args = ['--gid', name] if group else ['--user-group']
            run('useradd', '--system', *group_args, '--no-create-home', '--home-dir', state, '--shell', shell, name)
        else:
            if group is None:
                run('addgroup', '-S', name)
            run('adduser', '-S', '-D', '-H', '-h', state, '-s', shell, '-G', name, name)
        user = pwd.getpwnam(name)
    require(user.pw_uid != 0 and user.pw_dir == str(state) and user.pw_shell.endswith('/nologin'), 'existing service account is not the dedicated managed account')
    require(grp.getgrnam(name).gr_gid == user.pw_gid, 'service account must use its dedicated primary group')
    return user.pw_uid, user.pw_gid, name


def service_text(manager, role, current, state, user, log):
    name = 'relay-platform-' + role
    # The agent lists local addresses through netlink for loop protection;
    # reading them needs no capability.
    families = 'AF_UNIX AF_INET AF_INET6' + (' AF_NETLINK' if role == 'agent' else '')
    if manager == 'systemd':
        # Fixed native paths contain no whitespace. Staging roots are validated.
        return f'''[Unit]
Description=Relay independent {role}
After=network-online.target
Wants=network-online.target
# A relay should recover from any crash loop on its own: never stop retrying.
StartLimitIntervalSec=0

[Service]
Type=simple
User={user}
Group={user}
ExecStart={current}/run
WorkingDirectory={state}
Restart=on-failure
# 1 s after a crash, growing to 30 s while it keeps failing (systemd 254+;
# older versions ignore the step settings and keep 1 s).
RestartSec=1
RestartSteps=5
RestartMaxDelaySec=30
TimeoutStopSec=30
KillMode=control-group
UMask=0077
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths={state}
RestrictAddressFamilies={families}
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
'''
    return f'''#!/sbin/openrc-run
description="Relay independent {role}"
supervisor="supervise-daemon"
command="{current}/run"
command_user="{user}:{user}"
directory="{state}"
umask="0077"
respawn_delay=2
# 0: keep restarting; a relay should recover from a crash loop on its own.
respawn_max=0
# Each relayed TCP connection holds two descriptors.
rc_ulimit="-n 1048576"
retry="TERM/30/KILL/5"
output_log="{log}"
error_log="{log}"
depend() {{
    need net
}}
'''


def logrotate_text(log, user):
    return f'''{log} {{
    size 10M
    rotate 5
    compress
    missingok
    notifempty
    copytruncate
    su {user} {user}
}}
'''
