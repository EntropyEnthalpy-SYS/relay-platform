import copy
import gzip
import io
import json
import os
from pathlib import Path
import shutil
import socket
import sys
import tarfile
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from deployment import bundle, install
from deployment.bundle import DeployError
from deployment.host import Services, inventory


class Interrupted(Exception):
    pass


class DeploymentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='relay-deploy-tests-')
        cls.scratch = Path(cls.temp.name).resolve()
        cls.binary = Path(os.environ.get('RELAY_TEST_BINARY', str(Path(__file__).resolve().parents[2] / 'target/debug/relay')))
        cls.info = bundle.build_info(cls.binary)
        cls.keys = bundle.keygen(cls.scratch / 'signer')
        cls.other = bundle.keygen(cls.scratch / 'other-signer')
        cls.licenses = cls.scratch / 'THIRD_PARTY.md'
        cls.licenses.write_text('Test component list; not a production SBOM.\n')
        cls.archives = []
        cls.verified = []
        for index in (1, 2):
            path = cls.scratch / f'release-{index}.tar.gz'
            bundle.pack(cls.binary, cls.licenses, cls.keys['private_key'], path, str(index) * 40)
            cls.archives.append(path)
            cls.verified.append(bundle.verify(path, cls.keys['public_key']))

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='relay-stage-', dir=self.scratch)
        self.root = Path(self.directory.name)
        self.layout = install.Layout(self.root, 'controller', 'systemd')
        with socket.socket() as reserve:
            reserve.bind(('127.0.0.1', 0))
            self.default_settings = {'listen': '127.0.0.1:' + str(reserve.getsockname()[1])}

    def tearDown(self):
        self.directory.cleanup()

    def deploy(self, revision=0, config=None, **kwargs):
        return install.deploy(self.layout, self.verified[revision], config or self.default_settings, **kwargs)

    def break_at(self, boundary):
        def fail(at):
            if at == boundary:
                raise Interrupted(boundary)
        return fail

    def raw_archive(self, changes=None, extra=None):
        values = dict(self.verified[0]['files'])
        values.update(changes or {})
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode='w:gz', format=tarfile.USTAR_FORMAT) as archive:
            for name, value in values.items():
                entry = tarfile.TarInfo(name); entry.size = len(value)
                archive.addfile(entry, io.BytesIO(value))
            if extra:
                archive.addfile(*extra)
        path = self.root / 'bad.tar.gz'
        path.write_bytes(stream.getvalue())
        return path

    def test_signed_manifest_and_payload_match_without_executing_payload(self):
        with patch('subprocess.run', wraps=bundle.subprocess.run) as run:
            result = bundle.verify(self.archives[0], self.keys['public_key'])
        self.assertEqual(result['manifest']['build'], self.info)
        self.assertTrue(all('openssl' in str(call.args[0][0]) for call in run.call_args_list))
        self.assertEqual(os.stat(self.keys['private_key']).st_mode & 0o777, 0o600)

    def test_wrong_signer_and_tampered_binary_are_rejected_before_install(self):
        with self.assertRaises(DeployError):
            bundle.verify(self.archives[0], self.other['public_key'])
        original = self.verified[0]['files']['relay']
        altered = original[:-1] + bytes([original[-1] ^ 1])
        with self.assertRaises(DeployError):
            bundle.verify(self.raw_archive({'relay': altered}), self.keys['public_key'])
        self.assertFalse(self.layout.prefix.exists())

    def test_modified_manifest_rejects_signature_even_with_matching_payload(self):
        manifest = copy.deepcopy(self.verified[0]['manifest'])
        manifest['source_revision'] = '3' * 40
        with self.assertRaises(DeployError):
            bundle.verify(self.raw_archive({'manifest.json': bundle.encoded(manifest)}), self.keys['public_key'])

    def test_archive_traversal_symlink_duplicate_and_oversized_headers_rejected(self):
        for name, kind in [('../outside', tarfile.REGTYPE), ('relay', tarfile.SYMTYPE), ('manifest.json', tarfile.REGTYPE)]:
            with self.subTest(name=name, kind=kind):
                entry = tarfile.TarInfo(name); entry.type = kind; entry.linkname = '/etc/passwd'
                with self.assertRaises(DeployError):
                    bundle.verify(self.raw_archive(extra=(entry, io.BytesIO())), self.keys['public_key'])
        entry = tarfile.TarInfo('manifest.json'); entry.size = 10**9
        path = self.root / 'bomb.tar.gz'
        path.write_bytes(gzip.compress(entry.tobuf() + b'\0' * 1024))
        with self.assertRaises(DeployError):
            bundle.verify(path, self.keys['public_key'])

    def test_pax_metadata_is_rejected_before_consuming_claimed_body(self):
        entry = tarfile.TarInfo('metadata'); entry.type = tarfile.XHDTYPE; entry.size = 10**9
        path = self.root / 'pax.tar.gz'; path.write_bytes(gzip.compress(entry.tobuf() + b'\0' * 1024))
        with self.assertRaises(DeployError):
            bundle.verify(path, self.keys['public_key'])
        fifo = self.root / 'not-a-file'; os.mkfifo(fifo)
        source = 'import sys;sys.path.insert(0,sys.argv[1]);from deployment import bundle;bundle.verify(sys.argv[2],sys.argv[3])'
        rejected = bundle.subprocess.run([sys.executable, '-c', source, str(Path(__file__).resolve().parents[1]), str(fifo), self.keys['public_key']], capture_output=True, timeout=3)
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn(b'bounded regular file', rejected.stderr)

    def test_target_header_is_independent_of_manifest_labels(self):
        data = bytearray(64); data[:6] = b'\x7fELF\x02\x01'; data[16:18] = (3).to_bytes(2, 'little'); data[18:20] = (62).to_bytes(2, 'little')
        bundle.target_header(data, {'os': 'linux', 'arch': 'x86_64'})
        with self.assertRaises(DeployError):
            bundle.target_header(data, {'os': 'linux', 'arch': 'aarch64'})
        with self.assertRaises(DeployError):
            bundle.target_header(b'#!/bin/sh\n' + b'a' * 128, {'os': 'linux', 'arch': 'x86_64'})

    def test_foreign_target_preflight_does_not_touch_installation(self):
        other = copy.deepcopy(self.verified[0]); other['manifest']['build']['arch'] = 'aarch64' if self.info['arch'] == 'x86_64' else 'x86_64'
        report = install.preflight(self.layout, other)
        self.assertFalse(report['ready']); self.assertFalse(self.layout.prefix.exists())
        with self.assertRaises(DeployError):
            install.deploy(self.layout, other, {})

    def test_occupied_controller_port_is_rejected_before_writing_installation(self):
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0)); listener.listen()
            config = {'listen': '127.0.0.1:' + str(listener.getsockname()[1])}
            report = install.preflight(self.layout, self.verified[0], config)
            self.assertFalse(report['ready']); self.assertFalse(report['controller_listener_bindable_now'])
            with self.assertRaises(DeployError):
                self.deploy(config=config)
        self.assertFalse(self.layout.prefix.exists())

    def test_world_writable_managed_parent_is_rejected_without_adopting_files(self):
        folder = self.root / 'opt'; folder.mkdir(); folder.chmod(0o777)
        with self.assertRaises(DeployError):
            self.deploy()
        self.assertFalse(self.layout.prefix.exists())

    def test_native_installation_is_refused_on_macos_and_staging_has_no_service_calls(self):
        fake = {**inventory(), 'os': 'macos', 'system_install_supported': False, 'service_manager': None}
        with patch('deployment.install.inventory', return_value=fake):
            self.assertFalse(install.preflight(install.Layout('/', 'controller', 'systemd'))['ready'])
        with self.assertRaises(DeployError):
            Services('systemd', staged=True).action('controller', 'start')

    def test_preexisting_foreign_state_and_service_file_are_not_adopted(self):
        self.layout.state.mkdir(parents=True); (self.layout.state / 'keep').write_text('foreign')
        with self.assertRaises(DeployError):
            self.deploy()
        self.assertEqual((self.layout.state / 'keep').read_text(), 'foreign')
        shutil.rmtree(self.layout.state)
        service = self.layout.service_path('systemd'); service.parent.mkdir(parents=True); service.write_text('foreign')
        with self.assertRaises(DeployError):
            self.deploy()
        self.assertEqual(service.read_text(), 'foreign')

    def test_symlink_ancestors_and_unowned_prefix_are_rejected(self):
        outside = self.root / 'outside'; outside.mkdir()
        (self.root / 'opt').symlink_to(outside)
        with self.assertRaises(DeployError):
            self.deploy()
        self.assertEqual(list(outside.iterdir()), [])
        (self.root / 'opt').unlink(); self.layout.prefix.mkdir(parents=True)
        with self.assertRaises((DeployError, FileNotFoundError)):
            self.deploy()

    def test_deploy_upgrade_and_rollback_preserve_every_runtime_byte(self):
        first = self.deploy()
        private = self.layout.state / 'do-not-rollback.sqlite'; private.write_bytes(b'newly-admitted-usage')
        with socket.socket() as reserve:
            reserve.bind(('127.0.0.1', 0))
            changed = {'listen': '127.0.0.1:' + str(reserve.getsockname()[1])}
        second = self.deploy(1, changed)
        self.assertNotEqual(first['current'], second['current'])
        self.assertEqual(second['previous'], first['current'])
        result = install.rollback(self.layout)
        self.assertEqual(result['current'], first['current'])
        self.assertFalse(result['runtime_state_restored'])
        self.assertEqual(private.read_bytes(), b'newly-admitted-usage')
        self.assertFalse(self.deploy()['changed'])

    def test_concurrent_installer_lock_prevents_second_writer(self):
        self.deploy()
        with self.layout.lock():
            with self.assertRaises(DeployError):
                self.deploy(1)

    def test_restrictive_invoking_umask_still_produces_readable_service_programs(self):
        previous = os.umask(0o077)
        try:
            result = self.deploy()
        finally:
            os.umask(previous)
        folder = self.layout.generations / result['current']
        for directory in (self.layout.prefix, self.layout.base, self.layout.generations, folder):
            self.assertEqual(directory.stat().st_mode & 0o777, 0o755)
        for program in (folder / 'relay', folder / 'run'):
            self.assertEqual(program.stat().st_mode & 0o777, 0o755)
        self.assertEqual(self.layout.state.stat().st_mode & 0o777, 0o700)

    def test_interrupted_first_provision_retries_only_original_intent(self):
        for boundary in ('provision_intent_durable', 'service_file_durable'):
            with self.subTest(boundary=boundary):
                self.layout = install.Layout(self.root / boundary, 'controller', 'systemd')
                with self.assertRaises(Interrupted):
                    self.deploy(checkpoint=self.break_at(boundary))
                with self.assertRaises(DeployError):
                    self.deploy(1)
                result = self.deploy()
                self.assertTrue(result['installed']); self.assertFalse(result['provisioning_pending'])

    def test_crashes_at_each_selection_boundary_recover_exact_target_once(self):
        for boundary in ('intent_durable', 'selection_durable', 'receipt_durable'):
            with self.subTest(boundary=boundary):
                self.layout = install.Layout(self.root / boundary, 'controller', 'systemd')
                first = self.deploy()
                (self.layout.state / 'usage').write_bytes(b'keep')
                with self.assertRaises(Interrupted):
                    self.deploy(1, checkpoint=self.break_at(boundary))
                self.assertIsNotNone(self.layout.status()['pending'])
                with self.assertRaises(DeployError):
                    install.rollback(self.layout)
                result = install.recover(self.layout)
                self.assertEqual(result['previous'], first['current'])
                self.assertNotEqual(result['current'], first['current'])
                self.assertEqual((self.layout.state / 'usage').read_bytes(), b'keep')
                self.assertIsNone(result['pending'])

    def test_upgrades_install_service_files_from_a_newer_installer_even_if_interrupted(self):
        original = install.service_text
        def newer(suffix):
            return patch.object(install, 'service_text', lambda *a: original(*a) + suffix)
        for boundary in ('intent_durable', 'selection_durable'):
            with self.subTest(boundary=boundary):
                self.layout = install.Layout(self.root / boundary, 'controller', 'systemd')
                first = self.deploy()
                service = self.layout.service_path('systemd')
                with newer('# v2\n'):
                    with self.assertRaises(Interrupted):
                        self.deploy(1, checkpoint=self.break_at(boundary))
                    result = install.recover(self.layout)
                    self.assertNotEqual(result['current'], first['current'])
                    self.assertTrue(service.read_text().endswith('# v2\n'))
                    self.assertEqual(service.stat().st_mode & 0o777, 0o644)
                    self.assertFalse(self.deploy(1)['changed'])
                # Same program and settings: only the service file changes.
                with newer('# v3\n'):
                    again = self.deploy(1)
                self.assertTrue(again['changed'])
                self.assertEqual(again['current'], result['current'])
                self.assertTrue(service.read_text().endswith('# v3\n'))

    def test_unexpected_current_link_and_modified_service_prevent_mutation(self):
        self.deploy()
        service = self.layout.service_path('systemd'); original = service.read_bytes(); service.write_bytes(original + b'# user edit\n')
        with self.assertRaises(DeployError):
            self.deploy(1)
        with self.assertRaises(DeployError):
            install.remove(self.layout)
        service.write_bytes(original)
        self.layout.current.unlink(); self.layout.current.symlink_to('/usr/bin')
        with self.assertRaises(DeployError):
            install.remove(self.layout)
        self.assertTrue(self.layout.state.exists())

    def test_hard_linked_and_group_writable_managed_files_rejected(self):
        self.deploy()
        service = self.layout.service_path('systemd')
        os.link(service, self.root / 'outside-link')
        with self.assertRaises(DeployError):
            self.deploy(1)
        (self.root / 'outside-link').unlink(); service.chmod(0o664)
        with self.assertRaises(DeployError):
            install.remove(self.layout)

    def test_incompatible_contract_rejects_upgrade_before_pointer_change(self):
        first = self.deploy(); other = copy.deepcopy(self.verified[1]); other['manifest']['build']['state_contract']['controller'] += 1
        with self.assertRaisesRegex(DeployError, 'incompatible state contract'):
            install.deploy(self.layout, other, self.default_settings)
        self.assertEqual(self.layout.selected(), first['current'])

    def test_agent_secret_permissions_identity_guard_and_private_key_rejection(self):
        self.layout = install.Layout(self.root, 'agent', 'systemd')
        token = self.root / 'token.secret'; token.write_text('a' * 64)
        ca = self.root / 'panel-ca.pem'; ca.write_text('-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n')
        config = {'controller': 'https://relay.example.test', 'node_id': 'node-one'}
        result = self.deploy(config=config, enrollment=token, ca=ca)
        installed = self.layout.config / 'enrollment.secret'
        self.assertEqual(installed.stat().st_mode & 0o777, 0o600)
        # Without netlink the agent cannot list local addresses and rejects
        # every configuration (seen under real systemd on Debian 13).
        families = next(line for line in self.layout.service_path('systemd').read_text().splitlines()
                        if line.startswith('RestrictAddressFamilies='))
        self.assertIn('AF_NETLINK', families.split('=', 1)[1].split())
        # Each relayed TCP connection holds two descriptors; 65536 ran out
        # near 32k connections.
        limit = next(line for line in self.layout.service_path('systemd').read_text().splitlines()
                     if line.startswith('LimitNOFILE='))
        self.assertGreaterEqual(int(limit.split('=', 1)[1]), 1 << 20)
        self.assertNotIn('a' * 64, json.dumps(result))
        with self.assertRaises(DeployError):
            self.deploy(1, config={**config, 'node_id': 'another'})
        with self.assertRaises(DeployError):
            self.deploy(1, config=config, enrollment=token)
        # An upgrade without --ca-certificate keeps trusting the controller CA
        # (it was silently dropped once, cutting a VPS agent off its panel).
        upgraded = self.deploy(1, config=config)
        self.assertNotEqual(upgraded['current'], result['current'])
        folder = self.layout.generations / upgraded['current']
        self.assertEqual((folder / 'ca.pem').read_bytes(), ca.read_bytes())
        self.assertIn('--ca-certificate', (folder / 'run').read_text())
        key = self.root / 'ca.pem'; key.write_text('-----BEGIN CERTIFICATE-----\n-----BEGIN PRIVATE KEY-----')
        with self.assertRaises(DeployError):
            self.deploy(1, config=config, ca=key)

    def test_openrc_service_and_rotation_files_have_owned_lifecycle_without_host_actions(self):
        self.layout = install.Layout(self.root, 'controller', 'openrc')
        result = self.deploy()
        bundle.subprocess.run(['/bin/sh', '-n', self.layout.service_path('openrc')], check=True)
        self.assertTrue(self.layout.rotation_path().is_file())
        self.assertEqual(result['service_state'], 'staged')
        removed = install.remove(self.layout)
        self.assertTrue(removed['removed']); self.assertTrue(self.layout.state.is_dir())
        self.assertFalse(self.layout.rotation_path().exists())
        self.assertFalse(self.layout.service_path('openrc').exists())

    def test_removal_refuses_untracked_generation_files_and_preserves_foreign_data(self):
        first = self.deploy(); extra = self.layout.generations / first['current'] / 'user-notes'
        extra.write_text('keep this')
        with self.assertRaises(DeployError):
            install.remove(self.layout)
        self.assertEqual(extra.read_text(), 'keep this')
        self.assertTrue(self.layout.current.is_symlink())

    def test_reinstall_resumes_retained_owned_state_without_adopting_foreign_service_files(self):
        self.deploy()
        data = self.layout.state / 'controller.sqlite'; data.write_bytes(b'latest-live-state')
        install.remove(self.layout)
        service = self.layout.service_path('systemd'); service.write_text('foreign replacement')
        with self.assertRaises(DeployError):
            self.deploy(1)
        self.assertEqual(service.read_text(), 'foreign replacement'); service.unlink()
        with self.assertRaises(Interrupted):
            self.deploy(1, checkpoint=self.break_at('service_file_durable'))
        restored = self.deploy(1)
        self.assertTrue(restored['installed']); self.assertFalse(restored['removed'])
        self.assertEqual(data.read_bytes(), b'latest-live-state')

    def test_openrc_enable_disable_are_idempotent_for_the_managed_runlevel(self):
        services = Services('openrc')
        with patch.object(services, '_native'), patch('deployment.host.run', return_value=SimpleNamespace(stdout=b'')) as run:
            services.action('controller', 'disable')
            self.assertEqual(run.call_count, 1)
            services.action('controller', 'enable')
            self.assertEqual(run.call_count, 3)
        with patch.object(services, '_native'), patch('deployment.host.run', return_value=SimpleNamespace(stdout=b' relay-platform-controller | default\n')) as run:
            services.action('controller', 'enable')
            self.assertEqual(run.call_count, 1)

    def test_removal_crashes_resume_without_deleting_state_or_other_role(self):
        for boundary in ('removal_intent_durable', 'service_files_removed', 'generation_file_removed'):
            with self.subTest(boundary=boundary):
                self.layout = install.Layout(self.root / boundary, 'controller', 'systemd')
                self.deploy(); self.deploy(1)
                data = self.layout.state / 'controller.sqlite'; data.write_bytes(b'persist-identity-and-usage')
                other = self.layout.prefix / 'roles' / 'agent'; other.mkdir(); (other / 'foreign').write_text('keep')
                with self.assertRaises(Interrupted):
                    install.remove(self.layout, checkpoint=self.break_at(boundary))
                self.assertTrue(self.layout.status()['removal_pending'])
                with self.assertRaises(DeployError):
                    install.rollback(self.layout)
                result = install.recover(self.layout)
                self.assertTrue(result['removed']); self.assertFalse(result['installed'])
                self.assertEqual(data.read_bytes(), b'persist-identity-and-usage')
                self.assertEqual((other / 'foreign').read_text(), 'keep')

    def test_pending_record_cannot_redirect_removal_outside_managed_service_files(self):
        self.deploy()
        with self.assertRaises(Interrupted):
            install.remove(self.layout, checkpoint=self.break_at('removal_intent_durable'))
        file = self.layout.base / 'removing.json'; record = json.loads(file.read_text())
        victim = self.root / 'keep'; victim.write_text('untouched')
        record['index']['managed_files']['/keep'] = bundle.sha(b'untouched')
        install.atomic(file, bundle.encoded(record))
        with self.assertRaises(DeployError):
            install.recover(self.layout)
        self.assertEqual(victim.read_text(), 'untouched')

    def test_invalid_settings_cannot_turn_into_shell_options_or_remote_plaintext(self):
        for role, config in [('controller', {'listen': '0.0.0.0:8080'}),
                             ('agent', {'controller': 'http://example.com', 'node_id': 'one'}),
                             ('agent', {'controller': 'https://relay.test', 'node_id': 'one; rm -rf /'}),
                             ('controller', {'listen': '127.0.0.1:80'})]:
            with self.subTest(config=config), self.assertRaises(DeployError):
                install.settings(role, config)


if __name__ == '__main__':
    unittest.main()
