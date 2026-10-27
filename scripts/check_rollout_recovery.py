#!/usr/bin/env python3
"""Rollout recovery, revision identity and permission regressions (R95/R96).

Runs a real local controller; agent receipts are seeded in temporary SQLite.
"""
import argparse
import copy
from concurrent.futures import ThreadPoolExecutor
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location('fixture', args.source / 'scripts/check_subscriptions.py')
    f = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(f)
    results = {}

    def save(name, value):
        results[name] = value
        args.output.write_text(json.dumps(results, indent=2) + '\n')
        print(name + ': ' + json.dumps(value), flush=True)

    with tempfile.TemporaryDirectory(prefix='relay-rollout-regression-') as directory:
        root = Path(directory)
        password = root / 'password'
        password.write_text(f.PASSWORD)
        os.chmod(password, 0o600)
        process, origin = f.start(args.binary.resolve(), root / 'state', password)
        try:
            def req(path, data=None, token=None, method=None):
                return f.json_request(origin, '/api/v1/' + path, data, token, method)

            def ok(path, data=None, token=None, method=None):
                status, body = req(path, data, token, method)
                assert status == 200, (path, status, body)
                return body

            login = ok('auth/login', {'username': 'admin', 'password': f.PASSWORD})
            admin = login['token']
            owner = login['user']['id']
            body = {'tenant_id': None, 'name': 'Global v1', 'description': '',
                    'rule': f.plain_rule(owner)}
            template = ok('templates', body, admin)
            tid = template['id']
            body['name'] = 'Global v2'
            ok('templates/' + tid, body, admin, 'PUT')
            ok('users', {'username': 'tenant-operator', 'password': f.PASSWORD,
                         'role': 'tenant_admin', 'tenant_id': 'default'}, admin)
            tenant = ok('auth/login', {'username': 'tenant-operator', 'password': f.PASSWORD})['token']
            update_status, _ = req('templates/' + tid, body, tenant, 'PUT')
            rollback_status, _ = req(f'templates/{tid}/versions/1/rollback', {}, tenant, 'POST')
            versions = ok(f'templates/{tid}/versions', token=admin)
            assert update_status == 403 and rollback_status == 403
            assert max(v['version'] for v in versions) == 2
            assert next(v for v in versions if v['version'] == 2)['name'] == 'Global v2'

            own = copy.deepcopy(body)
            own.update(tenant_id='default', name='Own v1')
            own_template = ok('templates', own, tenant)
            own['name'] = 'Own v2'
            ok('templates/' + own_template['id'], own, tenant, 'PUT')
            restored = ok(f"templates/{own_template['id']}/versions/1/rollback", {}, tenant)
            assert restored['name'] == 'Own v1' and restored['version'] == 3

            history_body = copy.deepcopy(body)
            history_body['name'] = 'Scope history global'
            history = ok('templates', history_body, admin)
            history_body['tenant_id'] = 'default'
            ok('templates/' + history['id'], history_body, admin, 'PUT')
            history_status, _ = req(f"templates/{history['id']}/versions/1/rollback", {}, tenant)
            assert history_status == 403
            save('R95_01_rollback_permissions', {'passed': True, 'global_update_status': update_status,
                 'global_rollback_status': rollback_status, 'global_version_after_denial': 2,
                 'own_template_rollback_version': 3, 'historical_global_scope_rollback_status': history_status})

            def node(name):
                n = ok('nodes', {'name': name, 'lease_policy': None, 'settings': {}}, admin)['node']
                cfg = ok(f"nodes/{n['id']}/config", {'expected_revision': 0, 'rules': []}, admin, 'PUT')
                return n['id'], cfg['revision']

            def config(node_id):
                return ok(f'nodes/{node_id}/config', token=admin)

            def target(node_id, revision, port):
                return {'node_id': node_id, 'expected_revision': revision, 'name': 'review rollout',
                        'listen': f'127.0.0.1:{port}'}

            def report_health(node_id, revision, rule_id, address, checked=None):
                now = int(time.time() * 1000)
                health = {
                    'probe_kind': 'tcp_connect', 'rule_id': rule_id, 'target_index': 0,
                    'listen_port': 19003, 'protocol': 'tcp', 'target_address': address,
                    'status': 'healthy', 'eligible': True, 'selection_reason': 'local fixture',
                    'sample_age_ms': 10, 'max_age_ms': 30000,
                    'checked_at_ms': now if checked is None else checked,
                    'latency_ewma_us': 1000, 'window_checks': 1, 'window_failures': 0,
                    'jitter_us': None, 'consecutive_successes': 1, 'consecutive_failures': 0,
                    'completed_checks': 1, 'successful_checks': 1, 'last_error': None,
                    'probe_sent_bytes': 1, 'probe_received_bytes': 1, 'priority': 0,
                    'active_sessions': 0, 'max_sessions': None}
                with sqlite3.connect(root / 'state/controller.sqlite') as db:
                    raw = db.execute('SELECT stats_json FROM nodes WHERE id=?', (node_id,)).fetchone()[0]
                    stats = json.loads(raw)
                    for field in ['active_tcp', 'active_udp', 'accepted_tcp', 'rejected_connections',
                                  'failed_connections', 'dropped_datagrams', 'forwarded_upload_bytes',
                                  'forwarded_download_bytes']:
                        stats.setdefault(field, 0)
                    stats['target_health'] = [health]
                    db.execute('UPDATE nodes SET stats_json=?,applied_revision=?,last_seen_ms=?,apply_error=NULL WHERE id=?',
                               (json.dumps(stats), revision, now, node_id))

            def wait_config(node_id, revision):
                deadline = time.monotonic() + 2
                while time.monotonic() < deadline:
                    cfg = config(node_id)
                    if cfg['revision'] >= revision:
                        return cfg
                    time.sleep(.02)
                raise AssertionError(('configuration not published', node_id, revision))

            def acknowledge(node_id, cfg):
                r = cfg['rules'][-1]
                report_health(node_id, cfg['revision'], r['id'], r['targets'][0]['address'])

            a, av = node('rollback-retry-A')
            b, bv = node('rollback-retry-B')
            first = ok(f'templates/{tid}/rollout', {'batch_size': 1, 'rollback_on_failure': True,
                       'targets': [target(a, av, 19001), target(b, bv + 99, 19002)]}, admin)
            assert first['aborted'] and first['rolled_back'] == 1
            retried = ok(f"templates/{tid}/rollouts/{first['id']}/retry", {}, admin)
            assert not retried['aborted'] and retried['applied'] == 2
            assert len(config(a)['rules']) == len(config(b)['rules']) == 1
            save('R95_05_rolled_back_nodes_retried', {'passed': True, 'retry_applied': 2,
                 'A_rules': 1, 'B_rules': 1})

            c, cv = node('gate-failed-canary-C')
            d, dv = node('gate-next-batch-D')
            for n in [c, d]:
                report_health(n, 1, 'unrelated-old-rule', '127.0.0.1:9', checked=1)
            failed = ok(f'templates/{tid}/rollout', {'batch_size': 1, 'require_target_health': True,
                        'wait_for_apply_ms': 250,
                        'targets': [target(c, cv, 19003), target(d, dv, 19004)]}, admin)
            assert failed['aborted'] and failed['batches'] == 1
            assert config(c)['revision'] == 2 and config(d)['revision'] == 1
            save('R95_04_stale_unrelated_health_rejected', {'passed': True, 'aborted': True,
                 'batches_published': 1, 'unattempted_node_revision': 1, 'gate_error': failed['gate_error']})

            # Restart before retry, preserving the original failed canary.
            f.stop(process)
            process, origin = f.start(args.binary.resolve(), root / 'state', password)
            admin = ok('auth/login', {'username': 'admin', 'password': f.PASSWORD})['token']
            blocked = ok(f"templates/{tid}/rollouts/{failed['id']}/retry", {}, admin)
            assert blocked['aborted'] and blocked['results'][0]['reused']
            assert not blocked['results'][0]['acknowledged']
            assert config(c)['revision'] == 2 and config(d)['revision'] == 1
            assert blocked['results'][0]['rule_id'] == failed['results'][0]['rule_id']
            with sqlite3.connect(root / 'state/controller.sqlite') as db:
                db.execute('UPDATE nodes SET apply_error=? WHERE id=?', ('fixture listener activation failed', c))
            rejected = ok(f"templates/{tid}/rollouts/{failed['id']}/retry", {}, admin)
            assert rejected['aborted'] and not rejected['results'][0]['completed']
            assert config(c)['revision'] == 2 and config(d)['revision'] == 1
            acknowledge(c, config(c))
            with ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(ok, f"templates/{tid}/rollouts/{failed['id']}/retry", {}, admin)
                published_d = wait_config(d, 2)
                acknowledge(d, published_d)
                retry = future.result(timeout=5)
            assert not retry['aborted'] and len(retry['results']) == 2
            assert all(r['completed'] and r['acknowledged'] and r['healthy'] for r in retry['results'])
            replay = ok(f"templates/{tid}/rollouts/{failed['id']}/retry", {}, admin)
            assert replay['id'] == retry['id']
            assert config(c)['revision'] == config(d)['revision'] == 2
            assert len(config(c)['rules']) == len(config(d)['rules']) == 1
            save('R96_01_retry_rechecks_original_canary', {'passed': True,
                 'controller_restarted_before_retry': True, 'unacknowledged_retry_aborted': True,
                 'application_error_retry_aborted': True,
                 'next_batch_revision_while_canary_unacknowledged': 1,
                 'completed_nodes_after_receipts': 2, 'duplicate_rules': 0,
                 'completed_retry_replays_same_report': True,
                 'fixture': 'stored telemetry in local temporary SQLite; no real agents'})

            e, ev = node('superseded-canary-E')
            g, gv = node('superseded-next-batch-F')
            with ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(ok, f'templates/{tid}/rollout', {
                    'batch_size': 1, 'require_target_health': True, 'wait_for_apply_ms': 2000,
                    'rollback_on_failure': True,
                    'targets': [target(e, ev, 19005), target(g, gv, 19006)]}, admin)
                published_e = wait_config(e, 2)
                changed_rules = copy.deepcopy(published_e['rules'])
                original_target = changed_rules[-1]['targets'][0]['address']
                changed_rules[-1]['targets'][0]['address'] = '127.0.0.1:19'
                replacement = ok(f'nodes/{e}/config', {'expected_revision': 2, 'rules': changed_rules}, admin, 'PUT')
                assert replacement['revision'] == 3
                acknowledge(e, replacement)
                superseded = future.result(timeout=5)
            assert superseded['aborted'] and superseded['batches'] == 1
            assert 'superseded' in superseded['gate_error']
            assert config(g)['revision'] == 1
            assert superseded['results'][0]['revision'] == 2
            assert superseded['rollback_failed'] == 1 and superseded['rolled_back'] == 0
            retry_conflict = ok(f"templates/{tid}/rollouts/{superseded['id']}/retry", {}, admin)
            assert retry_conflict['aborted']
            assert 'superseded' in retry_conflict['results'][0]['error']
            assert config(e)['revision'] == 3 and len(config(e)['rules']) == 1
            assert config(g)['revision'] == 1
            save('R96_02_later_configuration_cannot_qualify_canary', {'passed': True,
                 'rollout_canary_revision': 2, 'actual_applied_canary_revision': 3,
                 'intended_target': original_target, 'actual_canary_target': '127.0.0.1:19',
                 'same_rule_id': replacement['rules'][-1]['id'] == published_e['rules'][-1]['id'],
                 'aborted': superseded['aborted'], 'batches_published': superseded['batches'],
                 'unattempted_node_revision': config(g)['revision'],
                 'rollback_failed_safely': True, 'retry_preserved_concurrent_edit_without_duplicate': True,
                 'fixture': 'configuration mutation via HTTP; local seeded telemetry for revised rules'})
        finally:
            f.stop(process)


if __name__ == '__main__':
    main()
