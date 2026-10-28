#!/usr/bin/env python3
"""Generate a CycloneDX 1.6 inventory from Cargo.lock-resolved metadata.

Includes all resolved target/platform dependencies. This is an inventory, not
an advisory scan or proof that a dependency is reachable in a particular build.
"""
import argparse
import datetime
import json
import os
from pathlib import Path
import subprocess
from urllib.parse import quote


def generate(repo):
    metadata = json.loads(subprocess.check_output(
        ['cargo', 'metadata', '--locked', '--format-version', '1'], cwd=repo))
    packages = {p['id']: p for p in metadata['packages']}
    members = set(metadata['workspace_members'])
    root_id = next(p for p in metadata['workspace_members'] if packages[p]['name'] == 'relay-platform')
    purl = lambda p: f"pkg:cargo/{quote(p['name'], safe='')}@{quote(p['version'], safe='')}"
    ref = {k: purl(v) for k, v in packages.items()}
    try:
        commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=repo, text=True).strip()
        dirty = bool(subprocess.check_output(['git', 'status', '--porcelain'], cwd=repo))
        epoch = int(os.environ.get('SOURCE_DATE_EPOCH') or subprocess.check_output(
            ['git', 'show', '-s', '--format=%ct', 'HEAD'], cwd=repo, text=True))
    except (subprocess.CalledProcessError, ValueError):
        commit, dirty, epoch = 'unknown', True, int(os.environ.get('SOURCE_DATE_EPOCH', '0'))
    def component(p):
        value = {'type': 'application' if p['id'] in members else 'library',
                 'bom-ref': ref[p['id']], 'name': p['name'], 'version': p['version'], 'purl': ref[p['id']]}
        if p.get('license'):
            value['licenses'] = [{'expression': p['license']}]
        elif p.get('license_file'):
            value['licenses'] = [{'license': {'name': 'See upstream license file'}}]
        links = [{'type': kind, 'url': p[key]} for key, kind in [('repository', 'vcs'), ('homepage', 'website')]
                 if p.get(key)]
        if links:
            value['externalReferences'] = links
        return value
    main = component(packages[root_id])
    main['properties'] = [{'name': 'relay:source:git_commit', 'value': commit},
                          {'name': 'relay:source:dirty', 'value': str(dirty).lower()},
                          {'name': 'relay:inventory:scope', 'value': 'all Cargo resolved target/platform dependencies'}]
    dependencies = [{'ref': ref[n['id']], 'dependsOn': sorted(set(ref[d['pkg']] for d in n['deps']))}
                    for n in metadata['resolve']['nodes']]
    bom = {'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'version': 1,
           'metadata': {'timestamp': datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc).isoformat().replace('+00:00', 'Z'), 'component': main},
           'components': sorted([component(p) for k, p in packages.items() if k != root_id], key=lambda x: x['bom-ref']),
           'dependencies': sorted(dependencies, key=lambda x: x['ref'])}
    rows = [p for k,p in packages.items() if k not in members]
    rows.sort(key=lambda p: (p['name'], p['version']))
    report = '# Third-party dependencies\n\nGenerated from the locked Cargo resolution by `scripts/generate_sbom.py`. Includes optional and non-host platform packages. The corresponding CycloneDX document records dependency edges; neither file is a vulnerability audit.\n\n| Package | Version | Declared license | Upstream |\n|---|---|---|---|\n'
    for p in rows:
        url = p.get('repository') or p.get('homepage') or f"https://crates.io/crates/{p['name']}/{p['version']}"
        report += f"| {p['name']} | {p['version']} | {p.get('license') or 'See upstream'} | [Source]({url}) |\n"
    return bom, report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--license-report', type=Path)
    args = parser.parse_args()
    bom, report = generate(args.repo.resolve())
    args.output.write_text(json.dumps(bom, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    if args.license_report:
        args.license_report.write_text(report, encoding='utf-8')
    print(json.dumps({'components': len(bom['components']) + 1, 'dependency_nodes': len(bom['dependencies']), 'format': 'CycloneDX 1.6', 'output': str(args.output)}))


if __name__ == '__main__':
    main()
