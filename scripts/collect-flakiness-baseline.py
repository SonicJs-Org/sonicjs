#!/usr/bin/env python3
"""Collect runner identities only; no servers, test execution, or uploads.

Usage: python3 scripts/collect-flakiness-baseline.py /absolute/evidence/baseline
Requires installed locked dependencies and Node 22 on PATH. Evidence stays untracked.
"""
import collections
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
OUT = Path(sys.argv[1]).resolve()
OUT.mkdir(parents=True, exist_ok=True)
# Deliberately exclude inherited credentials, CI flags, URLs and reporter settings.
ENV = {'PATH': os.environ['PATH'], 'HOME': str(OUT), 'NO_COLOR': '1'}
files = subprocess.check_output(['git', 'ls-files'], cwd=ROOT, text=True).splitlines()
selected = [f for f in files if f.endswith(('.ts', '.js', '.mjs', '.cjs', '.tsx', '.jsx', '.sh', 'package.json'))
            or 'config' in f and ('vitest' in f or 'playwright' in f)
            or f == 'package-lock.json' or f.startswith('.github/workflows/') or f.startswith('scripts/lint-e2e')]
(OUT / 'source-hashes.json').write_text(json.dumps({f: hashlib.sha256((ROOT / f).read_bytes()).hexdigest()
                                                 for f in selected}, indent=2) + '\n')
summary = {}

def collect(name, cwd, command, kind):
    result = subprocess.run(command, cwd=ROOT / cwd, env=ENV, capture_output=True, text=True)
    (OUT / (name + '.stdout.json')).write_text(result.stdout)
    (OUT / (name + '.stderr.log')).write_text(result.stderr)
    record = {'cwd': cwd, 'command': command, 'exit': result.returncode}
    identities = []
    try:
        data = json.loads(result.stdout)
        if kind == 'playwright':
            def walk(suites, titles):
                for suite in suites:
                    path = titles + [suite['title']]
                    for spec in suite.get('specs', []):
                        for test in spec['tests']:
                            identities.append({'file': str((Path(data['config']['rootDir']) / spec['file']).relative_to(ROOT)), 'project': test['projectName'],
                                               'name': path[1:] + [spec['title']],
                                               'expectedStatus': test['expectedStatus'],
                                               'line': spec['line']})
                    walk(suite.get('suites', []), path)
            walk(data.get('suites', []), [])
            record['collectionErrors'] = data.get('errors', [])
        else:
            for test in data:
                file = Path(test['file'])
                identities.append({'file': str(file.relative_to(ROOT)) if file.is_absolute() else str(file),
                                   'project': test.get('projectName', ''), 'name': test['name']})
        counts = collections.Counter(json.dumps([x['file'], x['project'], x['name']], sort_keys=True) for x in identities)
        names = collections.Counter(json.dumps([x['project'], x['name']], sort_keys=True) for x in identities)
        record['duplicateFullNames'] = [{'name': json.loads(k), 'multiplicity': n} for k, n in names.items() if n > 1]
        record['expectedStatuses'] = dict(collections.Counter(x.get('expectedStatus', 'not exposed by Vitest list') for x in identities))
        record.update(total=len(identities), unique=len(counts), duplicateExcess=sum(n - 1 for n in counts.values()),
                      duplicates=[{'identity': json.loads(k), 'multiplicity': n} for k, n in counts.items() if n > 1])
        (OUT / (name + '.identities.json')).write_text(json.dumps(identities, indent=2) + '\n')
    except (ValueError, KeyError, TypeError) as error:
        record['parseError'] = str(error)
    summary[name] = record
    (OUT / 'collection-summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(name, json.dumps(record), flush=True)

for name, config in [('cms-e2e', 'playwright.config.ts'), ('cms-no-server', 'playwright-no-server.config.ts'),
                     ('cms-smoke', 'playwright.smoke.config.ts'), ('www-e2e', 'playwright.www.config.ts'),
                     ('runner-contracts', 'playwright.infrastructure.config.ts')]:
    collect(name, '.', ['node', str(ROOT / 'node_modules/@playwright/test/cli.js'), 'test',
                        '--config=tests/' + config, '--list', '--reporter=json'], 'playwright')
for name, cwd in [('core-unit', 'packages/core'), ('sdk-unit', 'packages/sdk'), ('root-unit', '.'), ('sample-unit-audit', 'my-sonicjs-app')]:
    collect(name, cwd, ['node', str(ROOT / 'node_modules/vitest/vitest.mjs'), 'list', '--json'], 'vitest')
