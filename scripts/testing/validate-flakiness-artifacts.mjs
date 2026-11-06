import { Schema } from '@flakiness/flakiness-report';
import { fromBufferPromise } from 'yauzl';
import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { lstat, mkdir, mkdtemp, writeFile, rm } from 'node:fs/promises';
import { resolve, join, dirname, relative, sep, parse } from 'node:path';
import { createHash } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';
import { crc32 } from 'node:zlib';

/**
 * Pure provenance policy; artifact intake follows later in this module.
 * Neither entry point authenticates caller-supplied trusted context.
 * Input MUST come from a trusted GitHub API/event adapter with complete job/step
 * metadata for the exact run attempt. Never populate it from producer artifacts.
 * The adapter must establish job keys and preserve the original run's immutable
 * PR-head snapshot; current PR data alone cannot establish historical checkout.
 * Live API acquisition/authentication belongs to Task6.
 */
const repository = 'SonicJs-Org/sonicjs';
/** @type {ReadonlyArray<readonly ['core-unit' | 'cms-e2e', string]>} */
const suiteSteps = [
  ['core-unit', 'Run unit tests with coverage'],
  ['cms-e2e', 'Run full E2E regression suite'],
];

/** @param {unknown} condition @param {string} message @returns {asserts condition} */
function requireValid(condition, message) {
  if (!condition) throw new Error(`Non-publishable producer: ${message}`);
}

/** @param {unknown} value @returns {value is number} */
function validId(value) {
  return typeof value === 'number' && Number.isSafeInteger(value) && value > 0;
}

/** @param {unknown} value @returns {value is string} */
function validSha(value) {
  return typeof value === 'string' && /^[a-fA-F0-9]{40}$/.test(value);
}

/**
 * @param {import('./validate-flakiness-artifacts.mjs').ProducerProvenanceInput} input
 * @returns {import('./validate-flakiness-artifacts.mjs').ValidatedProducerProvenance}
 */
export function validateProducerProvenance(input) {
  const { trigger, producer: p, jobs } = input;
  requireValid(trigger.repository === repository && p.repository === repository, 'repository mismatch');
  requireValid([trigger.runId, trigger.runAttempt, p.runId, p.runAttempt].every(validId), 'invalid run identity');
  requireValid(trigger.runId === p.runId && trigger.runAttempt === p.runAttempt, 'run/attempt mismatch');
  requireValid(p.workflowId === 207092903 && p.workflowPath === '.github/workflows/pr-tests.yml'
    && p.workflowName === 'PR Tests', 'workflow mismatch');
  requireValid(p.status === 'completed' && (p.conclusion === 'success' || p.conclusion === 'failure'), 'run not publishable');
  requireValid((p.event === 'push' || p.event === 'pull_request_target'), 'unsupported event');
  requireValid(validSha(p.headSha), 'invalid producer SHA');
  requireValid(typeof p.headBranch === 'string' && p.headBranch.length > 0, 'missing branch');
  requireValid(p.event !== 'push' || ['main', 'v3', 'test/e2e-infrastructure-hardening'].includes(p.headBranch), 'forbidden push branch');
  requireValid(Array.isArray(jobs) && jobs.length === 1 && jobs[0]?.key === 'test', 'missing, duplicate or unknown job');
  const job = jobs[0];
  requireValid(job, 'missing job');
  requireValid(validId(job.id) && job.runId === p.runId && job.runAttempt === p.runAttempt
    && job.status === 'completed', 'job binding/status mismatch');
  requireValid(Array.isArray(job.steps), 'missing steps');
  /** @type {Set<number>} */ const numbers = new Set();
  /** @type {Set<string>} */ const names = new Set();
  for (const step of job.steps) {
    requireValid(validId(step.number) && typeof step.name === 'string' && step.name.length > 0
      && !numbers.has(step.number) && !names.has(step.name), 'invalid or duplicate step identity');
    numbers.add(step.number);
    names.add(step.name);
  }
  /** @type {import('./validate-flakiness-artifacts.mjs').ValidatedProducerProvenance['suites']} */
  const suites = suiteSteps.map(([suite, name]) => {
    const step = job.steps.find(candidate => candidate.name === name);
    requireValid(step && step.status === 'completed'
      && (step.conclusion === 'success' || step.conclusion === 'failure' || step.conclusion === 'skipped'), `missing or non-publishable suite: ${suite}`);
    return { suite, jobId: job.id, stepNumber: step.number,
      conclusion: step.conclusion, ran: step.conclusion !== 'skipped' };
  });
  let pullRequest = null;
  let testedSha = p.headSha;
  if (p.event === 'pull_request_target') {
    requireValid(Array.isArray(input.originalPullRequests) && input.originalPullRequests.length === 1,
      'missing or ambiguous original-run PR snapshot');
    const original = input.originalPullRequests[0];
    const current = input.currentPullRequest;
    requireValid(original && current, 'missing PR identity');
    for (const record of [original, current]) {
      requireValid(record && validId(record.number) && record.baseRepository === repository
        && typeof record.headRepository === 'string'
        && /^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\/[A-Za-z0-9_-][A-Za-z0-9_.-]*$/.test(record.headRepository)
        && validSha(record.headSha), 'invalid PR identity');
    }
    requireValid(original.number === current.number && original.baseRepository === current.baseRepository
      && original.headRepository === current.headRepository && original.headSha === current.headSha,
      'stale or different current PR head');
    pullRequest = { number: original.number, baseRepository: original.baseRepository,
      headRepository: original.headRepository, headSha: original.headSha };
    testedSha = original.headSha;
  }
  return {
    repository, runId: p.runId, runAttempt: p.runAttempt,
    workflowId: 207092903, workflowPath: '.github/workflows/pr-tests.yml', workflowName: 'PR Tests',
    event: p.event, conclusion: p.conclusion, testedSha, branch: p.headBranch,
    pullRequest, suites,
    sourceUrl: `https://github.com/${repository}/actions/runs/${p.runId}/attempts/${p.runAttempt}`,
  };
}

/** Conservative fixed intake budgets; never raised from artifact input. */
export const ARTIFACT_LIMITS = Object.freeze({ reportBytes: 16 * 1024 * 1024, manifestBytes: 64 * 1024,
  fileBytes: 32 * 1024 * 1024, totalBytes: 128 * 1024 * 1024, files: 2048,
  depth: 64, nodes: 1_000_000, stringBytes: 8 * 1024 * 1024, invocations: 2 });
/** @param {unknown} condition @param {string} reason @returns {asserts condition} */
function check(condition, reason) { if (!condition) throw new Error(`Invalid artifact: ${reason}`); }
/** JSON-only bounded policy applies even to schema-any metadata. @param {Buffer} bytes @param {number} limit */
function parseBounded(bytes, limit) {
  check(bytes.length <= limit, 'JSON bytes budget');
  const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  /** @type {unknown} */
  const value = JSON.parse(text);
  const stack = [{ value, depth: 0 }];
  let nodes = 0;
  while (stack.length) {
    const item = stack.pop();
    check(item, 'preflight item');
    check(++nodes <= ARTIFACT_LIMITS.nodes, 'JSON nodes budget');
    check(item.depth <= ARTIFACT_LIMITS.depth, 'JSON depth budget');
    const v = item.value;
    if (typeof v === 'string') check(Buffer.byteLength(v) <= ARTIFACT_LIMITS.stringBytes, 'string bytes budget');
    else if (typeof v === 'number') check(Number.isFinite(v), 'nonfinite number');
    else if (v !== null && typeof v === 'object') {
      for (const [key, child] of Object.entries(v)) {
        check(!['__proto__', 'prototype', 'constructor'].includes(key), 'prototype-dangerous key');
        check(Buffer.byteLength(key) <= 1024, 'key bytes budget');
        stack.push({ value: child, depth: item.depth + 1 });
        check(stack.length + nodes <= ARTIFACT_LIMITS.nodes, 'JSON nodes budget');
      }
    }
  }
  return value;
}
/** Public native parser; parsed data must preserve every original field.
 * @param {Buffer} bytes @returns {import('./validate-flakiness-artifacts.mjs').NativeReport} */
export function validateNativeReport(bytes) {
  const input = parseBounded(bytes, ARTIFACT_LIMITS.reportBytes);
  const parsed = Schema.Report.safeParse(input);
  check(parsed.success, 'native report schema');
  check(isDeepStrictEqual(parsed.data, input), 'native schema stripped or changed fields');
  return /** @type {import('./validate-flakiness-artifacts.mjs').NativeReport} */ (parsed.data);
}

/** @param {Buffer | string} bytes @param {string} [algorithm] */
function digest(bytes, algorithm = 'sha256') { return createHash(algorithm).update(bytes).digest('hex'); }
/** @param {string} path */
async function ancestry(path) {
  let current = resolve(path);
  const records = [];
  while (true) {
    const stat = await lstat(current);
    check(!stat.isSymbolicLink() && stat.isDirectory(), 'unsafe directory ancestry');
    records.push(`${current}:${stat.dev}:${stat.ino}`);
    if (current === parse(current).root) break;
    current = dirname(current);
  }
  return records.join('\n');
}
/** Narrow trusted OS bridge. Fixed interpreter/helper; no artifact code or inherited env.
 * @param {'directory' | 'file'} kind @param {string} path @param {string} temporaryDirectory @param {number} [byteLimit] @param {number} [entryLimit]
 * @returns {Promise<{files: Array<[string, string]>, dirs: string[], entries: number}>} */
async function safeIntake(kind, path, temporaryDirectory, byteLimit = ARTIFACT_LIMITS.totalBytes, entryLimit = ARTIFACT_LIMITS.files) {
  const helper = fileURLToPath(new URL('./read-flakiness-artifacts.py', import.meta.url));
  const request = JSON.stringify({ kind, path, byteLimit, entryLimit });
  check(Buffer.byteLength(request) <= 8192, 'intake request budget');
  const output = await new Promise((accept, reject) => {
    const child = execFile('/usr/bin/python3', ['-I', '-S', '-B', helper],
      { cwd: '/', env: { TMPDIR: temporaryDirectory }, encoding: 'buffer', timeout: 30_000, killSignal: 'SIGKILL', maxBuffer: 180 * 1024 * 1024 },
      (error, stdout, stderr) => {
        if (error || stderr.length > 4096) reject(new Error('Invalid artifact: safe POSIX intake failed'));
        else accept(stdout);
      });
    let stderrBytes = 0;
    child.stderr?.on('data', chunk => { stderrBytes += chunk.length; if (stderrBytes > 4096) child.kill('SIGKILL'); });
    child.stdin?.on('error', () => {});
    child.stdin?.end(request);
  });
  check(Buffer.isBuffer(output), 'intake protocol');
  /** @type {unknown} */ let protocol;
  try { protocol = JSON.parse(output.toString('utf8')); }
  catch { throw new Error('Invalid artifact: safe POSIX intake failed'); }
  const result = record(protocol);
  check(Array.isArray(result.files) && result.files.length <= ARTIFACT_LIMITS.files
    && Array.isArray(result.dirs) && result.dirs.length <= ARTIFACT_LIMITS.files
    && typeof result.entries === 'number' && Number.isSafeInteger(result.entries)
    && result.entries >= 0 && result.entries <= entryLimit, 'intake protocol');
  /** @type {Array<[string, string]>} */ const files = [];
  for (const item of /** @type {unknown[]} */ (result.files)) {
    check(Array.isArray(item) && item.length === 2 && typeof item[0] === 'string'
      && typeof item[1] === 'string', 'intake file protocol');
    files.push([item[0], item[1]]);
  }
  check(result.dirs.every(dir => typeof dir === 'string'), 'intake directory protocol');
  return { files, dirs: /** @type {string[]} */ (result.dirs), entries: result.entries };
}
/** @param {string} path @param {number} limit @param {string} temporaryDirectory */
async function readRegular(path, limit, temporaryDirectory) {
  const result = await safeIntake('file', path, temporaryDirectory, limit);
  check(result.files.length === 1 && result.files[0]?.[0] === '', 'intake file protocol');
  const bytes = Buffer.from(result.files[0][1], 'base64');
  check(bytes.length <= limit, 'file bytes budget');
  return bytes;
}
/** @param {string} name */
function safeName(name) {
  check(name.length > 0 && name.length <= 512 && !name.includes('\\') && !name.includes('\0')
    && !name.startsWith('/') && !/^[A-Za-z]:/.test(name), 'unsafe payload path');
  const parts = name.split('/');
  check(parts.length <= 6 && parts.every(p => /^[A-Za-z0-9_.-]+$/.test(p) && p !== '.' && p !== '..'), 'unsafe payload segments');
}
/** @returns {{entries: number, intake: number, declared: number, compressed: number, actual: number}} */
function newBudget() { return { entries: 0, intake: 0, declared: 0, compressed: 0, actual: 0 }; }
/** @param {string} root @param {string} temporaryDirectory @param {ReturnType<typeof newBudget>} [budget] @returns {Promise<Map<string, Buffer>>} */
async function readDirectory(root, temporaryDirectory, budget = newBudget()) {
  const result = await safeIntake('directory', root, temporaryDirectory, Math.min(ARTIFACT_LIMITS.totalBytes - budget.actual, ARTIFACT_LIMITS.totalBytes - budget.intake), ARTIFACT_LIMITS.files - budget.entries);
  budget.entries += result.entries;
  const files = new Map(result.files.map(([name, data]) => [name, Buffer.from(data, 'base64')]));
  for (const [name, bytes] of files) { safeName(name); budget.actual += bytes.length; budget.declared += bytes.length; budget.intake += bytes.length; }
  check(budget.actual <= ARTIFACT_LIMITS.totalBytes, 'global actual bytes budget');
  validateDirectories(new Set(result.dirs), files);
  return files;
}
/** @param {unknown} value @returns {Record<string, unknown>} */
function record(value) { check(value !== null && typeof value === 'object' && !Array.isArray(value), 'expected metadata object'); return /** @type {Record<string, unknown>} */ (value); }
/** @param {unknown} value @param {readonly string[]} keys */
function onlyKeys(value, keys) { const obj = record(value); check(Object.keys(obj).every(key => keys.includes(key)), 'unknown metadata/manifest field'); return obj; }
/** @param {unknown} value @param {import('./validate-flakiness-artifacts.mjs').ValidatedProducerProvenance} p */
function sourceLink(value, p) {
  const base = `https://github.com/${p.repository}/actions/runs/${p.runId}`;
  check(typeof value === 'string', 'missing producer source link');
  const url = new URL(value);
  check(!url.hash && (value.split('?')[0] === base || value.split('?')[0] === p.sourceUrl), 'producer source link mismatch');
  /** @type {Set<string>} */ const seen = new Set();
  for (const [key, val] of url.searchParams) {
    check(!seen.has(key) && ((key === 'attempt' && val === String(p.runAttempt))
      || (key === 'check_suite_focus' && val === 'true')), 'producer source query mismatch');
    seen.add(key);
  }
}
/** @param {Map<string, Buffer>} files @param {import('./validate-flakiness-artifacts.mjs').ValidatedProducerProvenance} p */
function validateContents(files, p) {
  /** @type {Map<string, {suite: 'core-unit' | 'cms-e2e', invocation: string}>} */ const groups = new Map();
  for (const name of files.keys()) {
    safeName(name);
    const parts = name.split('/'); const [suite, invocation] = parts;
    check((suite === 'core-unit' || suite === 'cms-e2e') && invocation
      && invocation.length <= 160 && /^test-[A-Za-z0-9_-]+-[1-9]\d*-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(invocation), 'unknown suite/invocation layout');
    const prefix = `${suite}/${invocation}`;
    check(name === `${prefix}/invocation.json` || name === `${prefix}/vendor/report.json`
      || (parts.length === 5 && parts[2] === 'vendor' && parts[3] === 'attachments' && /^[a-f0-9]{40}$/.test(parts[4] ?? '')), 'unexpected payload file');
    groups.set(prefix, { suite, invocation });
  }
  check(groups.size > 0 && groups.size <= ARTIFACT_LIMITS.invocations, 'missing/too many invocations');
  /** @type {Set<string>} */ const suites = new Set();
  const results = [];
  for (const [prefix, identity] of groups) {
    check(!suites.has(identity.suite), 'duplicate suite invocation'); suites.add(identity.suite);
    const step = p.suites.find(s => s.suite === identity.suite);
    check(step?.ran, 'unexpected/not-run suite');
    const manifestBytes = files.get(`${prefix}/invocation.json`); const reportBytes = files.get(`${prefix}/vendor/report.json`);
    check(manifestBytes && reportBytes, 'missing native report/manifest evidence');
    const m = onlyKeys(parseBounded(manifestBytes, ARTIFACT_LIMITS.manifestBytes), ['suite', 'target', 'source', 'invocation', 'commit', 'startedAt', 'endedAt', 'outcome', 'runId', 'attempt', 'job', 'shard', 'pullRequest', 'pullRequestStatus', 'pullRequestSource', 'workflow', 'runURL', 'targetURL']);
    check(m.suite === identity.suite && m.invocation === identity.invocation && m.source === 'ci'
      && m.runId === String(p.runId) && m.attempt === String(p.runAttempt) && m.job === 'test'
      && m.workflow === p.workflowName && m.commit === p.testedSha, 'manifest provenance mismatch');
    check(m.shard === undefined && identity.invocation.startsWith(`test-local-${p.runAttempt}-`), 'unexpected shard/invocation identity');
    check(typeof m.startedAt === 'string' && typeof m.endedAt === 'string' && Number.isFinite(Date.parse(m.startedAt))
      && Date.parse(m.endedAt) >= Date.parse(m.startedAt), 'missing/invalid completion time');
    check(m.outcome === 'passed' || m.outcome === 'failed', 'interrupted/incomplete outcome');
    check((m.outcome === 'passed') === (step.conclusion === 'success'), 'manifest/step outcome mismatch');
    const target = m.target;
    check(identity.suite === 'core-unit' ? target === 'none'
      : target === 'local-worker' || target === 'preview-worker', 'unstable target dimension');
    if (m.targetURL !== undefined) {
      check(typeof m.targetURL === 'string' && target !== 'none', 'unexpected target URL');
      const url = new URL(m.targetURL);
      check(['http:', 'https:'].includes(url.protocol) && !url.username && !url.password
        && !url.search && !url.hash && !m.targetURL.includes('?') && !m.targetURL.includes('#')
        && url.toString() === m.targetURL, 'unsanitized target URL');
      const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname.toLowerCase());
      check(loopback === (target === 'local-worker'), 'target URL/dimension mismatch');
    }
    check(p.pullRequest ? m.pullRequest === String(p.pullRequest.number) && m.pullRequestStatus === 'associated'
      && ['event', 'override', 'ref'].includes(String(m.pullRequestSource)) : m.pullRequest === undefined && m.pullRequestStatus === 'no-pr' && m.pullRequestSource === undefined, 'manifest PR mismatch');
    sourceLink(m.runURL, p);
    const r = validateNativeReport(reportBytes);
    check(r.commitId === p.testedSha && r.category === (identity.suite === 'core-unit' ? 'vitest' : 'playwright'), 'native category/commit mismatch');
    check(r.flakinessProject === undefined || r.flakinessProject === 'SonicJs/sonicjs', 'hostile project');
    sourceLink(r.url, p);
    check(r.environments.length === 1 && r.environments[0]?.name === (identity.suite === 'core-unit' ? 'vitest' : 'chromium'), 'environment name/count mismatch');
    for (const env of r.environments) {
      check(isDeepStrictEqual(env.metadata, { suite: identity.suite, target, source: 'ci' }), 'environment dimensions mismatch');
      // Native schema-any field is deliberately forbidden until reviewed producer use exists.
      check(env.userSuppliedData === undefined, 'unreviewed userSuppliedData');
    }
    const counts = { tests: 0, attempts: 0, passed: 0, failed: 0, skipped: 0, suiteErrors: r.unattributedErrors?.length ?? 0 };
    /** @type {Set<string>} */ const attachments = new Set();
    /** @param {ReadonlyArray<import('./validate-flakiness-artifacts.mjs').NativeAttachment> | undefined} refs */
    function collect(refs) { for (const ref of refs ?? []) { check(/^[a-f0-9]{40}$/.test(ref.id), 'unsafe attachment ID'); attachments.add(ref.id); } }
    const pending = [...(r.suites ?? [])]; const tests = [...(r.tests ?? [])];
    while (pending.length) {
      const suite = pending.pop(); check(suite, 'suite');
      for (const child of suite.suites ?? []) pending.push(child);
      for (const test of suite.tests ?? []) tests.push(test);
    }
    for (const test of tests) {
      counts.tests++; check(test.attempts.length > 0, 'missing attempts');
      for (const attempt of test.attempts) {
        counts.attempts++;
        const idx = attempt.environmentIdx ?? 0;
        check(Number.isSafeInteger(idx) && idx >= 0 && idx < r.environments.length, 'environment index');
        check(attempt.status !== 'interrupted', 'interrupted attempt');
        collect(attempt.attachments);
        const steps = [...attempt.steps ?? []];
        while (steps.length) {
          const child = steps.pop(); check(child, 'step'); collect(child.attachments);
          for (const nested of child.steps ?? []) steps.push(nested);
        }
      }
      const last = test.attempts.at(-1); check(last, 'attempt');
      const status = last.status ?? 'passed';
      if (status === 'skipped') counts.skipped++;
      else if (status === (last.expectedStatus ?? 'passed')) counts.passed++;
      else counts.failed++;
    }
    check((counts.tests > 0 && counts.passed + counts.failed > 0)
      || (counts.tests === 0 && counts.suiteErrors > 0 && m.outcome === 'failed' && step.conclusion === 'failure'), 'empty/not-run report');
    const failure = counts.failed > 0 || counts.suiteErrors > 0;
    check(m.outcome === 'failed' ? failure : !failure, 'native/manifest outcome mismatch');
    for (const id of attachments) {
      const bytes = files.get(`${prefix}/vendor/attachments/${id}`);
      check(bytes && digest(bytes, 'sha1') === id, 'missing attachment/digest mismatch');
    }
    for (const name of files.keys()) if (name.startsWith(`${prefix}/vendor/attachments/`)) check(attachments.has(name.slice(name.lastIndexOf('/') + 1)), 'unreferenced attachment');
    const outcome = /** @type {'passed' | 'failed'} */ (m.outcome);
    results.push({ prefix, ...identity, step, counts, outcome });
  }
  for (const step of p.suites) check(!step.ran || suites.has(step.suite), 'missing suite evidence');
  return results;
}
/** @template T @param {T} value @returns {Readonly<T>} */
function freeze(value) {
  if (value && typeof value === 'object') { for (const child of Object.values(value)) freeze(child); Object.freeze(value); }
  return value;
}
/** @param {import('./validate-flakiness-artifacts.mjs').ArtifactValidationInput} input @returns {Promise<import('./validate-flakiness-artifacts.mjs').ArtifactSnapshots>} */
export async function validateArtifactPayload(input) {
  // Copy trusted adapter input before first await; never derive it from a manifest.
  const provenance = validateProducerProvenance(structuredClone(input.trusted));
  const inputs = /** @type {readonly import('./validate-flakiness-artifacts.mjs').ArtifactInput[]} */ (Array.isArray(input.input) ? input.input : [input.input]);
  check(inputs.length > 0 && inputs.length <= ARTIFACT_LIMITS.invocations, 'input batch count budget');
  const sources = inputs.map(item => {
    check(item.kind === 'directory' || item.kind === 'zip', 'unsupported input kind');
    return { kind: item.kind, path: resolve(item.path) };
  });
  const parent = resolve(input.stagingParent);
  for (const source of sources) check(parent !== source.path && !parent.startsWith(source.path + sep), 'staging must be outside input');
  await ancestry(parent);
  const owner = await lstat(parent); check(owner.uid === process.getuid?.() && !(owner.mode & 0o022), 'staging parent must be owned/private');
  const budget = newBudget();
  /** @type {Map<string, Buffer>} */ const files = new Map();
  /** @type {Map<string, string>} */ const prefixes = new Map();
  const batches = [];
  for (const source of sources) {
    const batch = source.kind === 'directory' ? await readDirectory(source.path, parent, budget) : await readZip(source.path, budget, parent);
    for (const [name, bytes] of batch) {
      check(!files.has(name), 'cross-input duplicate path');
      const parts = name.split('/');
      for (let i = 1; i <= parts.length; i++) {
        const prefix = parts.slice(0, i).join('/'); const folded = prefix.toLowerCase();
        check(!prefixes.has(folded) || prefixes.get(folded) === prefix, 'cross-input case collision');
        prefixes.set(folded, prefix);
        if (i < parts.length) check(!files.has(prefix), 'cross-input file/directory prefix collision');
      }
      check(![...files.keys()].some(key => key.startsWith(name + '/')), 'cross-input file/directory prefix collision');
      files.set(name, bytes);
    }
    batches.push({ source, batch });
  }
  const contents = validateContents(files, provenance);
  // Re-read directories using anchored intake to catch changes spanning validation.
  for (const { source, batch } of batches) if (source.kind === 'directory') {
    const again = await readDirectory(source.path, parent);
    check(again.size === batch.size && [...batch].every(([name, bytes]) => again.get(name)?.equals(bytes)), 'input mutated during validation');
  }
  const root = await mkdtemp(join(parent, 'snapshot-'));
  try {
    for (const [name, bytes] of files) { const path = join(root, name); await mkdir(dirname(path), { recursive: true, mode: 0o700 }); await writeFile(path, bytes, { flag: 'wx', mode: 0o400 }); }
    const invocations = contents.map(c => {
      const manifest = [...files].sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).filter(([name]) => name.startsWith(c.prefix + '/')).map(([name, bytes]) => ({ path: relative(root, join(root, name)), bytes: bytes.length, sha256: digest(bytes) }));
      const id = digest(JSON.stringify([provenance.repository, provenance.runId, provenance.runAttempt, c.step.jobId, c.suite, c.invocation, manifest]));
      return { id, suite: c.step.suite, invocation: c.invocation, jobId: c.step.jobId, stepNumber: c.step.stepNumber, reportPath: join(root, c.prefix, 'vendor/report.json'), manifestPath: join(root, c.prefix, 'invocation.json'), counts: c.counts, outcome: c.outcome, files: manifest };
    });
    return freeze({ root, provenance, invocations });
  } catch (error) { await rm(root, { recursive: true, force: true }); throw error; }
}
/** @param {import('./validate-flakiness-artifacts.mjs').ArtifactSnapshots} snapshots */
export async function verifyUploadSnapshots(snapshots) {
  const files = await readDirectory(snapshots.root, dirname(snapshots.root));
  const expected = snapshots.invocations.flatMap(i => i.files);
  check(files.size === expected.length, 'snapshot tree changed');
  for (const file of expected) { const bytes = files.get(file.path); check(bytes && bytes.length === file.bytes && digest(bytes) === file.sha256, 'snapshot digest changed'); }
}
/** @param {string} path @param {ReturnType<typeof newBudget>} budget @param {string} temporaryDirectory @returns {Promise<Map<string, Buffer>>} */
async function readZip(path, budget, temporaryDirectory) {
  const bytes = await readRegular(path, ARTIFACT_LIMITS.totalBytes - budget.intake, temporaryDirectory);
  budget.intake += bytes.length;
  const zip = await fromBufferPromise(bytes, { lazyEntries: true, autoClose: false, strictFileNames: true, decodeStrings: true, validateEntrySizes: true });
  // Keep error listener installed for the complete handle lifetime, including streams.
  /** @type {Error | undefined} */ let zipError;
  zip.on('error', error => { zipError = error; });
  try {
    budget.entries += zip.entryCount;
    check(zip.entryCount > 0 && budget.entries <= ARTIFACT_LIMITS.files, 'global ZIP entry count budget');
    /** @type {import('yauzl').Entry[]} */ const entries = [];
    /** @type {Map<string, boolean>} */ const names = new Map();
    /** @type {Map<string, string>} */ const prefixes = new Map(); /** @type {Set<string>} */ const dirs = new Set();
    for await (const entry of zip.eachEntry()) {
      const directory = entry.fileName.endsWith('/');
      const name = directory ? entry.fileName.slice(0, -1) : entry.fileName;
      safeName(name);
      const folded = name.toLowerCase();
      const segments = name.split('/');
      for (let length = 1; length <= segments.length; length++) {
        const prefix = segments.slice(0, length).join('/'); const key = prefix.toLowerCase();
        check(!prefixes.has(key) || prefixes.get(key) === prefix, 'ZIP case-colliding prefix'); prefixes.set(key, prefix);
      }
      check(!names.has(folded), 'ZIP duplicate/case-colliding name'); names.set(folded, directory);
      check(!entry.isEncrypted() && !(entry.generalPurposeBitFlag & 0x40), 'ZIP encryption');
      check(entry.compressionMethod === 0 || entry.compressionMethod === 8, 'ZIP unsupported method');
      check(!(entry.generalPurposeBitFlag & ~0x80e), 'ZIP unsupported flags');
      const mode = entry.externalFileAttributes >>> 16; const type = mode & 0o170000;
      check(type === 0 || type === (directory ? 0o040000 : 0o100000), 'ZIP special/symlink metadata');
      check(!(mode & 0o7000) && (!(mode & 0o111) || directory), 'ZIP executable/unsupported permissions');
      const dos = entry.externalFileAttributes & 0xffff;
      check(!(dos & ~0x37) && (dos === 0 || Boolean(dos & 0x10) === directory), 'ZIP unsupported DOS metadata');
      check(Number.isSafeInteger(entry.uncompressedSize) && Number.isSafeInteger(entry.compressedSize)
        && entry.uncompressedSize >= 0 && entry.compressedSize >= 0 && entry.uncompressedSize <= ARTIFACT_LIMITS.fileBytes, 'ZIP declared entry budget');
      budget.declared += entry.uncompressedSize; budget.compressed += entry.compressedSize;
      check(budget.declared <= ARTIFACT_LIMITS.totalBytes && budget.compressed <= ARTIFACT_LIMITS.totalBytes && budget.actual + entry.uncompressedSize <= ARTIFACT_LIMITS.totalBytes, 'ZIP declared total budget');
      check(entry.uncompressedSize <= Math.max(1024 * 1024, entry.compressedSize * 1000), 'ZIP compression ratio budget');
      if (directory) { check(entry.uncompressedSize === 0, 'ZIP directory payload'); dirs.add(name); }
      entries.push(entry);
    }
    check(!zipError, 'ZIP parser error');
    for (const [name] of names) {
      const parts = name.split('/'); parts.pop();
      while (parts.length) { check(names.get(parts.join('/')) !== false, 'ZIP file/directory prefix collision'); parts.pop(); }
    }
    /** @type {Map<string, Buffer>} */ const files = new Map();
    for (const entry of entries) {
      if (entry.fileName.endsWith('/')) continue;
      const stream = await zip.openReadStreamPromise(entry); const chunks = []; let length = 0; let crc = 0;
      try {
        for await (const chunk of stream) {
          check(Buffer.isBuffer(chunk), 'ZIP stream type');
          length += chunk.length; budget.actual += chunk.length;
          check(length <= ARTIFACT_LIMITS.fileBytes && budget.actual <= ARTIFACT_LIMITS.totalBytes && length <= entry.uncompressedSize, 'ZIP actual decompression budget');
          crc = crc32(chunk, crc); chunks.push(chunk);
          check(!zipError, 'ZIP parser error');
        }
      } finally { stream.destroy(); }
      check(length === entry.uncompressedSize && crc === entry.crc32, 'ZIP actual size/CRC mismatch');
      files.set(entry.fileName, Buffer.concat(chunks));
    }
    validateDirectories(dirs, files);
    check(!zipError, 'ZIP parser error');
    return files;
  } finally { zip.close(); }
}

/** @param {Set<string>} dirs @param {Map<string, Buffer>} files */
function validateDirectories(dirs, files) {
  for (const dir of dirs) check([...files.keys()].some(name => name.startsWith(dir + '/'))
    || (dir.endsWith('/vendor/attachments') && files.has(dir.slice(0, -12) + '/report.json')), 'unexpected empty directory');
}
