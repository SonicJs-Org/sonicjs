/**
 * Upload orchestration with a caller-persisted delivery ledger.
 * Consumes pre-validated private ArtifactSnapshots only; never re-reads inputs.
 * Does NOT authenticate; authentication is passed explicitly as `auth`.
 * Task 5 — no hosted delivery until Task 7 (privacy/OIDC/cutover) gates are met.
 */
import { spawn } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { readFile, writeFile, rename, mkdir, mkdtemp, rm, stat } from 'node:fs/promises';
import { join, dirname, resolve } from 'node:path';
import { verifyUploadSnapshots } from './validate-flakiness-artifacts.mjs';

const FIXED_PROJECT = 'SonicJs/sonicjs';
const FIXED_ENDPOINT = 'https://flakiness.io';
/** Matches a single receipt URL from CLI stdout; anchored to expected origin. */
const RECEIPT_PATTERN = /https:\/\/flakiness\.io\/[^\s"<>\x00-\x1f]{1,250}/g;
const DEFAULT_TIMEOUT_MS = 120_000;
const MAX_OUTPUT_BYTES = 64 * 1024;
const TERM_GRACE_MS = 5_000;

/**
 * Logical delivery key — computed from provenance + invocation identity, NOT content.
 * Different content under the same key is rejected; changing content must be a new invocation.
 * @param {import('./validate-flakiness-artifacts.mjs').UploadSnapshot} snapshot
 * @param {import('./validate-flakiness-artifacts.mjs').ArtifactSnapshots['provenance']} provenance
 */
function logicalKey(snapshot, provenance) {
  return `${provenance.repository}/${provenance.runId}/${provenance.runAttempt}/${snapshot.jobId}/${snapshot.suite}/${snapshot.invocation}`;
}

/** @param {string} key */
function assertSafeKey(key) {
  if (key.includes('..') || key.includes('\0') || key.length > 2048) {
    throw new Error(`Unsafe logical key: ${key.slice(0, 120)}`);
  }
}

/**
 * Content digest over the sorted snapshot file manifest.
 * Used to detect when the same logical key carries changed content.
 * @param {import('./validate-flakiness-artifacts.mjs').UploadSnapshot} snapshot
 */
function contentDigest(snapshot) {
  const sorted = [...snapshot.files].sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
  return createHash('sha256').update(JSON.stringify(sorted.map(f => [f.path, f.bytes, f.sha256]))).digest('hex');
}

/**
 * @param {string} ledgerDir
 * @param {string} key
 */
function ledgerPath(ledgerDir, key) {
  assertSafeKey(key);
  return join(ledgerDir, createHash('sha256').update(key).digest('hex') + '.json');
}

/**
 * @param {string} path
 * @returns {Promise<Record<string, unknown> | null>}
 */
async function readLedger(path) {
  let text;
  try {
    text = await readFile(path, 'utf8');
  } catch (err) {
    if (/** @type {NodeJS.ErrnoException} */ (err).code === 'ENOENT') return null;
    throw new Error(`Ledger read error: ${/** @type {Error} */ (err).message}`);
  }
  try {
    const v = JSON.parse(text);
    if (!v || typeof v !== 'object' || Array.isArray(v)) throw new Error('not an object');
    return /** @type {Record<string, unknown>} */ (v);
  } catch {
    throw new Error(`Corrupt ledger entry: ${path}`);
  }
}

/**
 * Atomically write ledger entry via temp-file rename.
 * @param {string} path
 * @param {Record<string, unknown>} entry
 */
async function writeLedger(path, entry) {
  const tmp = `${path}.tmp.${randomBytes(4).toString('hex')}`;
  await writeFile(tmp, JSON.stringify(entry, null, 2), { flag: 'w', mode: 0o600 });
  await rename(tmp, path);
}

/**
 * Verify this invocation's files via direct Node read (narrow pre-spawn check).
 * @param {string} snapshotRoot
 * @param {import('./validate-flakiness-artifacts.mjs').UploadSnapshot} snapshot
 */
async function verifyInvocationFiles(snapshotRoot, snapshot) {
  for (const f of snapshot.files) {
    let bytes;
    try { bytes = await readFile(join(snapshotRoot, f.path)); }
    catch { throw new Error(`Snapshot file missing before spawn: ${f.path}`); }
    if (bytes.length !== f.bytes || createHash('sha256').update(bytes).digest('hex') !== f.sha256) {
      throw new Error(`Snapshot file changed before spawn: ${f.path}`);
    }
  }
}

/**
 * Spawn the CLI child with isolated environment and bounded output.
 * Never logs stdout/stderr (they may contain credentials/tokens).
 * @param {string} cliBin
 * @param {string} reportDir
 * @param {string} home
 * @param {string} tmp
 * @param {{accessToken: string} | {githubOidcUrl: string; githubOidcToken: string}} auth
 * @param {number} timeoutMs
 * @param {string} project
 * @returns {Promise<{state: string; receiptUrl?: string; error?: string}>}
 */
function spawnCli(cliBin, reportDir, home, tmp, auth, timeoutMs, project) {
  return new Promise(resolvePromise => {
    // Explicit allowlist — strip all ambient env, Node options, session config, OIDC vars.
    // Include node binary dir so fake-CLI shell wrappers in tests can exec node.
    const nodeBinDir = dirname(process.execPath);
    const env = /** @type {Record<string, string>} */ ({
      PATH: `${nodeBinDir}:${join(resolve(cliBin), '..')}:/usr/bin:/bin`,
      HOME: home,
      TMPDIR: tmp,
      CI: '1',
      SONICJS_TEST_UPLOAD: '0',
      FLAKINESS_DISABLE_UPLOAD: '1',
    });
    if ('accessToken' in auth) {
      env.FLAKINESS_ACCESS_TOKEN = auth.accessToken;
    } else {
      env.ACTIONS_ID_TOKEN_REQUEST_URL = auth.githubOidcUrl;
      env.ACTIONS_ID_TOKEN_REQUEST_TOKEN = auth.githubOidcToken;
    }

    const proc = spawn(cliBin, ['upload', '--project', project, '--endpoint', FIXED_ENDPOINT, reportDir], {
      env, cwd: tmp, stdio: ['ignore', 'pipe', 'pipe'],
    });

    /** @type {Buffer[]} */ const stdoutBufs = [];
    let stdoutLen = 0;
    let overflowed = false;
    let timedOut = false;

    const timer = setTimeout(() => {
      timedOut = true;
      try { proc.kill('SIGTERM'); } catch {}
      setTimeout(() => { try { proc.kill('SIGKILL'); } catch {} }, TERM_GRACE_MS);
    }, timeoutMs);

    proc.stdout.on('data', chunk => {
      if (overflowed) return;
      stdoutLen += chunk.length;
      if (stdoutLen > MAX_OUTPUT_BYTES) {
        overflowed = true;
        try { proc.kill('SIGTERM'); } catch {}
        return;
      }
      stdoutBufs.push(chunk);
    });
    proc.stderr.on('data', () => {}); // discard; may contain credentials

    proc.on('error', () => {
      clearTimeout(timer);
      // Spawn failure occurs before execution; keep diagnostics free of ambient paths.
      resolvePromise({ state: 'failed', error: 'CLI could not start' });
    });

    proc.on('close', (code, signal) => {
      clearTimeout(timer);
      if (timedOut) { resolvePromise({ state: 'ambiguous', error: 'timeout' }); return; }
      if (overflowed) { resolvePromise({ state: 'ambiguous', error: 'stdout overflow' }); return; }
      if (signal) { resolvePromise({ state: 'ambiguous', error: `signal: ${signal}` }); return; }
      if (code !== 0) { resolvePromise({ state: 'failed', error: `exit ${code}` }); return; }

      const stdout = Buffer.concat(stdoutBufs).toString('utf8');
      const matches = [...stdout.matchAll(RECEIPT_PATTERN)].map(m => m[0]);
      if (matches.length !== 1) {
        resolvePromise({ state: 'ambiguous', error: `expected 1 receipt URL, got ${matches.length}` });
        return;
      }

      const url = matches[0];
      let parsed;
      try { parsed = new URL(url); }
      catch { resolvePromise({ state: 'ambiguous', error: 'URL parse failed' }); return; }

      if (parsed.protocol !== 'https:' || parsed.hostname !== 'flakiness.io' ||
          parsed.username || parsed.password || parsed.search || parsed.hash ||
          url.length > 300) {
        resolvePromise({ state: 'ambiguous', error: 'URL invalid or non-canonical' });
        return;
      }
      resolvePromise({ state: 'accepted-unverified', receiptUrl: url });
    });
  });
}

/**
 * Validate-only entry point; no auth, CLI, or ledger access.
 * Always safe to call; returns state:'validation-only' for all invocations.
 * @param {import('./validate-flakiness-artifacts.mjs').ArtifactSnapshots} snapshots
 * @returns {Promise<import('./upload-flakiness.mjs').UploadSummary>}
 */
export async function validateOnly(snapshots) {
  const { provenance, invocations } = snapshots;
  return {
    provenance: {
      repository: provenance.repository, runId: provenance.runId,
      runAttempt: provenance.runAttempt, workflowId: provenance.workflowId,
      testedSha: provenance.testedSha,
    },
    results: invocations.map(snapshot => ({
      invocationId: snapshot.id, suite: snapshot.suite,
      logicalKey: logicalKey(snapshot, provenance),
      state: /** @type {import('./upload-flakiness.mjs').UploadState} */ ('validation-only'),
    })),
    anyAmbiguous: false,
    anyFailed: false,
  };
}

/**
 * Execute upload with durable ledger. Pass options.enableUpload:true to enable CLI.
 * Without enableUpload:true, behaves identically to validateOnly (safe default).
 * @param {import('./validate-flakiness-artifacts.mjs').ArtifactSnapshots} snapshots
 * @param {import('./upload-flakiness.mjs').UploadConfig} config
 * @param {{accessToken: string} | {githubOidcUrl: string; githubOidcToken: string}} auth
 * @param {{enableUpload?: boolean}} [options]
 * @returns {Promise<import('./upload-flakiness.mjs').UploadSummary>}
 */
export async function executeUpload(snapshots, config, auth, options) {
  if (!options || options.enableUpload !== true) return validateOnly(snapshots);

  const { provenance, invocations } = snapshots;
  const { runtimeDir, ledgerDir, timeoutMs = DEFAULT_TIMEOUT_MS } = config;
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) throw new Error('Invalid timeoutMs');

  const project = config.project ?? FIXED_PROJECT;
  if (typeof project !== 'string' || project.length > 150 || !/^[A-Za-z0-9_-]+\/[A-Za-z0-9_.-]+$/.test(project)) throw new Error('Invalid trusted project');
  const cliBin = join(resolve(runtimeDir), 'node_modules', '.bin', 'flakiness');
  await stat(cliBin);
  await stat(join(runtimeDir, 'package-lock.json'));

  // Verify ALL snapshots before ANY auth or child access.
  // If this throws, nothing else runs — including auth property access.
  await verifyUploadSnapshots(snapshots);

  const summary = /** @type {import('./upload-flakiness.mjs').UploadSummary} */ ({
    provenance: {
      repository: provenance.repository, runId: provenance.runId,
      runAttempt: provenance.runAttempt, workflowId: provenance.workflowId,
      testedSha: provenance.testedSha,
    },
    results: [],
    anyAmbiguous: false,
    anyFailed: false,
  });

  for (const snapshot of invocations) {
    const key = logicalKey(snapshot, provenance);
    assertSafeKey(key);
    const lPath = ledgerPath(ledgerDir, key);

    const existing = await readLedger(lPath);
    if (existing !== null) {
      if (typeof existing.state !== 'string') throw new Error(`Corrupt ledger state for key: ${key}`);
      if (existing.contentDigest !== contentDigest(snapshot)) {
        summary.results.push({ invocationId: snapshot.id, suite: snapshot.suite, logicalKey: key, state: 'blocked', error: 'content mismatch: snapshot changed from prior ledger entry' });
        summary.anyFailed = true;
        continue;
      }
      // Even nonzero exit can follow a successful remote submission. No blind retries.
      if (['started', 'ambiguous', 'accepted-unverified', 'failed'].includes(existing.state)) {
        summary.results.push({ invocationId: snapshot.id, suite: snapshot.suite, logicalKey: key, state: 'blocked', error: `ledger state: ${existing.state}` });
        summary.anyFailed = true;
        continue;
      }
      throw new Error(`Unrecognized ledger state for key: ${key}`);
    }

    const digest = contentDigest(snapshot);
    // Write 'started' atomically BEFORE spawning; crash-restart leaves this as ambiguous.
    await writeLedger(lPath, {
      logicalKey: key, invocationId: snapshot.id, contentDigest: digest,
      suite: snapshot.suite, outcome: snapshot.outcome,
      counts: { ...snapshot.counts },
      state: 'started', startedAt: new Date().toISOString(),
    });

    // Narrow per-invocation pre-spawn re-verify (Node read, not Python bridge)
    try {
      await verifyInvocationFiles(snapshots.root, snapshot);
    } catch (err) {
      const entry = await readLedger(lPath);
      await writeLedger(lPath, { ...entry, state: 'ambiguous', error: 'snapshot changed before spawn', finishedAt: new Date().toISOString() });
      summary.results.push({ invocationId: snapshot.id, suite: snapshot.suite, logicalKey: key, state: 'ambiguous', error: 'snapshot changed before spawn' });
      summary.anyAmbiguous = true;
      continue;
    }

    // Create isolated HOME and tmpdir; clean up in finally.
    const home = await mkdtemp(join(ledgerDir, 'cli-home-'));
    const tmp = await mkdtemp(join(ledgerDir, 'cli-tmp-'));
    let childResult;
    try {
      childResult = await spawnCli(cliBin, dirname(snapshot.reportPath), home, tmp, auth, timeoutMs, project);
    } finally {
      await rm(home, { recursive: true, force: true });
      await rm(tmp, { recursive: true, force: true });
    }

    const startedEntry = await readLedger(lPath);
    await writeLedger(lPath, {
      logicalKey: key, invocationId: snapshot.id, contentDigest: digest,
      suite: snapshot.suite, outcome: snapshot.outcome,
      counts: { ...snapshot.counts },
      state: childResult.state,
      ...(childResult.receiptUrl != null ? { receiptUrl: childResult.receiptUrl } : {}),
      ...(childResult.error != null ? { error: childResult.error } : {}),
      startedAt: (startedEntry?.startedAt ?? new Date().toISOString()),
      finishedAt: new Date().toISOString(),
    });

    summary.results.push({
      invocationId: snapshot.id, suite: snapshot.suite, logicalKey: key,
      state: /** @type {import('./upload-flakiness.mjs').UploadState} */ (childResult.state),
      ...(childResult.receiptUrl != null ? { receiptUrl: childResult.receiptUrl } : {}),
      ...(childResult.error != null ? { error: childResult.error } : {}),
    });
    if (childResult.state === 'ambiguous') summary.anyAmbiguous = true;
    if (childResult.state === 'failed') summary.anyFailed = true;
  }

  return summary;
}
