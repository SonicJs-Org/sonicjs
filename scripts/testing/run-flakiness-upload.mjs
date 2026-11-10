/**
 * Trusted CI entrypoint. One complete producer attempt is validated before any
 * privileged child starts. All report fields remain untrusted; only main's
 * installed runtime and GitHub metadata determine identity and destination.
 * CLI acceptance is explicitly unverified until Task 7 hosted read-back.
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fetchProducerProvenance } from './fetch-producer-provenance.mjs';
import { validateArtifactPayload, validateProducerProvenance } from './validate-flakiness-artifacts.mjs';
import { executeUpload } from './upload-flakiness.mjs';
import { beginDeliveryAttempt, finishDeliveryAttempt } from './delivery-ledger.mjs';

/** Append concise delivery status; never render untrusted report text or credentials. */
function summary(text) {
  console.log(text);
  if (process.env.GITHUB_STEP_SUMMARY) writeFileSync(process.env.GITHUB_STEP_SUMMARY, `${text}\n`, { flag: 'a' });
}

/** Validate required runtime configuration without inspecting any secret values. */
function required(name) {
  const value = process.env[name];
  if (!value) throw new Error(`Missing required environment variable: ${name}`);
  return value;
}

/** Run exactly one serialized consumer attempt, preserving ledger on ordinary errors. */
async function main() {
  const options = { ledgerDir: resolve(required('LEDGER_DIR')), producerRunId: Number(required('PRODUCER_RUN_ID')),
    producerAttempt: Number(required('PRODUCER_RUN_ATTEMPT')), consumerRunId: Number(required('GITHUB_RUN_ID')),
    consumerAttempt: Number(required('GITHUB_RUN_ATTEMPT')) };
  mkdirSync(options.ledgerDir, { recursive: true, mode: 0o700 });
  await beginDeliveryAttempt(options); // Missing rerun history must never receive a new seal.
  try {
    const trusted = await fetchProducerProvenance({ repository: required('GITHUB_REPOSITORY'), runId: options.producerRunId,
      runAttempt: options.producerAttempt, token: required('GITHUB_TOKEN') });
    const provenance = validateProducerProvenance(trusted);
    if (provenance.suites.every(suite => !suite.ran)) {
      summary('nothing to publish; suites not run. Trusted producer provenance validated.');
      return;
    }
    const project = required('FLAKINESS_PROJECT');
    const stagingParent = resolve(required('STAGING_DIR'));
    mkdirSync(stagingParent, { recursive: true, mode: 0o700 });
    const snapshots = await validateArtifactPayload({ input: { kind: 'directory', path: resolve(required('ARTIFACT_DIR')) }, stagingParent, trusted, project });
    const skipped = snapshots.provenance.suites.filter(s => !s.ran).length;
    summary(`Validated ${snapshots.invocations.length} complete invocation(s); ${skipped} producer suite job(s) did not run. Missing/interrupted evidence is never counted as success.`);
    const result = await executeUpload(snapshots, { runtimeDir: resolve(required('RUNTIME_DIR')), ledgerDir: options.ledgerDir, privateScratchDir: resolve(required('CLI_SCRATCH_DIR')), project, timeoutMs: 180_000 },
      { githubOidcUrl: required('ACTIONS_ID_TOKEN_REQUEST_URL'), githubOidcToken: required('ACTIONS_ID_TOKEN_REQUEST_TOKEN') }, { enableUpload: true });
    for (const r of result.results) summary(`- ${r.suite}: ${r.state}${r.receiptUrl ? ` — ${r.receiptUrl}` : ''}`);
    summary('CLI acceptance is not dashboard verification. Hosted OIDC delivery and read-back remain unproven.');
    if (result.anyFailed || result.anyAmbiguous) process.exitCode = 1;
  } finally {
    // started/failed/ambiguous ledger states block resubmission independently.
    await finishDeliveryAttempt(options);
  }
}

/** Fixed diagnostics only. Never interpolate upstream error messages or stacks. */
function safeFailureCategory(error) {
  const message = error?.message;
  if (message === 'Invalid artifact: JSON syntax') return 'Invalid artifact: JSON syntax';
  if (message === 'Prior delivery checkpoint unavailable; rerun blocked to prevent duplicate submission') return 'Prior delivery checkpoint unavailable; rerun blocked to prevent duplicate submission';
  if (message === 'Prior delivery checkpoint record inventory mismatch') return 'Prior delivery checkpoint record inventory mismatch';
  if (message === 'Prior delivery checkpoint mismatch') return 'Prior delivery checkpoint mismatch';
  if (error?.code === 'EACCES' && error?.syscall === 'mkdtemp') return 'Private scratch allocation failed: EACCES during mkdtemp';
  if (typeof message === 'string') {
    if (message.startsWith('Invalid artifact:')) return 'Invalid artifact: validation failed';
    if (message.startsWith('Non-publishable producer:')) return 'Producer provenance validation failed.';
    if (message.startsWith('Missing required environment variable:')) return 'Required runtime configuration missing.';
    if (message.startsWith('GitHub metadata request failed:')) return 'GitHub metadata request failed.';
  }
  return 'Publishing operation failed.';
}

main().catch(error => {
  summary('Publishing failed or evidence is missing/interrupted. Delivery is not verified; inspect native producer artifacts.');
  console.error(safeFailureCategory(error));
  process.exitCode = 1;
});
