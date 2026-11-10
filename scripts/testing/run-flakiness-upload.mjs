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

main().catch(error => {
  summary('Publishing failed or evidence is missing/interrupted. Delivery is not verified; inspect native producer artifacts.');
  console.error(error.message);
  process.exitCode = 1;
});
