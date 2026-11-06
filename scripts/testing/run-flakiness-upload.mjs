/**
 * CI entrypoint: fetch provenance from GitHub API, validate artifacts, upload to Flakiness.
 * Run from the flakiness-upload.yml workflow step.
 *
 * Required env:
 *   GITHUB_TOKEN         - for GitHub API (actions: read)
 *   GITHUB_REPOSITORY    - e.g. SonicJs-Org/sonicjs
 *   PRODUCER_RUN_ID      - workflow_run.id
 *   PRODUCER_RUN_ATTEMPT - workflow_run.run_attempt
 *   FLAKINESS_PROJECT    - e.g. SonicJs/sonicjs
 *   ARTIFACT_DIR         - path to downloaded artifact directory (suite root)
 *   SUITE                - 'core-unit' or 'cms-e2e'
 *   STAGING_DIR          - private writable temp dir outside artifact
 *   LEDGER_DIR           - private writable dir for delivery ledger
 *   RUNTIME_DIR          - path to installed flakiness CLI runtime
 *   ACTIONS_ID_TOKEN_REQUEST_URL   - provided by id-token: write
 *   ACTIONS_ID_TOKEN_REQUEST_TOKEN - provided by id-token: write
 */
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { fetchProducerProvenance } from './fetch-producer-provenance.mjs';
import { validateArtifactPayload } from './validate-flakiness-artifacts.mjs';
import { executeUpload } from './upload-flakiness.mjs';

const {
  GITHUB_TOKEN, GITHUB_REPOSITORY,
  PRODUCER_RUN_ID, PRODUCER_RUN_ATTEMPT,
  ARTIFACT_DIR, STAGING_DIR, LEDGER_DIR, RUNTIME_DIR,
} = process.env;

if (!GITHUB_TOKEN || !GITHUB_REPOSITORY || !PRODUCER_RUN_ID || !PRODUCER_RUN_ATTEMPT ||
    !ARTIFACT_DIR || !STAGING_DIR || !LEDGER_DIR || !RUNTIME_DIR) {
  console.error('Missing required environment variables');
  process.exit(1);
}

if (!process.env.ACTIONS_ID_TOKEN_REQUEST_URL) {
  console.error('ACTIONS_ID_TOKEN_REQUEST_URL not set — id-token: write permission required');
  process.exit(1);
}

const runId = Number(PRODUCER_RUN_ID);
const runAttempt = Number(PRODUCER_RUN_ATTEMPT);

console.log(`Fetching provenance for run ${runId} attempt ${runAttempt}...`);
const provenanceInput = await fetchProducerProvenance({
  repository: GITHUB_REPOSITORY,
  runId,
  runAttempt,
  token: GITHUB_TOKEN,
});
console.log(`Producer: ${provenanceInput.producer.event} ${provenanceInput.producer.headSha.slice(0, 8)} conclusion=${provenanceInput.producer.conclusion}`);

mkdirSync(STAGING_DIR, { recursive: true });
mkdirSync(LEDGER_DIR, { recursive: true });

console.log(`Validating artifacts from ${ARTIFACT_DIR}...`);
const snapshots = await validateArtifactPayload({
  input: { kind: 'directory', path: ARTIFACT_DIR },
  stagingParent: STAGING_DIR,
  trusted: provenanceInput,
});
console.log(`Validated ${snapshots.invocations.length} invocation(s)`);
for (const inv of snapshots.invocations) {
  console.log(`  ${inv.suite}/${inv.invocation}: ${inv.outcome} (${inv.counts.tests} tests, ${inv.counts.passed} passed, ${inv.counts.failed} failed)`);
}

const auth = {
  githubOidcUrl: process.env.ACTIONS_ID_TOKEN_REQUEST_URL,
  githubOidcToken: process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN ?? '',
};

console.log('Uploading to Flakiness...');
const summary = await executeUpload(
  snapshots,
  { runtimeDir: RUNTIME_DIR, ledgerDir: LEDGER_DIR, timeoutMs: 180_000 },
  auth,
  { enableUpload: true },
);

console.log(`\nUpload summary:`);
for (const r of summary.results) {
  const url = r.receiptUrl ? `  → ${r.receiptUrl}` : '';
  const err = r.error ? `  (${r.error})` : '';
  console.log(`  ${r.suite}: ${r.state}${url}${err}`);
}

// Write receipt URLs to GITHUB_STEP_SUMMARY if available
if (process.env.GITHUB_STEP_SUMMARY) {
  const { writeFileSync } = await import('node:fs');
  const lines = ['## Flakiness Upload Results\n'];
  for (const r of summary.results) {
    if (r.state === 'accepted-unverified' && r.receiptUrl) {
      lines.push(`- ✅ **${r.suite}**: [View on Flakiness](${r.receiptUrl})`);
    } else {
      lines.push(`- ${r.state === 'failed' ? '❌' : '⚠️'} **${r.suite}**: ${r.state}${r.error ? ` — ${r.error}` : ''}`);
    }
  }
  writeFileSync(process.env.GITHUB_STEP_SUMMARY, lines.join('\n') + '\n', { flag: 'a' });
}

if (summary.anyFailed) { console.error('One or more uploads failed'); process.exit(1); }
if (summary.anyAmbiguous) { console.warn('One or more uploads are ambiguous (delivery unconfirmed)'); process.exit(0); }
console.log('All uploads accepted-unverified (delivery confirmed by CLI)');
