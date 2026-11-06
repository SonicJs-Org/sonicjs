/**
 * Pure provenance policy, not an artifact validator or authentication mechanism.
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
  const numbers = new Set();
  const names = new Set();
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
