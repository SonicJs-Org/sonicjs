import { validateProducerProvenance } from './validate-flakiness-artifacts.mjs';

/** Fetch bounded, trusted API metadata; never derive history from report artifacts. */
async function ghApi(path, token) {
  const res = await fetch(`https://api.github.com${path}`, {
    signal: AbortSignal.timeout(30_000),
    headers: { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28' },
  });
  if (!res.ok) throw new Error(`GitHub metadata request failed: ${res.status}`);
  return res.json();
}

/**
 * Acquire exact-attempt jobs and immutable authorization-job identity. That job
 * executes only a fixed echo, no checkout, artifacts, dependencies or PR hooks.
 * Its API job name contains the original event's head repository/SHA/PR number,
 * including fork events whose run.pull_requests array is empty. Live PR data is
 * only a consistency check; missing historical identity always fails closed.
 * @param {{repository: string, runId: number, runAttempt: number, token: string}} options
 * @returns {Promise<import('./validate-flakiness-artifacts.mjs').ProducerProvenanceInput>}
 */
export async function fetchProducerProvenance({ repository, runId, runAttempt, token }) {
  if (repository !== 'SonicJs-Org/sonicjs' || !Number.isSafeInteger(runId) || runId <= 0 || !Number.isSafeInteger(runAttempt) || runAttempt <= 0) throw new Error('Invalid producer identity');
  const base = `/repos/${repository}/actions/runs/${runId}`;
  const run = await ghApi(`${base}/attempts/${runAttempt}`, token);
  if (run.id !== runId || run.run_attempt !== runAttempt || run.repository?.full_name !== repository) throw new Error('Run binding mismatch');
  const allJobs = [];
  for (let page = 1; page <= 10; page++) {
    const response = await ghApi(`${base}/attempts/${runAttempt}/jobs?per_page=100&page=${page}`, token);
    if (!Array.isArray(response.jobs) || !Number.isSafeInteger(response.total_count) || response.total_count > 1000) throw new Error('Invalid jobs page');
    allJobs.push(...response.jobs);
    if (allJobs.length === response.total_count) break;
    if (allJobs.length > response.total_count || response.jobs.length === 0 || page === 10) throw new Error('Incomplete jobs metadata');
  }
  if (new Set(allJobs.map(j => j.id)).size !== allJobs.length) throw new Error('Duplicate API jobs');
  for (const job of allJobs) if (job.run_id !== runId || job.run_attempt !== runAttempt) throw new Error('Job attempt mismatch');
  const authorization = allJobs.filter(j => j.name.startsWith('authorize:'));
  if (authorization.length !== 1 || authorization[0].status !== 'completed' || authorization[0].conclusion !== 'success') throw new Error('Missing immutable authorization identity');
  const match = /^authorize:([1-9]\d*):([1-9]\d*):(push|pull_request_target):(0|[1-9]\d*):([A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+):([a-f0-9]{40})$/.exec(authorization[0].name);
  if (!match || Number(match[1]) !== runId || Number(match[2]) !== runAttempt || match[3] !== run.event) throw new Error('Authorization identity mismatch');
  const [, , , event, number, headRepository, headSha] = match;
  let originalPullRequests, currentPullRequest;
  if (event === 'push') {
    if (number !== '0' || headRepository !== repository || headSha !== run.head_sha) throw new Error('Push authorization mismatch');
  } else {
    if (number === '0') throw new Error('Missing historical PR number');
    const original = { number: Number(number), baseRepository: repository, headRepository, headSha };
    // Associations, when available, must agree; never substitute live head fields.
    const associations = run.pull_requests;
    if (!Array.isArray(associations) || associations.length > 1) throw new Error('Ambiguous PR association');
    for (const pr of associations) {
      if (pr.number !== original.number || pr.head?.sha !== headSha ||
          (pr.head?.repo?.full_name && pr.head.repo.full_name !== headRepository)) throw new Error('Historical PR association mismatch');
    }
    const live = await ghApi(`/repos/${repository}/pulls/${number}`, token);
    originalPullRequests = [original];
    currentPullRequest = { number: live.number, baseRepository: live.base?.repo?.full_name ?? '', headRepository: live.head?.repo?.full_name ?? '', headSha: live.head?.sha ?? '' };
  }
  const jobs = [];
  for (const j of allJobs) {
    const shard = /^e2e-shard \(([1-4])\)$/.exec(j.name);
    if (!shard && !['unit-tests', 'e2e-local', 'e2e-locked', 'e2e-shard'].includes(j.name)) continue;
    jobs.push({ id: j.id, key: shard ? 'e2e-shard' : j.name, ...(shard ? { shard: `${shard[1]}-of-4` } : {}), runId, runAttempt, status: j.status, conclusion: j.conclusion, steps: j.steps ?? [] });
  }
  const input = {
    trigger: { repository, runId, runAttempt },
    producer: { repository: run.repository.full_name, runId: run.id, runAttempt: run.run_attempt, workflowId: run.workflow_id, workflowPath: run.path, workflowName: run.name, event: run.event, status: run.status, conclusion: run.conclusion, headBranch: run.head_branch, headSha: run.head_sha },
    jobs,
    ...(originalPullRequests ? { originalPullRequests, currentPullRequest } : {}),
  };
  validateProducerProvenance(input);
  return input;
}
