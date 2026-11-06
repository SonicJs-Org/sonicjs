/**
 * Fetch GitHub API metadata for a workflow_run and build a ProducerProvenanceInput.
 * Uses the GITHUB_TOKEN (actions: read) — no Flakiness credentials needed here.
 *
 * Handles both push (headSha = run head_sha) and pull_request_target
 * (headSha = PR head from original PR snapshot; run head_sha is the merge commit).
 */

const GITHUB_API = 'https://api.github.com';

/**
 * @param {string} path
 * @param {string} token
 * @returns {Promise<unknown>}
 */
async function ghApi(path, token) {
  const res = await fetch(`${GITHUB_API}${path}`, {
    headers: { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28' },
  });
  if (!res.ok) throw new Error(`GitHub API ${path} → ${res.status} ${res.statusText}: ${await res.text().catch(() => '')}`);
  return res.json();
}

/**
 * Build ProducerProvenanceInput from a completed workflow_run event context.
 * @param {{
 *   repository: string,
 *   runId: number,
 *   runAttempt: number,
 *   token: string,
 * }} options
 * @returns {Promise<import('./validate-flakiness-artifacts.mjs').ProducerProvenanceInput>}
 */
export async function fetchProducerProvenance({ repository, runId, runAttempt, token }) {
  const run = /** @type {any} */ (await ghApi(`/repos/${repository}/actions/runs/${runId}`, token));
  if (run.run_attempt !== runAttempt) throw new Error(`Run attempt mismatch: expected ${runAttempt}, got ${run.run_attempt}`);

  const jobsResp = /** @type {any} */ (await ghApi(`/repos/${repository}/actions/runs/${runId}/attempts/${runAttempt}/jobs`, token));
  const allJobs = /** @type {any[]} */ (jobsResp.jobs ?? []);

  // Find the 'test' job (YAML job key; display name matches key when no 'name:' override)
  const testJob = allJobs.find(j => j.name === 'test');
  if (!testJob) throw new Error(`No 'test' job found in run ${runId} attempt ${runAttempt}. Jobs: ${allJobs.map(j => j.name).join(', ')}`);

  const steps = /** @type {any[]} */ (testJob.steps ?? []).map(s => ({
    number: s.number,
    name: s.name,
    status: s.status,
    conclusion: s.conclusion ?? null,
  }));

  const producerJob = {
    id: testJob.id,
    key: 'test',
    runId,
    runAttempt,
    status: testJob.status,
    steps,
  };

  // For pull_request_target, resolve the actual tested PR head SHA from the PR list.
  // workflow_run.head_sha for pull_request_target is the merge commit, not the PR head.
  let originalPullRequests;
  let currentPullRequest;

  if (run.event === 'pull_request_target') {
    const prs = /** @type {any[]} */ (run.pull_requests ?? []);
    if (prs.length !== 1) throw new Error(`Expected exactly 1 PR association for pull_request_target run ${runId}, got ${prs.length}`);
    const pr = prs[0];
    const prNumber = pr.number;
    // Fetch current live PR state for consistency check
    const livePr = /** @type {any} */ (await ghApi(`/repos/${repository}/pulls/${prNumber}`, token));
    const prIdentity = {
      number: prNumber,
      baseRepository: repository,
      headRepository: livePr.head.repo?.full_name ?? repository,
      headSha: pr.head.sha, // from run.pull_requests (original association)
    };
    originalPullRequests = [prIdentity];
    currentPullRequest = {
      number: prNumber,
      baseRepository: repository,
      headRepository: livePr.head.repo?.full_name ?? repository,
      headSha: livePr.head.sha, // current live head
    };
  }

  return {
    trigger: { repository, runId, runAttempt },
    producer: {
      repository,
      runId,
      runAttempt,
      workflowId: run.workflow_id,
      workflowPath: run.path,
      workflowName: run.name,
      event: run.event,
      status: run.status,
      conclusion: run.conclusion ?? null,
      headBranch: run.head_branch ?? '',
      headSha: run.head_sha,
    },
    jobs: [producerJob],
    ...(originalPullRequests ? { originalPullRequests, currentPullRequest } : {}),
  };
}
