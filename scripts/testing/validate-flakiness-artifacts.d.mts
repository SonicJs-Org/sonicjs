/** Trusted adapter output only; not authenticated by this helper. IDs are positive safe integers. */
export interface ProducerProvenanceInput {
  trigger: { repository: string; runId: number; runAttempt: number };
  producer: {
    repository: string; runId: number; runAttempt: number;
    workflowId: number; workflowPath: string; workflowName: string;
    event: string; status: string; conclusion: string | null;
    headBranch: string; headSha: string;
  };
  /** Complete jobs for this exact attempt; key is established by trusted adapter. */
  jobs: Array<{
    id: number; key: string; runId: number; runAttempt: number; status: string;
    steps: Array<{ number: number; name: string; status: string; conclusion: string | null }>;
  }>;
  /** Exactly one original-run association, persisted from trusted original-run metadata. */
  originalPullRequests?: PullRequestIdentity[];
  /** Fresh trusted GitHub PR record; never a replacement for the original snapshot. */
  currentPullRequest?: PullRequestIdentity;
}
export interface PullRequestIdentity {
  number: number;
  baseRepository: string;
  headRepository: string;
  headSha: string;
}
export interface ValidatedProducerProvenance {
  repository: 'SonicJs-Org/sonicjs'; runId: number; runAttempt: number;
  workflowId: 207092903; workflowPath: '.github/workflows/pr-tests.yml'; workflowName: 'PR Tests';
  event: 'push' | 'pull_request_target'; conclusion: 'success' | 'failure';
  testedSha: string; branch: string; pullRequest: PullRequestIdentity | null;
  suites: Array<{
    suite: 'core-unit' | 'cms-e2e'; jobId: number; stepNumber: number;
    conclusion: 'success' | 'failure' | 'skipped'; ran: boolean;
  }>;
  sourceUrl: string;
}
/** Throws Error for rejected / non-publishable provenance. No environment or filesystem effects. */
export function validateProducerProvenance(input: ProducerProvenanceInput): ValidatedProducerProvenance;
