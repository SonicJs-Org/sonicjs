/** Trusted adapter output only; not authenticated by this helper. IDs are positive safe integers. */
export interface ProducerProvenanceInput {
  trigger: { repository: string; runId: number; runAttempt: number };
  producer: {
    repository: string; runId: number; runAttempt: number;
    workflowId: number; workflowPath: string; workflowName: string;
    event: string; status: string; conclusion: string | null;
    headBranch: string; headSha: string;
  };
  /** Only declared producing jobs (currently test), filtered by trusted adapter; not all API jobs. */
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
export const ARTIFACT_LIMITS: Readonly<{ reportBytes: number; manifestBytes: number; fileBytes: number; totalBytes: number; files: number; depth: number; nodes: number; stringBytes: number; invocations: number }>;
export function validateNativeReport(bytes: Buffer): NativeReport;
export interface ArtifactInput { kind: 'directory' | 'zip'; path: string }
export interface ArtifactValidationInput {
  input: ArtifactInput | readonly ArtifactInput[];
  /** Existing private, owned directory outside the input; no temporary fallback. */
  stagingParent: string;
  trusted: ProducerProvenanceInput;
}
export interface SnapshotFile { readonly path: string; readonly bytes: number; readonly sha256: string }
export interface UploadSnapshot {
  readonly id: string;
  readonly suite: 'core-unit' | 'cms-e2e'; readonly invocation: string;
  readonly jobId: number; readonly stepNumber: number;
  readonly reportPath: string; readonly manifestPath: string;
  readonly outcome: 'passed' | 'failed';
  readonly counts: Readonly<{ tests: number; attempts: number; passed: number; failed: number; skipped: number; suiteErrors: number }>;
  readonly files: readonly SnapshotFile[];
}
export interface ArtifactSnapshots {
  readonly root: string;
  readonly provenance: DeepReadonly<ValidatedProducerProvenance>;
  readonly invocations: readonly UploadSnapshot[];
}
/** Validates all evidence before returning any snapshots. Throws and cleans private staging on failure. */
export function validateArtifactPayload(input: ArtifactValidationInput): Promise<ArtifactSnapshots>;
/** Must be called immediately before each future child read. Rechecks owned files and complete tree. */
export function verifyUploadSnapshots(snapshots: ArtifactSnapshots): Promise<void>;

type ParsedReport = import('zod/v4').infer<typeof import('@flakiness/flakiness-report').Schema.Report>;
type ParsedSuite = import('zod/v4').infer<typeof import('@flakiness/flakiness-report').Schema.Suite>;
type ParsedTest = import('zod/v4').infer<typeof import('@flakiness/flakiness-report').Schema.Test>;
type ParsedAttempt = import('zod/v4').infer<typeof import('@flakiness/flakiness-report').Schema.RunAttempt>;
type ParsedStep = import('zod/v4').infer<typeof import('@flakiness/flakiness-report').Schema.TestStep>;
// Package's generated recursive Zod declarations widen children to Record<string, unknown>.
// Runtime Schema.Report validates those children; restore their structural public types here.
export type NativeReport = Omit<ParsedReport, 'suites' | 'tests'> & { suites?: NativeSuite[]; tests?: NativeTest[] };
export type NativeSuite = Omit<ParsedSuite, 'suites' | 'tests'> & { suites?: NativeSuite[]; tests?: NativeTest[] };
export type NativeTest = Omit<ParsedTest, 'attempts'> & { attempts: NativeAttempt[] };
export type NativeAttempt = Omit<ParsedAttempt, 'steps'> & { steps?: NativeStep[] };
export type NativeStep = Omit<ParsedStep, 'steps'> & { steps?: NativeStep[] };
export type NativeAttachment = import('zod/v4').infer<typeof import('@flakiness/flakiness-report').Schema.Attachment>;

export type DeepReadonly<T> = T extends object ? { readonly [K in keyof T]: DeepReadonly<T[K]> } : T;
