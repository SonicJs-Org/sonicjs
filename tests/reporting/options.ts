import { execFileSync } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import type { ReporterDescription } from '@playwright/test'
import type PlaywrightReporter from '@flakiness/playwright'

export const repositoryRoot = fileURLToPath(new URL('../..', import.meta.url)).replace(/\/$/, '')
export const reportingSuites = [
  'core-unit', 'sdk-unit', 'root-unit', 'cms-e2e', 'cms-smoke', 'www-e2e',
  'runner-contracts', 'reporting-contracts', 'create-app-cli', 'sample-unit',
] as const
export const reportingTargets = ['local-worker', 'preview-worker', 'www', 'none'] as const
export type ReportingSuite = typeof reportingSuites[number]
export type ReportingTarget = typeof reportingTargets[number]
export type ReportingEnvironment = Readonly<Record<string, string | undefined>>
type PlaywrightOptions = NonNullable<ConstructorParameters<typeof PlaywrightReporter>[0]>

// The Vitest package ships JS only. These fields were reviewed against 1.12.0.
export type VitestReporterOptions = {
  flakinessProject?: string
  outputFolder: string
  disableUpload: boolean
  commitId: string
}
export interface InvocationManifest {
  suite: ReportingSuite
  target: ReportingTarget
  source: 'local' | 'ci'
  invocation: string
  commit: string
  startedAt: string
  endedAt?: string
  outcome?: 'passed' | 'failed' | 'interrupted'
  runId?: string
  attempt?: string
  job?: string
  shard?: string
  /** Self-reported producer data; not trusted provenance. */
  pullRequest?: string
  pullRequestStatus: 'associated' | 'no-pr' | 'missing' | 'malformed'
  pullRequestSource?: 'override' | 'event' | 'ref'
  workflow?: string
  runURL?: string
  targetURL?: string
}
export interface ReportingOptions {
  /** Archive this root to retain lifecycle metadata and vendor evidence. */
  invocationFolder: string
  /** Official reporter output only; vendor may recursively clean this directory. */
  outputFolder: string
  playwright: ['@flakiness/playwright', PlaywrightOptions]
  vitest: {
    includeTaskLocation: true
    reporters: ['default', ['@flakiness/vitest', VitestReporterOptions]]
  }
  /** Apply at the runner integration boundary; factories never mutate process.env. */
  environment: { FK_ENV_SUITE: ReportingSuite; FK_ENV_TARGET: ReportingTarget; FK_ENV_SOURCE: 'local' | 'ci' }
  manifest: InvocationManifest
  notice?: string
}

const ciFlags = ['CI', 'GITHUB_ACTIONS', 'GITLAB_CI', 'TF_BUILD', 'CIRCLECI', 'BUILDKITE', 'TRAVIS']
const ciContexts = ['GITHUB_RUN_ID', 'GITHUB_REPOSITORY', 'ACTIONS_ID_TOKEN_REQUEST_URL',
  'ACTIONS_ID_TOKEN_REQUEST_TOKEN', 'CI_JOB_URL', 'CI_JOB_ID', 'BUILD_URL', 'BUILD_BUILDID', 'JENKINS_URL']
const present = (value: string | undefined): boolean => Boolean(value?.trim())
const enabledFlag = (value: string | undefined): boolean => present(value) && !['false', '0', 'no'].includes(value!.trim().toLowerCase())
const segment = (value: string | undefined): string => (value ?? 'local').replace(/[^a-zA-Z0-9_-]/g, '-').slice(0, 80)

export function sanitizeURL(value?: string): string | undefined {
  if (!value) return undefined
  const url = new URL(value)
  if (!['http:', 'https:'].includes(url.protocol)) throw new Error('Unsupported target URL protocol')
  url.username = ''
  url.password = ''
  url.search = ''
  url.hash = ''
  return url.toString()
}

/** Reporting metadata only; does not control remote-preview execution policy. */
export function cmsReportingTarget(env: ReportingEnvironment): 'local-worker' | 'preview-worker' {
  if (!env.BASE_URL) return 'local-worker'
  try {
    const url = new URL(env.BASE_URL)
    return ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname.toLowerCase())
      ? 'local-worker' : 'preview-worker'
  } catch {
    // Metadata must not add URL validation to existing runner configuration.
    return 'preview-worker'
  }
}

const positiveNumber = (value: unknown): string | undefined => {
  if (typeof value !== 'string' && typeof value !== 'number') return undefined
  const text = String(value)
  return /^[1-9]\d*$/.test(text) && Number.isSafeInteger(Number(text)) ? text : undefined
}

/** Allowlisted event fields only. Never retain payload, path, or parse errors. */
function pullRequestMetadata(env: ReportingEnvironment): Pick<InvocationManifest,
  'pullRequest' | 'pullRequestStatus' | 'pullRequestSource'> {
  const override = positiveNumber(env.GITHUB_EVENT_NUMBER)
  if (override) return { pullRequest: override, pullRequestStatus: 'associated', pullRequestSource: 'override' }
  const isPR = ['pull_request', 'pull_request_target'].includes(env.GITHUB_EVENT_NAME ?? '')
  let status: InvocationManifest['pullRequestStatus'] = isPR ? 'missing' : 'no-pr'
  if (isPR && env.GITHUB_EVENT_PATH) {
    try {
      const event: unknown = JSON.parse(readFileSync(env.GITHUB_EVENT_PATH, 'utf8'))
      const pr = event && typeof event === 'object' && 'pull_request' in event ? event.pull_request : undefined
      const number = pr && typeof pr === 'object' && 'number' in pr ? positiveNumber(pr.number) : undefined
      if (number) return { pullRequest: number, pullRequestStatus: 'associated', pullRequestSource: 'event' }
      status = 'malformed'
    } catch (error) {
      status = (error as NodeJS.ErrnoException).code === 'ENOENT' ? 'missing' : 'malformed'
    }
  }
  const ref = env.GITHUB_REF?.match(/^refs\/pull\/([1-9]\d*)\/(?:merge|head)$/)
  const number = positiveNumber(ref?.[1])
  if (number && (isPR || !env.GITHUB_EVENT_NAME))
    return { pullRequest: number, pullRequestStatus: 'associated', pullRequestSource: 'ref' }
  return { pullRequestStatus: status }
}

function githubRunURL(env: ReportingEnvironment): string | undefined {
  if (!env.GITHUB_SERVER_URL || !/^[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+$/.test(env.GITHUB_REPOSITORY ?? '') ||
    !positiveNumber(env.GITHUB_RUN_ID)) return undefined
  try {
    const url = new URL(env.GITHUB_SERVER_URL)
    if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash || url.pathname !== '/') return undefined
    return `${url.origin}/${env.GITHUB_REPOSITORY}/actions/runs/${env.GITHUB_RUN_ID}`
  } catch { return undefined }
}

/** One call per actual runner invocation, including each watch rerun (Task 3/4 wiring). */
export function createReportingOptions(input: {
  suite: ReportingSuite
  target: ReportingTarget
  env?: ReportingEnvironment
  targetURL?: string
}): ReportingOptions {
  if (!reportingSuites.includes(input.suite)) throw new Error('Unsupported reporting suite')
  if (!reportingTargets.includes(input.target)) throw new Error('Unsupported reporting target')
  const env = input.env ?? process.env
  const isCI = ciFlags.some(key => enabledFlag(env[key])) || ciContexts.some(key => present(env[key]))
  const source = isCI ? 'ci' : 'local'
  const disableUpload = isCI || env.SONICJS_TEST_UPLOAD !== '1' ||
    !present(env.FLAKINESS_ACCESS_TOKEN) || !present(env.FLAKINESS_PROJECT)
  const invocation = `${segment(env.GITHUB_JOB)}-${segment(env.SONICJS_TEST_SHARD)}-${segment(env.GITHUB_RUN_ATTEMPT)}-${randomUUID()}`
  const invocationFolder = join(repositoryRoot, 'flakiness-reports', input.suite, invocation)
  const outputFolder = join(invocationFolder, 'vendor')
  // Never use GITHUB_SHA: pull_request_target can check out a different commit.
  const commit = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: repositoryRoot, encoding: 'utf8' }).trim()
  const common = { flakinessProject: env.FLAKINESS_PROJECT?.trim() || undefined, outputFolder, disableUpload }
  return {
    invocationFolder,
    outputFolder,
    playwright: ['@flakiness/playwright', { ...common, open: 'never' }],
    vitest: { includeTaskLocation: true, reporters: ['default', ['@flakiness/vitest', { ...common, commitId: commit }]] },
    environment: { FK_ENV_SUITE: input.suite, FK_ENV_TARGET: input.target, FK_ENV_SOURCE: source },
    manifest: {
      suite: input.suite, target: input.target, source, invocation, commit,
      startedAt: new Date().toISOString(), runId: env.GITHUB_RUN_ID,
      attempt: env.GITHUB_RUN_ATTEMPT, job: env.GITHUB_JOB, shard: env.SONICJS_TEST_SHARD,
      ...pullRequestMetadata(env),
      workflow: /^[a-zA-Z0-9 _()./-]{1,200}$/.test(env.GITHUB_WORKFLOW ?? '') ? env.GITHUB_WORKFLOW : undefined,
      runURL: githubRunURL(env), targetURL: sanitizeURL(input.targetURL),
    },
    notice: disableUpload ? '[flakiness] Upload disabled; local reports enabled.' : undefined,
  }
}

/** Integration calls at start/end. Errors propagate; shared report root is never cleaned. */
export function writeInvocationManifest(options: ReportingOptions, completion?: {
  outcome: NonNullable<InvocationManifest['outcome']>
}): void {
  const manifest = completion
    ? { ...options.manifest, endedAt: new Date().toISOString(), outcome: completion.outcome }
    : options.manifest
  mkdirSync(options.invocationFolder, { recursive: true })
  mkdirSync(options.outputFolder, { recursive: true })
  writeFileSync(join(options.invocationFolder, 'invocation.json'), `${JSON.stringify(manifest, null, 2)}\n`)
}

/** Task 4 calls after collection, before the vendor can rename/fail duplicate records. */
export function assertUniqueTestNames(tests: readonly {
  project: string; file: string; fullName: string
}[]): void {
  const seen = new Set<string>()
  for (const test of tests) {
    const identity = JSON.stringify([test.project, test.file, test.fullName])
    if (seen.has(identity)) throw new Error(`Duplicate full test name: ${test.fullName} (${test.file}, ${test.project})`)
    seen.add(identity)
  }
}

/** Config evaluation is side-effect free on disk. List mode must never emit run reports.
 * Inherited configs may replace this tuple; only the effective tuple is instantiated.
 */
export function playwrightReporting(suite: ReportingSuite, target: ReportingTarget): ReporterDescription[] {
  if (process.argv.includes('--list')) return []
  const options = createReportingOptions({ suite, target })
  Object.assign(process.env, options.environment)
  return [[fileURLToPath(new URL('./playwright-metadata.ts', import.meta.url)), { reporting: options }], options.playwright]
}
