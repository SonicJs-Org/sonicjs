import { describe, expect, it } from 'vitest'
import { validateProducerProvenance, type ProducerProvenanceInput } from '../../scripts/testing/validate-flakiness-artifacts.mjs'

// Sanitized synthetic fixtures; these are not captured GitHub service evidence.
const sha = 'a'.repeat(40)
function fixture(): ProducerProvenanceInput {
  return {
    trigger: { repository: 'SonicJs-Org/sonicjs', runId: 123, runAttempt: 2 },
    producer: {
      repository: 'SonicJs-Org/sonicjs', runId: 123, runAttempt: 2,
      workflowId: 207092903, workflowPath: '.github/workflows/pr-tests.yml', workflowName: 'PR Tests',
      event: 'push', status: 'completed', conclusion: 'success', headBranch: 'main', headSha: sha,
    },
    jobs: [{ id: 456, key: 'test', runId: 123, runAttempt: 2, status: 'completed', steps: [
      { number: 4, name: 'Run unit tests with coverage', status: 'completed', conclusion: 'success' },
      { number: 7, name: 'Run full E2E regression suite', status: 'completed', conclusion: 'failure' },
    ] }],
  }
}

describe('trusted producer provenance', () => {
  it('returns canonical push identity, trusted suite outcomes and attempt-specific source', () => {
    expect(validateProducerProvenance(fixture())).toEqual({
      repository: 'SonicJs-Org/sonicjs', runId: 123, runAttempt: 2,
      workflowId: 207092903, workflowPath: '.github/workflows/pr-tests.yml', workflowName: 'PR Tests',
      event: 'push', conclusion: 'success', testedSha: sha, branch: 'main', pullRequest: null,
      suites: [
        { suite: 'core-unit', jobId: 456, stepNumber: 4, conclusion: 'success', ran: true },
        { suite: 'cms-e2e', jobId: 456, stepNumber: 7, conclusion: 'failure', ran: true },
      ],
      sourceUrl: 'https://github.com/SonicJs-Org/sonicjs/actions/runs/123/attempts/2',
    })
  })
})

const invalidCases: Array<[string, (input: ProducerProvenanceInput) => void]> = [
  ['trigger repository', x => { x.trigger.repository = 'other/repo' }],
  ['producer repository case', x => { x.producer.repository = 'sonicjs-org/sonicjs' }],
  ['run mismatch', x => { x.trigger.runId++ }],
  ['attempt mismatch', x => { x.trigger.runAttempt++ }],
  ['workflow ID', x => { x.producer.workflowId++ }],
  ['workflow path', x => { x.producer.workflowPath = 'other.yml' }],
  ['workflow name', x => { x.producer.workflowName = 'Other' }],
  ['zero run ID', x => { x.producer.runId = 0 }],
  ['fractional attempt', x => { x.trigger.runAttempt = 1.5 }],
  ['unsafe ID', x => { x.trigger.runId = Number.MAX_SAFE_INTEGER + 1 }],
  ['malformed SHA', x => { x.producer.headSha = 'abc' }],
  ['SHA whitespace', x => { x.producer.headSha = ` ${sha}` }],
  ['forbidden branch', x => { x.producer.headBranch = 'feature/123' }],
  ['unsupported event', x => { x.producer.event = 'pull_request' }],
  ...['cancelled', 'skipped', 'neutral', null].map((outcome): [string, (x: ProducerProvenanceInput) => void] =>
    [`run conclusion ${outcome}`, x => { x.producer.conclusion = outcome }]),
  ['in progress', x => { x.producer.status = 'in_progress' }],
  ['missing job', x => { x.jobs = [] }],
  ['unknown job', x => { x.jobs[0]!.key = 'build' }],
  ['duplicate job', x => { x.jobs.push(structuredClone(x.jobs[0]!)) }],
  ['job run mismatch', x => { x.jobs[0]!.runId++ }],
  ['job attempt mismatch', x => { x.jobs[0]!.runAttempt++ }],
  ['bad job ID', x => { x.jobs[0]!.id = -1 }],
  ['unfinished job', x => { x.jobs[0]!.status = 'queued' }],
  ['missing step', x => { x.jobs[0]!.steps.pop() }],
  ['duplicate step name', x => { x.jobs[0]!.steps.push({ ...x.jobs[0]!.steps[0]!, number: 9 }) }],
  ['duplicate step number', x => { x.jobs[0]!.steps[1]!.number = 4 }],
  ['invalid step number', x => { x.jobs[0]!.steps[0]!.number = 0 }],
  ['unknown suite step', x => { x.jobs[0]!.steps[0]!.name = 'Run unknown tests' }],
  ['unfinished step', x => { x.jobs[0]!.steps[0]!.status = 'in_progress' }],
  ['missing step conclusion', x => { x.jobs[0]!.steps[0]!.conclusion = null }],
  ['cancelled step', x => { x.jobs[0]!.steps[0]!.conclusion = 'cancelled' }],
]
it.each(invalidCases)('rejects %s', (_label, change) => {
  const input = fixture()
  change(input)
  expect(() => validateProducerProvenance(input)).toThrow()
})
it('preserves skipped suites as not run and ignores unrelated build steps', () => {
  const input = fixture()
  input.producer.conclusion = 'failure'
  input.jobs[0]!.steps[0]!.conclusion = 'skipped'
  input.jobs[0]!.steps.push({ number: 10, name: 'Build', status: 'completed', conclusion: 'failure' })
  const result = validateProducerProvenance(input)
  expect(result.suites).toHaveLength(2)
  expect(result.suites[0]).toMatchObject({ conclusion: 'skipped', ran: false })
})

function prFixture(headRepository = 'SonicJs-Org/sonicjs'): ProducerProvenanceInput {
  const input = fixture()
  input.producer.event = 'pull_request_target'
  input.producer.headSha = 'b'.repeat(40) // Base SHA must never become tested checkout.
  input.originalPullRequests = [{ number: 42, baseRepository: 'SonicJs-Org/sonicjs', headRepository, headSha: sha }]
  input.currentPullRequest = structuredClone(input.originalPullRequests[0]!)
  return input
}
it.each(['SonicJs-Org/sonicjs', 'Contributor/sonicjs', 'dependabot/sonicjs'])('binds PR head from %s without actor privilege', repo => {
  const input = prFixture(repo)
  const before = structuredClone(input)
  const result = validateProducerProvenance(input)
  expect(result.testedSha).toBe(sha)
  expect(result.pullRequest).toEqual(input.originalPullRequests![0])
  expect(result.pullRequest).not.toBe(input.originalPullRequests![0])
  expect(input).toEqual(before)
})
const invalidPrCases: Array<[string, (x: ProducerProvenanceInput) => void]> = [
  ['missing historical snapshot', x => { delete x.originalPullRequests }],
  ['empty association', x => { x.originalPullRequests = [] }],
  ['ambiguous association', x => { x.originalPullRequests!.push({ ...x.originalPullRequests![0]! }) }],
  ['missing current PR', x => { delete x.currentPullRequest }],
  ['stale head', x => { x.currentPullRequest!.headSha = 'c'.repeat(40) }],
  ['different PR', x => { x.currentPullRequest!.number++ }],
  ['different head repository', x => { x.currentPullRequest!.headRepository = 'Other/sonicjs' }],
  ['base repository mismatch', x => { x.originalPullRequests![0]!.baseRepository = 'Other/sonicjs' }],
  ['current base mismatch', x => { x.currentPullRequest!.baseRepository = 'Other/sonicjs' }],
  ['invalid PR number', x => { x.originalPullRequests![0]!.number = 0 }],
  ['invalid historical SHA', x => { x.originalPullRequests![0]!.headSha = 'bad' }],
  ['missing head repository', x => { x.originalPullRequests![0]!.headRepository = '' }],
  ['malformed repository', x => { x.originalPullRequests![0]!.headRepository = '../sonicjs' }],
]
it.each(invalidPrCases)('rejects PR %s', (_label, change) => {
  const input = prFixture()
  change(input)
  expect(() => validateProducerProvenance(input)).toThrow()
})
it.each(['v3', 'test/e2e-infrastructure-hardening'])('allows push branch %s', branch => {
  const input = fixture()
  input.producer.headBranch = branch
  expect(validateProducerProvenance(input).branch).toBe(branch)
})
