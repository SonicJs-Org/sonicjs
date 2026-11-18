import { execFileSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { expect, test } from 'vitest'
import { cmsReportingTarget, createReportingOptions, repositoryRoot } from './options'

const fixture = (name: string) => fileURLToPath(new URL(`./fixtures/${name}`, import.meta.url))
const manifest = (env: Record<string, string | undefined>) => createReportingOptions({ suite: 'cms-e2e', target: 'local-worker', env }).manifest

test.each([
  ['/', 'preview-worker'], [undefined, 'local-worker'], ['http://localhost:8787', 'local-worker'],
  ['https://localhost:8787', 'local-worker'], ['http://127.0.0.1:8787', 'local-worker'],
  ['http://[::1]:8787', 'local-worker'], ['http://[0:0:0:0:0:0:0:1]:8787', 'local-worker'],
  ['https://preview.example.invalid', 'preview-worker'],
] as const)('CMS metadata target %s', (BASE_URL, target) => {
  expect(cmsReportingTarget({ BASE_URL })).toBe(target)
})

test.each([undefined, 'http://127.0.0.1:8787', 'http://[::1]:8787', 'https://preview.example.invalid'])('base/smoke/no-server metadata inheritance %s', async BASE_URL => {
  const output = execFileSync(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', `
    import main from './tests/playwright.config.ts'
    import smoke from './tests/playwright.smoke.config.ts'
    import noServer from './tests/playwright-no-server.config.ts'
    console.log(JSON.stringify({
      targets: [main, smoke, noServer].map(config => config.reporter.find(r => r[1]?.reporting)?.[1].reporting.manifest.target),
      inherited: noServer.reporter === main.reporter,
    }))
  `], { cwd: repositoryRoot, encoding: 'utf8',
    env: { PATH: process.env.PATH, ...(BASE_URL ? { BASE_URL } : {}) } })
  expect(JSON.parse(output)).toEqual({
    targets: Array(3).fill(BASE_URL?.startsWith('https://preview') ? 'preview-worker' : 'local-worker'),
    inherited: true,
  })
})

test.each(['pull_request', 'pull_request_target'])('standard %s payload, workflow and git HEAD', GITHUB_EVENT_NAME => {
  const result = manifest({ GITHUB_EVENT_NAME, GITHUB_EVENT_PATH: fixture('pr-event.json'),
    GITHUB_SHA: 'wrong', GITHUB_WORKFLOW: 'PR tests', GITHUB_SERVER_URL: 'https://github.com',
    GITHUB_REPOSITORY: 'example/repo', GITHUB_RUN_ID: '123' })
  expect(result).toMatchObject({ pullRequest: '42', pullRequestStatus: 'associated', pullRequestSource: 'event',
    workflow: 'PR tests', runURL: 'https://github.com/example/repo/actions/runs/123' })
  expect(result.commit).toBe(execFileSync('git', ['rev-parse', 'HEAD'], { cwd: repositoryRoot, encoding: 'utf8' }).trim())
  expect(JSON.stringify(result)).not.toMatch(/wrong|private|token|GITHUB_EVENT_PATH/)
})

test.each([
  [{ GITHUB_EVENT_NAME: 'pull_request', GITHUB_REF: 'refs/pull/51/merge' }, '51', 'associated', 'ref'],
  [{ GITHUB_EVENT_NAME: 'push', GITHUB_REF: 'refs/heads/fix-51' }, undefined, 'no-pr', undefined],
  [{ GITHUB_EVENT_NAME: 'pull_request' }, undefined, 'missing', undefined],
  [{ GITHUB_EVENT_NAME: 'pull_request', GITHUB_EVENT_PATH: fixture('missing-event.json') }, undefined, 'missing', undefined],
  [{ GITHUB_EVENT_NAME: 'pull_request', GITHUB_EVENT_PATH: fixture('malformed-event.txt') }, undefined, 'malformed', undefined],
  [{ GITHUB_EVENT_NAME: 'pull_request', GITHUB_EVENT_PATH: fixture('invalid-pr-event.json') }, undefined, 'malformed', undefined],
  [{ GITHUB_EVENT_NUMBER: '7', GITHUB_EVENT_NAME: 'push' }, '7', 'associated', 'override'],
  ...['0', '-1', '1.5', 'NaN', '9007199254740992', '42?token=private'].map(GITHUB_EVENT_NUMBER =>
    [{ GITHUB_EVENT_NUMBER }, undefined, 'no-pr', undefined] as const),
] as const)('PR metadata %j', (env, pullRequest, pullRequestStatus, pullRequestSource) => {
  const result = manifest(env)
  expect(result.pullRequest).toBe(pullRequest)
  expect(result.pullRequestStatus).toBe(pullRequestStatus)
  expect(result.pullRequestSource).toBe(pullRequestSource)
})

test('invalid run URL inputs remain absent; metadata never adds history dimensions', () => {
  const result = createReportingOptions({ suite: 'cms-e2e', target: 'local-worker', env: {
    GITHUB_WORKFLOW: 'PR tests', GITHUB_SERVER_URL: 'https://user:private@github.com/?token=private',
    GITHUB_REPOSITORY: 'example/repo', GITHUB_RUN_ID: '1',
  } })
  expect(result.manifest.runURL).toBeUndefined()
  expect(Object.keys(result.environment).sort()).toEqual(['FK_ENV_SOURCE', 'FK_ENV_SUITE', 'FK_ENV_TARGET'])
})
