import { expect, test } from 'vitest'
import { writeFileSync, cpSync } from 'node:fs'
import { join } from 'node:path'
import { beginDeliveryAttempt, finishDeliveryAttempt } from '../../scripts/testing/delivery-ledger.mjs'
import { reportingScratch } from './scratch'

/** Each directory models a fresh hosted runner; only immutable ledger artifacts survive. */
function options(attempt = 1) { return { ledgerDir: reportingScratch('ledger-'), producerRunId: 123, producerAttempt: 2, consumerRunId: 900, consumerAttempt: attempt } }
test('fresh runner with no prior checkpoint fails closed on upload-only rerun', async () => {
  await expect(beginDeliveryAttempt(options(2))).rejects.toThrow()
})
test('completed preflight failure can retry from persisted empty ledger without rerunning producer', async () => {
  const first = options()
  await beginDeliveryAttempt(first)
  await finishDeliveryAttempt(first)
  const rerun = options(2)
  cpSync(first.ledgerDir, rerun.ledgerDir, { recursive: true })
  await expect(beginDeliveryAttempt(rerun)).resolves.toBeUndefined()
})
test('restored ledger retains submitted states and removes seal before work; abrupt loss fails closed', async () => {
  const first = options()
  await beginDeliveryAttempt(first)
  writeFileSync(join(first.ledgerDir, 'entry.json'), '{"state":"started"}')
  await finishDeliveryAttempt(first)
  const second = options(2)
  cpSync(first.ledgerDir, second.ledgerDir, { recursive: true })
  await beginDeliveryAttempt(second)
  const third = options(3)
  cpSync(second.ledgerDir, third.ledgerDir, { recursive: true })
  await expect(beginDeliveryAttempt(third)).rejects.toThrow()
})
test('checkpoint cannot be substituted from another producer or consumer run', async () => {
  const first = options()
  await beginDeliveryAttempt(first); await finishDeliveryAttempt(first)
  const second = options(2); cpSync(first.ledgerDir, second.ledgerDir, { recursive: true })
  await expect(beginDeliveryAttempt({ ...second, producerRunId: 124 })).rejects.toThrow()
  await expect(beginDeliveryAttempt({ ...second, consumerRunId: 901 })).rejects.toThrow()
})


test('safe export includes only regular checkpoint/hash JSON records, never recursive or token files', async () => {
  const { mkdirSync, symlinkSync, readdirSync, readFileSync, linkSync } = await import('node:fs')
  const { exportDeliveryLedger } = await import('../../scripts/testing/export-flakiness-ledger.mjs')
  const first = options()
  await beginDeliveryAttempt(first); await finishDeliveryAttempt(first)
  const record = `${'a'.repeat(64)}.json`
  writeFileSync(join(first.ledgerDir, record), '{"state":"started"}')
  const privateDir = reportingScratch('private-')
  writeFileSync(join(privateDir, 'token.json'), 'FAKE-CREDENTIAL')
  for (const name of ['cli-home-abandoned', 'cli-tmp-abandoned', `${'b'.repeat(64)}.json`]) {
    mkdirSync(join(first.ledgerDir, name))
    writeFileSync(join(first.ledgerDir, name, 'token.json'), 'FAKE-CREDENTIAL')
  }
  for (const name of ['token.json', 'config.json', 'checkpoint.json.new', `${record}.tmp.1234`]) writeFileSync(join(first.ledgerDir, name), 'FAKE-CREDENTIAL')
  symlinkSync(join(privateDir, 'token.json'), join(first.ledgerDir, `${'c'.repeat(64)}.json`))
  linkSync(join(privateDir, 'token.json'), join(first.ledgerDir, `${'d'.repeat(64)}.json`))
  const exported = reportingScratch('export-')
  writeFileSync(join(exported, 'stale-token.json'), 'FAKE-CREDENTIAL')
  await exportDeliveryLedger(first.ledgerDir, exported)
  expect(readdirSync(exported).sort()).toEqual([record, 'checkpoint.json'].sort())
  for (const name of readdirSync(exported)) {
    expect(name).toMatch(/^(checkpoint|[a-f0-9]{64})\.json$/)
    expect(readFileSync(join(exported, name), 'utf8')).not.toContain('FAKE-CREDENTIAL')
    expect(readFileSync(join(exported, name))).toEqual(readFileSync(join(first.ledgerDir, name)))
  }
})

test('failed safe export cannot publish a checkpoint or retain stale export contents', async () => {
  const { existsSync, readdirSync, chmodSync } = await import('node:fs')
  const { dirname } = await import('node:path')
  const { exportDeliveryLedger } = await import('../../scripts/testing/export-flakiness-ledger.mjs')
  const first = options()
  await beginDeliveryAttempt(first); await finishDeliveryAttempt(first)
  const parent = reportingScratch('export-failure-')
  const exported = join(parent, 'exported')
  await exportDeliveryLedger(first.ledgerDir, exported)
  const checkpoint = join(first.ledgerDir, 'checkpoint.json')
  chmodSync(checkpoint, 0o000) // Real POSIX read failure on non-root CI runners.
  try {
    await expect(exportDeliveryLedger(first.ledgerDir, exported)).rejects.toThrow(/EACCES/)
    expect(existsSync(exported)).toBe(false)
    expect(readdirSync(dirname(exported))).toEqual([])
    expect(existsSync(join(first.ledgerDir, 'checkpoint.json'))).toBe(true)
  } finally { chmodSync(checkpoint, 0o600) }
})
