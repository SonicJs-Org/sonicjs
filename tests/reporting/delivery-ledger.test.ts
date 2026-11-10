import { expect, test } from 'vitest'
import { writeFileSync, cpSync, rmSync, readFileSync, symlinkSync, linkSync, mkdirSync, existsSync } from 'node:fs'
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
  writeFileSync(join(first.ledgerDir, `${'a'.repeat(64)}.json`), '{"state":"started"}')
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
  await beginDeliveryAttempt(first)
  const record = `${'a'.repeat(64)}.json`
  writeFileSync(join(first.ledgerDir, record), '{"state":"started"}')
  await finishDeliveryAttempt(first)
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
  // Recognized unsafe entries now invalidate export instead of being silently
  // omitted. After removing them, unknown credential/cache files stay excluded.
  await expect(exportDeliveryLedger(first.ledgerDir, exported)).rejects.toThrow()
  for (const hex of ['b', 'c', 'd']) rmSync(join(first.ledgerDir, `${hex.repeat(64)}.json`), { recursive: true })
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

const recordName = `${'e'.repeat(64)}.json`
test.each(['deleted', 'changed', 'added', 'symlink', 'hardlink', 'directory'])('sealed ledger rejects %s record before removing checkpoint', async mode => {
  const first = options()
  writeFileSync(join(first.ledgerDir, recordName), '{"state":"accepted-unverified"}')
  await finishDeliveryAttempt(first)
  const second = options(2); cpSync(first.ledgerDir, second.ledgerDir, { recursive: true })
  const path = join(second.ledgerDir, recordName)
  if (mode === 'deleted') rmSync(path)
  if (mode === 'changed') writeFileSync(path, '{"state":"not-started"}')
  if (mode === 'added') writeFileSync(join(second.ledgerDir, `${'a'.repeat(64)}.json`), '{}')
  if (['symlink', 'hardlink', 'directory'].includes(mode)) {
    rmSync(path)
    if (mode === 'symlink') symlinkSync(join(first.ledgerDir, recordName), path)
    if (mode === 'hardlink') linkSync(join(first.ledgerDir, recordName), path)
    if (mode === 'directory') mkdirSync(path)
  }
  await expect(beginDeliveryAttempt(second)).rejects.toThrow()
  expect(existsSync(join(second.ledgerDir, 'checkpoint.json'))).toBe(true)
})
test('checkpoint binds sorted exact record names and SHA256 of bytes', async () => {
  const { createHash } = await import('node:crypto')
  const first = options()
  for (const name of [recordName, `${'a'.repeat(64)}.json`]) writeFileSync(join(first.ledgerDir, name), '{"state":"started"}\n')
  await finishDeliveryAttempt(first)
  const seal = JSON.parse(readFileSync(join(first.ledgerDir, 'checkpoint.json'), 'utf8'))
  expect(seal.version).toBe(2)
  expect(seal.records).toEqual([`${'a'.repeat(64)}.json`, recordName].map(name => ({ name, sha256: createHash('sha256').update(readFileSync(join(first.ledgerDir, name))).digest('hex') })))
})
test.each(['symlink', 'hardlink', 'directory', 'unreadable'])('export rejects recognized %s records without publishing seal', async mode => {
  const { exportDeliveryLedger } = await import('../../scripts/testing/export-flakiness-ledger.mjs')
  const { chmodSync } = await import('node:fs')
  const first = options(); await finishDeliveryAttempt(first)
  const file = join(first.ledgerDir, recordName)
  const privateFile = join(reportingScratch('private-'), 'private'); writeFileSync(privateFile, 'private')
  if (mode === 'symlink') symlinkSync(privateFile, file)
  if (mode === 'hardlink') linkSync(privateFile, file)
  if (mode === 'directory') mkdirSync(file)
  if (mode === 'unreadable') { writeFileSync(file, '{}'); chmodSync(file, 0o000) }
  const target = join(reportingScratch('export-invalid-'), 'exported')
  try {
    await expect(exportDeliveryLedger(first.ledgerDir, target)).rejects.toThrow()
    expect(existsSync(target)).toBe(false)
  } finally { if (mode === 'unreadable') chmodSync(file, 0o600) }
})

test.each(['deleted', 'changed', 'added'])('export refuses sealed %s record inventory rather than publishing a partial ledger', async mode => {
  const { exportDeliveryLedger } = await import('../../scripts/testing/export-flakiness-ledger.mjs')
  const first = options()
  const path = join(first.ledgerDir, recordName)
  writeFileSync(path, '{"state":"accepted-unverified"}')
  await finishDeliveryAttempt(first)
  if (mode === 'deleted') rmSync(path)
  if (mode === 'changed') writeFileSync(path, '{"state":"not-started"}')
  if (mode === 'added') writeFileSync(join(first.ledgerDir, `${'a'.repeat(64)}.json`), '{}')
  const exported = join(reportingScratch('partial-export-'), 'exported')
  await expect(exportDeliveryLedger(first.ledgerDir, exported)).rejects.toThrow(/checkpoint.*inventory/i)
  expect(existsSync(exported)).toBe(false)
})
test('restore rejects an exported ledger truncated after its checkpoint was published', async () => {
  const { exportDeliveryLedger } = await import('../../scripts/testing/export-flakiness-ledger.mjs')
  const first = options()
  writeFileSync(join(first.ledgerDir, recordName), '{"state":"accepted-unverified"}')
  await finishDeliveryAttempt(first)
  const second = options(2)
  await exportDeliveryLedger(first.ledgerDir, second.ledgerDir)
  rmSync(join(second.ledgerDir, recordName))
  await expect(beginDeliveryAttempt(second)).rejects.toThrow(/checkpoint.*inventory/i)
  expect(existsSync(join(second.ledgerDir, 'checkpoint.json'))).toBe(true)
})
