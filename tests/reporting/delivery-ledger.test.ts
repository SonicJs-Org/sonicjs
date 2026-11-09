import { expect, test } from 'vitest'
import { mkdtempSync, writeFileSync, cpSync } from 'node:fs'
import { join } from 'node:path'
import { beginDeliveryAttempt, finishDeliveryAttempt } from '../../scripts/testing/delivery-ledger.mjs'

/** Each directory models a fresh hosted runner; only immutable ledger artifacts survive. */
function options(attempt = 1) { return { ledgerDir: mkdtempSync(join(process.env.TMPDIR!, 'ledger-')), producerRunId: 123, producerAttempt: 2, consumerRunId: 900, consumerAttempt: attempt } }
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
