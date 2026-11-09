import { writeFileSync } from 'node:fs'
import { expect, test } from '@playwright/test'
const mode = process.env.CASE_MODE
if (mode === 'static-skip') test.skip('static skip', () => {})
else test('semantics', async ({}, info) => {
  if (mode === 'runtime-skip') test.skip(true, 'runtime skip')
  if (mode === 'expected-failure') test.fail()
  if (mode === 'interrupt') {
    test.setTimeout(30_000)
    console.log('INTERRUPT_READY')
    await new Promise(() => {})
  }
  if (mode === 'timeout') await new Promise(() => {})
  const attachmentPath = info.outputPath('evidence.txt')
  writeFileSync(attachmentPath, 'retained file attachment')
  await info.attach('file-evidence', { path: attachmentPath, contentType: 'text/plain' })
  await info.attach('evidence', { body: Buffer.from('retained attachment'), contentType: 'text/plain' })
  expect(mode === 'fail' || mode === 'expected-failure' || (mode === 'retry' && info.retry === 0)).toBe(false)
})
