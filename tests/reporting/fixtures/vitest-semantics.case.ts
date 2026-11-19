import { test, expect } from 'vitest'
let attempts = 0
const mode = process.env.CASE_MODE
if (mode === 'empty') {
  // Intentionally collect no tests: lifecycle must fail rather than claim success.
} else if (mode === 'duplicate') {
  test('duplicate identity', () => {})
  test('duplicate identity', () => {})
} else if (mode === 'skip') {
  test.skip('skipped case', () => {})
} else {
  test('real case', async () => {
    if (mode === 'interrupt') {
      console.log('INTERRUPT_READY')
      await new Promise(resolve => setTimeout(resolve, 60_000))
    }
    expect(mode === 'fail' || (mode === 'retry' && attempts++ === 0)).toBe(false)
  })
}
