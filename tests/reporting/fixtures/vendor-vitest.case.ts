import { expect, test } from 'vitest'
test('vendor fixture', () => {
  expect(process.env.REPORTING_FIXTURE_FAIL).not.toBe('1')
})
