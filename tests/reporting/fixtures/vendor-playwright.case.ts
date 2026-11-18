import { expect, test } from '@playwright/test'
test('vendor fixture', () => {
  expect(process.env.REPORTING_FIXTURE_FAIL).not.toBe('1')
})
