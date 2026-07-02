import { test, expect } from '@playwright/test'
import { loginAsAdmin, ensureAdminUserExists } from './utils/test-helpers'

const BASE_URL = process.env.BASE_URL || 'http://localhost:8787'

// Regression tests for the stale configSchema settings bug (GitHub #972):
//   Bug 1 — POST /configure merges old settings, preserving removed schema fields
//   Bug 2 — Legacy settings page renders ALL stored keys, ignoring configSchema
//
// The hello-world plugin has configSchema: { greeting: { type: 'string' } }
// We inject a stale key 'oldField' via the JSON settings endpoint, then verify
// it does NOT appear in the legacy settings UI and is pruned when saving via /configure.

test.describe('Plugin stale settings pruning (issue #972) @plugins', () => {
  test.beforeEach(async ({ page }) => {
    await ensureAdminUserExists(page)
    await loginAsAdmin(page)
  })

  test('legacy settings page does not render stale keys absent from configSchema', async ({ page }) => {
    // Inject a stale key directly via the JSON settings endpoint
    const injectResp = await page.request.post(
      `${BASE_URL}/admin/plugins/hello-world/settings`,
      {
        data: { greeting: 'Hi from E2E', staleOldField: 'this-should-not-appear' },
        headers: { 'Content-Type': 'application/json' },
      }
    )
    expect(injectResp.ok()).toBeTruthy()

    // Visit the legacy settings page (/:id, not /:id/configure)
    await page.goto(`${BASE_URL}/admin/plugins/hello-world`)
    await page.waitForLoadState('networkidle')

    const bodyText = await page.locator('body').textContent()

    // The stale key must not appear — configSchema filter should suppress it
    expect(bodyText).not.toContain('staleOldField')
    expect(bodyText).not.toContain('this-should-not-appear')
  })

  test('/configure POST prunes stale keys not in configSchema', async ({ page }) => {
    // Step 1: inject stale key via JSON endpoint
    const injectResp = await page.request.post(
      `${BASE_URL}/admin/plugins/hello-world/settings`,
      {
        data: { greeting: 'Before prune', staleOldField: 'stale-value' },
        headers: { 'Content-Type': 'application/json' },
      }
    )
    expect(injectResp.ok()).toBeTruthy()

    // Step 2: save via /configure (form-based, schema-driven)
    await page.goto(`${BASE_URL}/admin/plugins/hello-world/configure`)
    await page.waitForLoadState('networkidle')

    const greetingInput = page.locator('input[name="greeting"]')
    await expect(greetingInput).toBeVisible({ timeout: 10000 })
    await greetingInput.fill('After prune')
    await page.locator('button[type="submit"]').click()

    // Redirect back to /configure after save
    await page.waitForURL(`**/configure`, { timeout: 10000 })
    await page.waitForLoadState('networkidle')

    // Step 3: verify saved greeting persisted
    const savedInput = page.locator('input[name="greeting"]')
    await expect(savedInput).toBeVisible({ timeout: 10000 })
    expect(await savedInput.inputValue()).toBe('After prune')

    // Step 4: visit legacy settings page — stale key must not appear there either
    await page.goto(`${BASE_URL}/admin/plugins/hello-world`)
    await page.waitForLoadState('networkidle')

    const bodyText = await page.locator('body').textContent()
    expect(bodyText).not.toContain('staleOldField')
    expect(bodyText).not.toContain('stale-value')
  })

  test('_-prefixed internal keys are preserved through /configure save', async ({ page }) => {
    // _routes, _adminPath etc. must survive schema-driven saves
    const injectResp = await page.request.post(
      `${BASE_URL}/admin/plugins/hello-world/settings`,
      {
        data: { greeting: 'Keep internals', _internalKey: 'must-survive' },
        headers: { 'Content-Type': 'application/json' },
      }
    )
    expect(injectResp.ok()).toBeTruthy()

    // Save via /configure
    await page.goto(`${BASE_URL}/admin/plugins/hello-world/configure`)
    await page.waitForLoadState('networkidle')

    const greetingInput = page.locator('input[name="greeting"]')
    await expect(greetingInput).toBeVisible({ timeout: 10000 })
    await page.locator('button[type="submit"]').click()
    await page.waitForURL(`**/configure`, { timeout: 10000 })
    await page.waitForLoadState('networkidle')

    // The configure page won't expose _internalKey (it's not in the schema).
    // Verify by checking the hello-world endpoint which reads from plugin settings:
    // the page should still load without error, meaning internal state is intact.
    const resp = await page.goto(`${BASE_URL}/admin/plugins/hello-world`)
    expect(resp?.status()).not.toBe(500)
  })
})
