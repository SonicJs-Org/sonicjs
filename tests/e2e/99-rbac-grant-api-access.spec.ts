import { test, expect } from '@playwright/test'
import { loginAsAdmin } from './utils/test-helpers'

/**
 * RBAC grant takes effect immediately on the API.
 *
 * Flow:
 *   1. Create a user, assign "public" role.
 *   2. Confirm /api/example returns 403 (no grant).
 *   3. Admin grants public role read on document_type:example via RBAC matrix.
 *   4. Same user calls /api/example again — must get 200.
 *   5. Admin revokes the grant.
 *   6. /api/example returns 403 again.
 *
 * This is a regression test for the bug where RBAC dynamic grants were not
 * consulted alongside code-time baseGrants, causing stale 403s after UI changes.
 */

const USER_EMAIL = `rbac-grant-test-${Date.now()}@test.com`
const USER_PASSWORD = 'Passw0rd!rbac'

async function signUp(page: any) {
  const res = await page.request.post('/auth/sign-up/email', {
    data: { email: USER_EMAIL, password: USER_PASSWORD, name: 'RBAC Grant Tester' },
    headers: { 'Content-Type': 'application/json' },
  })
  return res.ok() || res.status() === 400 // 400 = already exists
}

async function signIn(page: any) {
  return page.request.post('/auth/sign-in/email', {
    data: { email: USER_EMAIL, password: USER_PASSWORD },
    headers: { 'Content-Type': 'application/json' },
  })
}

async function assignRole(page: any, roleValue: string) {
  await loginAsAdmin(page)
  await page.goto('/admin/users')
  await page.waitForLoadState('networkidle')
  const editLink = page.locator('a[href*="/edit"]').filter({ hasText: USER_EMAIL }).first()
  if ((await editLink.count()) === 0) { return false }
  await editLink.click()
  await page.waitForLoadState('networkidle')
  await page.locator('select[name="role"]').selectOption(roleValue)
  await page.locator('button[type="submit"]').filter({ hasText: /save|update/i }).click()
  await page.waitForLoadState('networkidle')
  return true
}

async function setPublicRoleGrant(page: any, grant: boolean) {
  await loginAsAdmin(page)
  await page.goto('/admin/rbac')
  await page.waitForLoadState('networkidle')
  // Navigate to the matrix tab.
  const matrixTab = page.locator('[data-subtab="matrix"], #subtab-matrix, button:has-text("Matrix"), a:has-text("Matrix")').first()
  if ((await matrixTab.count()) > 0) {
    await matrixTab.click()
    await page.waitForLoadState('networkidle')
  }
  // Find the checkbox for role-public × document_type:example × read.
  const checkbox = page
    .locator('input[type="checkbox"]')
    .filter({ has: page.locator('[data-role="role-public"][data-resource="document_type:example"][data-verb="read"]') })
    .first()
  if ((await checkbox.count()) > 0) {
    const checked = await checkbox.isChecked()
    if (grant !== checked) await checkbox.click()
    await page.locator('button[type="submit"]').filter({ hasText: /save|apply/i }).first().click()
    await page.waitForLoadState('networkidle')
  }
}

test.describe('RBAC grant → immediate API access', () => {
  test('granting public role read on document_type:example unblocks /api/example immediately', async ({ page }) => {
    // 1. Ensure test user exists.
    const created = await signUp(page)
    if (!created) { test.skip(); return }

    // 2. Assign public role via admin UI.
    const assigned = await assignRole(page, 'role-public')
    if (!assigned) { test.skip(); return }

    // 3. Sign in as the public-role user and confirm 403 (no grant yet).
    await page.context().clearCookies()
    const signIn1 = await signIn(page)
    if (!signIn1.ok()) { test.skip(); return }

    const res1 = await page.request.get('/api/example')
    // Must be 403 (or 404 if collection not registered) — NOT 200.
    expect(res1.status()).not.toBe(200)

    // 4. Admin grants read.
    await setPublicRoleGrant(page, true)

    // 5. Sign back in as public-role user and re-check.
    await page.context().clearCookies()
    const signIn2 = await signIn(page)
    if (!signIn2.ok()) { test.skip(); return }

    const res2 = await page.request.get('/api/example')
    // After grant: must be 200 (even if data is empty).
    expect(res2.status()).toBe(200)

    // 6. Admin revokes grant — access must be blocked again.
    await setPublicRoleGrant(page, false)

    await page.context().clearCookies()
    const signIn3 = await signIn(page)
    if (!signIn3.ok()) { test.skip(); return }

    const res3 = await page.request.get('/api/example')
    expect(res3.status()).not.toBe(200)
  })
})
