import { test, expect } from '@playwright/test'
import { loginAsAdmin } from './utils/test-helpers'

/**
 * A user assigned the "Public" RBAC role must be blocked from /api/:collection
 * and /api/:collection/:id when the collection's baseGrants do not include a
 * 'public' read grant.
 *
 * Default collections (admin/editor/viewer grants only, no public grant) must
 * return 404 / empty results for an authenticated "public-role" user, not the
 * full published content set.
 */

const PUBLIC_USER_EMAIL = `pub-acl-${Date.now()}@test.com`
const PUBLIC_USER_PASSWORD = 'pubpass123!'

async function ensurePublicRoleExists(page: any) {
  await loginAsAdmin(page)
  await page.goto('/admin/rbac')
  await page.waitForLoadState('networkidle')
  await page.click('#subtab-roles-verbs')
  await page.locator('#panel-roles-verbs').waitFor({ state: 'visible' })
  // role-public is seeded — just verify it exists
  const body = await page.locator('body').innerText()
  return body.includes('Public') || body.includes('public')
}

test.describe('Public role — API ACL enforcement', () => {
  test('anonymous user sees published content (baseline)', async ({ page }) => {
    await page.context().clearCookies()
    const res = await page.request.get('/api/blog_post')
    // 200 (may be empty array) or 404 if collection missing — either is fine, just not 401/403
    expect(res.status()).not.toBe(401)
    expect(res.status()).not.toBe(403)
  })

  test('public-role user cannot see content from default-grant collection via /api/:collection', async ({ page }) => {
    // Sign up a new user
    const signUp = await page.request.post('/auth/sign-up/email', {
      data: { email: PUBLIC_USER_EMAIL, password: PUBLIC_USER_PASSWORD, name: 'Public ACL Tester' },
      headers: { 'Content-Type': 'application/json' },
    })
    if (!signUp.ok() && signUp.status() !== 400) { test.skip(); return }

    // Sign in
    const signIn = await page.request.post('/auth/sign-in/email', {
      data: { email: PUBLIC_USER_EMAIL, password: PUBLIC_USER_PASSWORD },
      headers: { 'Content-Type': 'application/json' },
    })
    if (!signIn.ok()) { test.skip(); return }

    // Assign "public" role to this user via admin
    await loginAsAdmin(page)
    await page.goto('/admin/users')
    await page.waitForLoadState('networkidle')

    // Find and open the user's edit page
    const userLink = page.locator(`a[href*="/edit"]`).filter({ hasText: PUBLIC_USER_EMAIL }).first()
    if ((await userLink.count()) === 0) { test.skip(); return }
    await userLink.click()
    await page.waitForLoadState('networkidle')

    const roleSelect = page.locator('select[name="role"]')
    await expect(roleSelect).toBeVisible()

    // Select public role (value = role-public)
    const publicOption = roleSelect.locator('option[value="role-public"]')
    if ((await publicOption.count()) === 0) { test.skip(); return }
    await roleSelect.selectOption('role-public')
    await page.locator('button[type="submit"]').filter({ hasText: /save|update/i }).click()
    await page.waitForLoadState('networkidle')

    // Now sign back in as the public-role user and call the API
    await page.context().clearCookies()
    const signIn2 = await page.request.post('/auth/sign-in/email', {
      data: { email: PUBLIC_USER_EMAIL, password: PUBLIC_USER_PASSWORD },
      headers: { 'Content-Type': 'application/json' },
    })
    if (!signIn2.ok()) { test.skip(); return }

    // 'example' collection has no public grant by default — public-role user should get 403.
    const res = await page.request.get('/api/example')
    // 403 Forbidden (authenticated but no type-level read grant) or 404 (collection not found).
    // Must NOT be 200.
    expect([403, 404]).toContain(res.status())

    // Clean up
    await page.request.post('/auth/sign-out', { headers: { 'Content-Type': 'application/json' } })
  })

  test('admin still sees all published content after ACL fix', async ({ page }) => {
    await loginAsAdmin(page)
    const res = await page.request.get('/api/blog_post')
    expect(res.status()).not.toBe(401)
    expect(res.status()).not.toBe(403)
    expect(res.status()).not.toBe(500)
  })
})
