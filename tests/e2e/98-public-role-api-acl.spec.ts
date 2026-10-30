import { test, expect } from './fixtures'
import { loginAsAdmin, submitAndWaitForXhr, TEST_ORIGIN } from './utils/test-helpers'

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

test.describe('Public role — API ACL enforcement @auth @api @lock-auth-registration', () => {
  test('anonymous user sees published content (baseline)', async ({ page }) => {
    await page.context().clearCookies()
    const res = await page.request.get('/api/blog_post')
    // 200 (may be empty array) or 404 if collection missing — either is fine, just not 401/403
    expect(res.status()).not.toBe(401)
    expect(res.status()).not.toBe(403)
  })

  // Shares `document_type:example` with 99-rbac-grant-api-access, which grants the public role
  // read on it and revokes again. That grant is global, so while 99 holds it this test's
  // premise — "no public grant" — is false and /api/example answers 200. Same `@lock-` name on
  // both, so the two can never overlap.
  test('public-role user cannot see content from default-grant collection via /api/:collection @lock-rbac-example-grant', async ({ page }) => {
    // Sign up a new user. The email carries this run's timestamp, so a 400 ("already
    // exists") would mean something else went wrong.
    const signUp = await page.request.post('/auth/sign-up/email', {
      data: { email: PUBLIC_USER_EMAIL, password: PUBLIC_USER_PASSWORD, name: 'Public ACL Tester' },
      headers: { 'Content-Type': 'application/json', Origin: TEST_ORIGIN },
    })
    expect(signUp.ok(), `sign-up failed: ${signUp.status()}`).toBeTruthy()
    const userId = (await signUp.json())?.user?.id
    expect(userId).toBeTruthy()

    // Sign in
    const signIn = await page.request.post('/auth/sign-in/email', {
      data: { email: PUBLIC_USER_EMAIL, password: PUBLIC_USER_PASSWORD },
      headers: { 'Content-Type': 'application/json', Origin: TEST_ORIGIN },
    })
    expect(signIn.ok(), `sign-in failed: ${signIn.status()}`).toBeTruthy()

    // Assign "public" role to this user via admin. Addressed by id rather than hunted for in
    // the users table: the list paginates, so a brand-new user is not reliably on page one.
    await loginAsAdmin(page)
    await page.goto(`/admin/users/${userId}/edit`)
    await page.waitForLoadState('networkidle')

    const roleSelect = page.locator('select[name="role"]')
    await expect(roleSelect).toBeVisible()

    // Select public role (value = role-public). The role is seeded by the RBAC bootstrap.
    await expect(roleSelect.locator('option[value="role-public"]')).toHaveCount(1)
    await roleSelect.selectOption('role-public')
    // htmx `PUT`, no navigation — see submitAndWaitForXhr. `networkidle` here could report the
    // quiet that precedes the request rather than the one that follows it.
    await submitAndWaitForXhr(page, 'PUT', `/admin/users/${userId}`, () =>
      page.locator('button[type="submit"]').filter({ hasText: /save|update/i }).click()
    )

    // Now sign back in as the public-role user and call the API
    await page.context().clearCookies()
    const signIn2 = await page.request.post('/auth/sign-in/email', {
      data: { email: PUBLIC_USER_EMAIL, password: PUBLIC_USER_PASSWORD },
      headers: { 'Content-Type': 'application/json', Origin: TEST_ORIGIN },
    })
    expect(signIn2.ok(), `sign-in after role change failed: ${signIn2.status()}`).toBeTruthy()

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
