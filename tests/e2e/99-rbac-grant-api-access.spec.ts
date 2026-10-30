import { test, expect } from './fixtures'
import { loginAsAdmin, submitAndWaitForDocument, submitAndWaitForXhr, TEST_ORIGIN } from './utils/test-helpers'

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

async function signUp(page: any): Promise<string> {
  const res = await page.request.post('/auth/sign-up/email', {
    data: { email: USER_EMAIL, password: USER_PASSWORD, name: 'RBAC Grant Tester' },
    headers: { 'Content-Type': 'application/json', Origin: TEST_ORIGIN },
  })
  expect(res.ok(), `sign-up failed: ${res.status()}`).toBeTruthy()
  const id = (await res.json())?.user?.id
  expect(id, 'sign-up returned no user id').toBeTruthy()
  return id
}

async function signIn(page: any) {
  return page.request.post('/auth/sign-in/email', {
    data: { email: USER_EMAIL, password: USER_PASSWORD },
    headers: { 'Content-Type': 'application/json', Origin: TEST_ORIGIN },
  })
}

// Addressed by id rather than hunted for in the users table: the list paginates, so a
// brand-new user is not reliably on page one.
async function assignRole(page: any, userId: string, roleValue: string) {
  await loginAsAdmin(page)
  await page.goto(`/admin/users/${userId}/edit`)
  await page.waitForLoadState('networkidle')
  await page.locator('select[name="role"]').selectOption(roleValue)
  // The user form is a `PUT`, so htmx sends it as an XHR and swaps an alert in — there is no
  // navigation, and `networkidle` can go true before htmx has issued the request at all. The
  // very next thing this spec does is `page.goto`, which would cancel the save in flight and
  // leave the user on their old role, so the 200-after-grant assertion would fail for a reason
  // that has nothing to do with grants.
  await submitAndWaitForXhr(page, 'PUT', `/admin/users/${userId}`, () =>
    page.locator('button[type="submit"]').filter({ hasText: /save|update/i }).click()
  )
}

// The matrix only renders the roles named in `?roles=` (with `compare=1`); a plain visit
// defaults to the first three roles, and "public" is not one of them. Each cell is a group of
// three radios named `g|<roleId>|<resource>|<verb>` with value any|own|none — not a checkbox —
// and the resource attribute is `data-res`. The radios are visually hidden (1px, opacity 0,
// pointer-events none), so the click has to land on the wrapping <label class="scope">.
//
// Reads the current state before writing. That is not only cheaper: the grant is global and
// outlives the test, so a run that dies between granting and revoking leaves it on, and
// Playwright's retry then re-runs against a database where the "no grant yet" assertion is
// already false. That is how this spec failed three attempts running in CI, for a reason that
// had nothing to do with the behaviour it covers.
async function setPublicRoleGrant(page: any, grant: boolean) {
  await loginAsAdmin(page)
  await page.goto('/admin/rbac?compare=1&roles=role-public')
  await page.waitForLoadState('networkidle')

  const cell = 'input[name="g|role-public|document_type:example|read"]'
  const target = page.locator(`${cell}[value="${grant ? 'any' : 'none'}"]`)
  await expect(target, 'public × document_type:example × read cell missing from matrix').toHaveCount(1)

  if (await target.isChecked()) return

  await page.locator(`label.scope:has(${cell}[value="${grant ? 'any' : 'none'}"])`).click()
  await expect(target).toBeChecked()

  // Wait for the document the POST redirects to. Without it the check below runs against the
  // page the form was submitted from, where the radio is checked because this function clicked
  // it — so "confirm the write landed" confirmed nothing.
  await submitAndWaitForDocument(page, '/admin/rbac', () =>
    page.locator('form[action="/admin/rbac/grants"] button[type="submit"]').first().click()
  )

  // The redirect re-renders the matrix from the saved grants — confirm the write landed.
  await expect(target).toBeChecked()
}

test.describe('RBAC grant → immediate API access @auth @api @lock-rbac-example-grant', () => {
  // Four admin logins and roughly fifteen page loads, against a preview where one cold admin
  // page load has been measured at ~10s. The suite default is sized for a test that loads a
  // couple of pages.
  test.setTimeout(240000)

  test('granting public role read on document_type:example unblocks /api/example immediately', async ({ page }) => {
    // 1. Ensure test user exists.
    const userId = await signUp(page)

    // 2. Assign public role via admin UI.
    await assignRole(page, userId, 'role-public')

    // 3. Start from a known state rather than trusting that the last run reached its revoke.
    //    Costs one matrix load when the grant is already off, which is the normal case.
    await setPublicRoleGrant(page, false)

    // 4. Sign in as the public-role user and confirm 403 (no grant yet).
    await page.context().clearCookies()
    const signIn1 = await signIn(page)
    expect(signIn1.ok(), `sign-in failed: ${signIn1.status()}`).toBeTruthy()

    const res1 = await page.request.get('/api/example')
    // Must be 403 (or 404 if collection not registered) — NOT 200.
    expect(res1.status()).not.toBe(200)

    // 5. Admin grants read.
    await setPublicRoleGrant(page, true)

    // 6. Sign back in as public-role user and re-check.
    await page.context().clearCookies()
    const signIn2 = await signIn(page)
    expect(signIn2.ok(), `sign-in failed: ${signIn2.status()}`).toBeTruthy()

    const res2 = await page.request.get('/api/example')
    // After grant: must be 200 (even if data is empty).
    expect(res2.status()).toBe(200)

    // 7. Admin revokes grant — access must be blocked again.
    await setPublicRoleGrant(page, false)

    await page.context().clearCookies()
    const signIn3 = await signIn(page)
    expect(signIn3.ok(), `sign-in failed: ${signIn3.status()}`).toBeTruthy()

    const res3 = await page.request.get('/api/example')
    expect(res3.status()).not.toBe(200)
  })
})
