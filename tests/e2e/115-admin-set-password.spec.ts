import { test, expect } from './fixtures'
import { loginAsAdmin, getCsrfTokenFromPage, TEST_ORIGIN } from './utils/test-helpers'

/**
 * A password set by an admin is the password that signs in.
 *
 * Better Auth signs in against `auth_account.password`. Admin create-user and admin edit-user
 * used to write only `auth_user.password_hash`, so an admin-created user could not sign in at
 * all, and after an admin set a new password the old one kept working and the new one failed.
 */
test.describe('Admin-set passwords sign in @auth', () => {
  test('create a user, then change their password: new one works, old one does not', async ({ page, request }) => {
    await loginAsAdmin(page)

    const unique = Date.now()
    const email = `admin-pw-test-${unique}@example.com`
    const firstPassword = `FirstPass${unique}!`
    const changedPassword = `Changed${unique}!`

    // Create user via admin UI API
    const csrfToken = await getCsrfTokenFromPage(page)
    const createRes = await page.request.post('/admin/users/new', {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        ...(csrfToken ? { 'X-CSRF-Token': csrfToken } : {}),
      },
      // The handler reads snake_case names and rejects the submission unless
      // `confirm_password` matches.
      form: {
        email,
        first_name: 'PW',
        last_name: 'Test',
        password: firstPassword,
        confirm_password: firstPassword,
        // RBAC role ids are prefixed; an unknown value silently falls back to the first
        // role, which is the admin one.
        role: 'role-editor',
        is_active: '1',
        email_verified: '1',
      },
    })
    // Accept redirect (200 with HX-Redirect) or 302
    expect([200, 302].includes(createRes.status())).toBeTruthy()
    // A validation failure also comes back as a 200, as an inline alert — so check the
    // body rather than trusting the status.
    expect(await createRes.text()).not.toContain('bg-error/10')

    // Sign in with the first password
    const signIn1 = await request.post('/auth/sign-in/email', {
      data: { email, password: firstPassword },
      headers: { 'Content-Type': 'application/json', Origin: TEST_ORIGIN },
    })
    expect(signIn1.ok()).toBeTruthy()

    // Sign out
    await request.post('/auth/sign-out', {
      data: {},
      headers: { 'Content-Type': 'application/json', Origin: TEST_ORIGIN },
    })

    // Change password via admin edit
    await loginAsAdmin(page)

    // Find the user ID
    const usersRes = await page.request.get(`/admin/users`)
    expect(usersRes.ok()).toBeTruthy()

    // Navigate to admin and change password via the edit form
    await page.goto('/admin/users')
    await page.waitForLoadState('networkidle')

    // Open the user's edit page. The only anchor carrying the address is a `mailto:`
    // link — the row itself navigates, through an onclick rather than an href.
    const row = page.locator(`tr:has-text("${email}")`).first()
    await expect(row).toBeVisible({ timeout: 15000 })
    const rowOnClick = (await row.getAttribute('onclick')) || ''
    const editPath = rowOnClick.match(/\/admin\/users\/[^']+\/edit/)?.[0]
    expect(editPath).toBeTruthy()
    await page.goto(editPath!)
    await page.waitForLoadState('networkidle')

    // Fill in the new password. The edit form posts snake_case names and refuses the
    // change unless `confirm_password` matches, so both fields have to be filled.
    await page.locator('input[name="new_password"]').fill(changedPassword)
    await page.locator('input[name="confirm_password"]').fill(changedPassword)
    await page.locator('button[type="submit"]').first().click()
    await page.waitForTimeout(2000)

    // Sign out admin
    await request.post('/auth/sign-out', {
      data: {},
      headers: { 'Content-Type': 'application/json', Origin: TEST_ORIGIN },
    })

    // New password works
    const signIn2 = await request.post('/auth/sign-in/email', {
      data: { email, password: changedPassword },
      headers: { 'Content-Type': 'application/json', Origin: TEST_ORIGIN },
    })
    expect(signIn2.ok()).toBeTruthy()

    await request.post('/auth/sign-out', {
      data: {},
      headers: { 'Content-Type': 'application/json', Origin: TEST_ORIGIN },
    })

    // …and the password it replaced does not
    const signIn3 = await request.post('/auth/sign-in/email', {
      data: { email, password: firstPassword },
      headers: { 'Content-Type': 'application/json', Origin: TEST_ORIGIN },
    })
    expect(signIn3.ok()).toBeFalsy()
  })
})
