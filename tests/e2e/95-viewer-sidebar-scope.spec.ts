import { test, expect } from './fixtures'
import { loginAsAdmin, submitLoginForm, TEST_ORIGIN } from './utils/test-helpers'

/**
 * Issue #783: viewer role sees all sidebar items.
 * A viewer account is provisioned; the viewer sidebar must not expose
 * Users, Plugins, or Settings navigation.
 */
test.describe('Viewer role sidebar scope @auth @lock-auth-login @lock-auth-registration', () => {
  const viewerEmail = `viewer-test-${Date.now()}@example.com`
  const viewerPassword = 'ViewerPass1!'

  test.beforeAll(async ({ browser }) => {
    const page = await browser.newPage()
    await loginAsAdmin(page)

    // The RBAC "viewer" role is not seeded on a fresh database. Better Auth's user-create hook
    // assigns it by name (addUserRoleByName), which silently no-ops when the role is missing —
    // the new account would then have no portal access at all. Create it (idempotent) and grant
    // portal access before registering the fixture user.
    await page.request.post('/admin/rbac/roles', {
      form: { name: 'viewer', display_name: 'Viewer' },
      headers: { Origin: TEST_ORIGIN },
    })
    const portal = await page.request.post('/admin/rbac/roles/role-viewer', {
      form: { display_name: 'Viewer', portal_access: '1' },
      headers: { Origin: TEST_ORIGIN },
    })
    expect(portal.status(), 'granting portal access to the viewer role').toBeLessThan(400)

    // Register through the sign-up endpoint rather than /admin/users/new: admin-created users get
    // no Better Auth credential account and no rbac_user_roles row, so they cannot sign in.
    const signUp = await page.request.post('/auth/sign-up/email', {
      data: { email: viewerEmail, password: viewerPassword, name: 'Viewer Test' },
      headers: { 'Content-Type': 'application/json', Origin: TEST_ORIGIN },
    })
    expect(signUp.ok(), `viewer sign-up failed with ${signUp.status()}`).toBeTruthy()
    await page.close()
  })

  test('viewer sees Content and Collections but not Users/Plugins/Settings', async ({ page }) => {
    // Sign in as viewer. `submitLoginForm` rather than a bare click: the form POST is rate
    // limited per IP, the whole suite is one IP, and a 429 to an htmx post is not swapped — the
    // page silently stays on /auth/login and this reads as an unexplained waitForURL timeout.
    await page.goto('/auth/login')
    await submitLoginForm(page, viewerEmail, viewerPassword)

    // The layout renders every nav link twice (desktop sidebar + #mobile-sidebar), hence .first().
    // Content link present
    await expect(page.locator('a[href="/admin/content"]').first()).toBeVisible()
    // Collections link present
    await expect(page.locator('a[href="/admin/collections"]').first()).toBeVisible()

    // Users, Plugins, Settings must NOT be in the sidebar — in either copy.
    await expect(page.locator('a[href="/admin/users"]')).toHaveCount(0)
    await expect(page.locator('a[href="/admin/plugins"]')).toHaveCount(0)
    await expect(page.locator('a[href="/admin/settings"]')).toHaveCount(0)
  })

  test('admin sees all sidebar items', async ({ page }) => {
    await loginAsAdmin(page)
    await page.goto('/admin/content')

    await expect(page.locator('a[href="/admin/users"]').first()).toBeVisible()
    await expect(page.locator('a[href="/admin/plugins"]').first()).toBeVisible()
    await expect(page.locator('a[href="/admin/settings"]').first()).toBeVisible()
  })
})
